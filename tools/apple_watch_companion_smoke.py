#!/usr/bin/env python3
"""Embedded watchOS companion smoke on a paired iPhone and Apple Watch simulator.

R22 Y3 D2, part 2. The Apple owner evidence set needs
``watch_companion_smoke_sha256``: the hash of a durable receipt proving the
embedded watchOS companion links to the iPhone app. Owner ruling 2026-10-17:
there is no Apple Watch, so the smoke runs on a paired iPhone and Apple Watch
simulator from a simulator Debug build of the release source commit.

Commands
  run     Stage the provenance-pinned simulator engine inputs, build
          ``flutter build ios --simulator --debug``, create and pair a fresh
          iPhone and Apple Watch simulator, observe the link from the Watch side
          (the debug-only hook in ios/WinsWatch Watch App/WinsWatchApp.swift),
          run the negative controls, delete the simulators it created, and
          write .artifacts/apple-watch-companion-smoke/<UTC>/WATCH_COMPANION_SMOKE.json
          (directory 0700, file 0600).
  verify  Re-verify a receipt: path, bytes, release, source commit, verdict.
  record  Bind a verified receipt into runtime_evidence.json. Refused unless the
          release candidate set is complete and carries its source commit, and
          the runtime evidence has left its not-started pending state (the
          state in which the validators require the smoke to stay unbound).

The receipt is evidence for a simulator build of the release commit, not for the
App Store IPA bytes; the IPA's Watch identity and executable hashes are bound
separately by the release candidate set. Every validator that reads
``watch_companion_smoke`` re-hashes the receipt and re-derives its verdict from
the recorded observations through ``runtime_watch_smoke_sha256`` below, rather
than trusting a recorded value.

The library part of this module uses the standard library only, so the Apple
validators can import it under ``python -I -S``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import plistlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]

CONTRACT = "winsvpn-apple-watch-companion-smoke-v1"
OBSERVATION_CONTRACT = "wins-watch-companion-smoke-observation-v1"
SCHEMA_VERSION = 1
TOOL_RELATIVE = "tools/apple_watch_companion_smoke.py"
RECEIPT_ROOT_RELATIVE = ".artifacts/apple-watch-companion-smoke"
RECEIPT_NAME = "WATCH_COMPANION_SMOKE.json"
RECEIPT_PATH_RE = re.compile(
    r"^\.artifacts/apple-watch-companion-smoke/[0-9]{8}T[0-9]{6}Z/WATCH_COMPANION_SMOKE\.json$"
)
RECEIPT_MAX_BYTES = 4 * 1024 * 1024
STAMP_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
RELEASE_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$")

COMPLETE_LOCAL_CANDIDATES = "complete_local_candidates"
RUNTIME_COMPLETE_STATUS = "complete_current_candidates"
# The runtime states in which every validator accepts a passed smoke. While the
# runtime evidence is still "pending_current_runtime_evidence" the submission
# validator requires the smoke to stay unbound, so recording waits for it.
RUNTIME_RECORDABLE_STATUSES = frozenset(
    {"partial_pending_universal_macos_rebuild", RUNTIME_COMPLETE_STATUS}
)
RELEASE_CANDIDATE_RELATIVE = "app_store/apple/artifacts/release_candidate.json"
RUNTIME_EVIDENCE_RELATIVE = "app_store/apple/artifacts/runtime_evidence.json"
SMOKE_KEYS = frozenset({"status", "receipt_path", "receipt_sha256"})

# A Debug simulator build carries the debug bundle identities
# (ios/Runner.xcodeproj Debug configurations); the shipping identities are
# org.winsvpn.app and org.winsvpn.app.watchkitapp, bound from the IPA bytes.
SIMULATOR_PHONE_BUNDLE_ID = "org.winsvpn.app.debug"
SIMULATOR_WATCH_BUNDLE_ID = "org.winsvpn.app.debug.watchkitapp"
WATCH_EXECUTABLE = "WinsWatch"
WATCH_SMOKE_ARGUMENT = "--wins-watch-companion-smoke"
WATCH_OBSERVATION_RELATIVE = "Documents/wins_watch_companion_smoke.json"
# Present only in a Watch binary compiled with DEBUG (the hook above); the
# release contamination gate refuses an IPA whose Watch executable carries it.
WATCH_SMOKE_BINARY_MARKER = b"wins_watch_companion_smoke"
WATCH_PROTOCOL_VERSION = 1

# What lib/watch_bridge.dart can publish (WatchTunnelStatus). Before Dart has
# published, ios/Runner/WatchSessionBridge.swift answers with status
# "unknown", which is also what an iPhone app WatchConnectivity had to wake in
# the background answers first (measured 2026-10-18 on watchOS 26.5 and iOS
# 26.5 simulators). A PASS needs the first reply to come from a running iPhone
# app whose Flutter layer had already published.
PHONE_PUBLISHED_STATUSES = frozenset(
    {"disconnected", "connecting", "connected", "disconnecting", "failed", "permissionRequired"}
)
NOT_RUNNING_CASES = ("phone_app_installed_never_launched", "phone_app_terminated")
MAX_ACTIVATION_RETRIES = 2
NOT_INSTALLED_CASE = "phone_app_not_installed"
NEGATIVE_CASES = NOT_RUNNING_CASES + (NOT_INSTALLED_CASE,)
STATEMENT = (
    "Simulator Debug build of the release source commit, run on a paired iPhone "
    "and Apple Watch simulator created for this run (owner ruling 2026-10-17: no "
    "physical Apple Watch). These are not the App Store IPA bytes; the IPA's "
    "embedded Watch identity and executable hashes are bound separately by the "
    "release candidate set."
)

OBSERVATION_CHECKS = (
    "contract",
    "nonce",
    "complete",
    "watch_bundle_id",
    "companion_bundle_id",
    "wc_supported",
    "activation_activated",
    "companion_app_installed",
    "reachable",
    "reply_received",
    "reply_protocol_version",
    "reply_timestamped",
    "reply_from_running_app",
    "phone_link_current",
)
# The checks that only a running phone app can satisfy. A not-running control
# must fail on at least one of these while the Watch app itself ran and
# reported (the well-formed checks).
LINK_CHECKS = (
    "companion_app_installed",
    "reachable",
    "reply_received",
    "reply_protocol_version",
    "reply_timestamped",
    "reply_from_running_app",
    "phone_link_current",
)
WELL_FORMED_CHECKS = (
    "contract",
    "nonce",
    "complete",
    "watch_bundle_id",
    "companion_bundle_id",
    "wc_supported",
    "activation_activated",
)


class WatchSmokeError(ValueError):
    """The smoke receipt or its recording is invalid, incomplete or unsafe."""


# ---------------------------------------------------------------------------
# Library: observation evaluation and receipt verification (stdlib only).
# ---------------------------------------------------------------------------


def _number(value: object) -> float | None:
    if type(value) in (int, float):
        return float(value)
    return None


def evaluate_observation(observation: object, nonce: str) -> dict[str, bool]:
    """Re-derive every link check from the Watch-side observation JSON."""

    record = observation if isinstance(observation, dict) else {}
    probe = record.get("probe") if isinstance(record.get("probe"), dict) else {}
    reply = probe.get("reply") if isinstance(probe.get("reply"), dict) else {}
    link = record.get("phone_link") if isinstance(record.get("phone_link"), dict) else {}
    reply_updated = _number(reply.get("updated_at_ms"))
    snapshot_updated = _number(link.get("snapshot_updated_at_ms"))
    return {
        "contract": record.get("contract") == OBSERVATION_CONTRACT,
        "nonce": bool(NONCE_RE.fullmatch(nonce)) and record.get("nonce") == nonce,
        "complete": record.get("complete") is True,
        "watch_bundle_id": record.get("watch_bundle_id") == SIMULATOR_WATCH_BUNDLE_ID,
        "companion_bundle_id": record.get("companion_bundle_id") == SIMULATOR_PHONE_BUNDLE_ID,
        "wc_supported": record.get("wc_supported") is True,
        "activation_activated": record.get("activation_state") == "activated",
        "companion_app_installed": record.get("is_companion_app_installed") is True,
        "reachable": record.get("reachable_ever") is True,
        "reply_received": probe.get("reply_received") is True and reply.get("present") is True,
        "reply_protocol_version": reply.get("protocol_version") == WATCH_PROTOCOL_VERSION
        and type(reply.get("protocol_version")) is int,
        "reply_timestamped": reply_updated is not None and reply_updated > 0,
        "reply_from_running_app": reply.get("status") in PHONE_PUBLISHED_STATUSES,
        # The shipping PhoneLink applied phone state at least as new as the
        # live reply. Its final link state is recorded but not judged: its own
        # 4 s request timeout marks the link unreachable when a loaded
        # simulator host takes longer (measured 14 s, final run 2).
        "phone_link_current": reply_updated is not None
        and reply_updated > 0
        and snapshot_updated is not None
        and snapshot_updated >= reply_updated,
    }


def observation_verdict(checks: Mapping[str, bool]) -> str:
    if tuple(checks) != OBSERVATION_CHECKS:
        return "FAIL"
    return "PASS" if all(checks[name] is True for name in OBSERVATION_CHECKS) else "FAIL"


def negative_control_held(checks: Mapping[str, bool]) -> bool:
    """The Watch app ran and reported, and a link check failed."""

    if tuple(checks) != OBSERVATION_CHECKS:
        return False
    return all(checks[name] is True for name in WELL_FORMED_CHECKS) and not all(
        checks[name] is True for name in LINK_CHECKS
    )


def not_installed_control_held(case: Mapping[str, Any], checks: Mapping[str, bool]) -> bool:
    """With the phone app removed the Watch app never reported for this nonce.

    watchOS removes a Watch app that does not run independently of its
    companion once the companion is uninstalled (WKRunsIndependentlyOfCompanionApp
    false), so the launch fails or nothing is written; either way no link
    evidence exists for the nonce.
    """

    if tuple(checks) != OBSERVATION_CHECKS or checks["nonce"] or checks["complete"]:
        return False
    removed = case.get("watch_app_installed_after_phone_uninstall") is False
    launch_failed = type(case.get("watch_launch_exit")) is int and case["watch_launch_exit"] != 0
    return removed or launch_failed


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WatchSmokeError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise WatchSmokeError(f"non-finite JSON number {value}")


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WatchSmokeError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise WatchSmokeError(f"{label} must contain one JSON object")
    return value


def require_receipt_relative_path(value: object) -> str:
    if type(value) is not str or not value:
        raise WatchSmokeError("watch companion smoke receipt path must be repository-relative")
    if value.startswith("/") or "\\" in value or ".." in pathlib.PurePosixPath(value).parts:
        raise WatchSmokeError("watch companion smoke receipt path must be repository-relative")
    if not RECEIPT_PATH_RE.fullmatch(value):
        raise WatchSmokeError(
            "watch companion smoke receipt must be "
            f"{RECEIPT_ROOT_RELATIVE}/<UTC stamp>/{RECEIPT_NAME}"
        )
    return value


def _require_owner_only_components(root: pathlib.Path, relative: str) -> pathlib.Path:
    """Every component from .artifacts down: real, owned by this user, 0700/0600."""

    expected_uid = os.getuid()
    parts = pathlib.PurePosixPath(relative).parts
    current = root
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise WatchSmokeError(
                f"watch companion smoke receipt does not exist: {relative}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise WatchSmokeError(
                f"watch companion smoke receipt must not traverse a symbolic link: {relative}"
            )
        final = index == len(parts) - 1
        if final:
            if not stat.S_ISREG(metadata.st_mode):
                raise WatchSmokeError("watch companion smoke receipt must be a regular file")
            if metadata.st_nlink != 1:
                raise WatchSmokeError("watch companion smoke receipt must not be hard-linked")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise WatchSmokeError("watch companion smoke receipt must be mode 0600")
        else:
            if not stat.S_ISDIR(metadata.st_mode):
                raise WatchSmokeError("watch companion smoke receipt parent must be a directory")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise WatchSmokeError("watch companion smoke receipt directory is not owner-only")
        if metadata.st_uid != expected_uid:
            raise WatchSmokeError("watch companion smoke receipt is not owned by the current user")
    return current


def read_receipt_bytes(root: pathlib.Path, relative: str) -> bytes:
    path = _require_owner_only_components(root, require_receipt_relative_path(relative))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WatchSmokeError(f"watch companion smoke receipt is unreadable: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise WatchSmokeError("watch companion smoke receipt must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > RECEIPT_MAX_BYTES:
            raise WatchSmokeError("watch companion smoke receipt size is out of bounds")
        chunks: list[bytes] = []
        remaining = RECEIPT_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if len(payload) > RECEIPT_MAX_BYTES:
        raise WatchSmokeError("watch companion smoke receipt size is out of bounds")
    return payload


def _require_dict(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WatchSmokeError(f"watch companion smoke receipt {label} must be an object")
    return value


def _require_case(case: object, label: str) -> tuple[dict[str, Any], dict[str, bool]]:
    record = _require_dict(case, label)
    nonce = record.get("nonce")
    if type(nonce) is not str or not NONCE_RE.fullmatch(nonce):
        raise WatchSmokeError(f"watch companion smoke receipt {label} nonce is invalid")
    checks = evaluate_observation(record.get("observation"), nonce)
    if record.get("checks") != checks:
        raise WatchSmokeError(
            f"watch companion smoke receipt {label} checks do not match its observation"
        )
    return record, checks


def _require_activation_retries(record: Mapping[str, Any], label: str) -> list[str]:
    """Earlier launches of one case may be recorded only when the Watch side
    WatchConnectivity session never activated (an environment that was not
    ready). A launch that activated, linked or not, can never be retried away.
    """

    retries = record.get("activation_retries", [])
    if not isinstance(retries, list) or len(retries) > MAX_ACTIVATION_RETRIES:
        raise WatchSmokeError(f"watch companion smoke receipt {label} retries are invalid")
    nonces = []
    for index, retry in enumerate(retries):
        attempt, checks = _require_case(retry, f"{label} retry {index}")
        if checks["activation_activated"] or checks["reply_received"]:
            raise WatchSmokeError(
                f"watch companion smoke receipt {label} retried a launch that activated"
            )
        nonces.append(attempt["nonce"])
    return nonces


def _require_producer_record(
    receipt: Mapping[str, Any], *, release: str, runner: Mapping[str, Any], watch: Mapping[str, Any]
) -> None:
    """The parts of a receipt only a producer run writes (R24 V1 F1).

    The observation checks alone re-derive the verdict, but not that the receipt
    came from this producer, from the measured release build, or from a real
    simulator pair. Binding the tool digest to this module's own bytes means a
    receipt written by other code (a fixture, a stale draft, a hand trim) is
    refused. It is still local self-attestation: it cannot stop the machine
    owner from writing a consistent record.
    """

    version, _, build = release.partition("+")
    if (
        str(runner.get("version")) != version
        or str(runner.get("build")) != build
        or str(watch.get("version")) != version
        or str(watch.get("build")) != build
        or watch.get("smoke_hook_present") is not True
    ):
        raise WatchSmokeError(
            "watch companion smoke receipt apps are not the measured release build"
        )
    tool = _require_dict(receipt.get("tool"), "tool")
    if tool.get("path") != TOOL_RELATIVE or tool.get("sha256") != sha256_file(
        pathlib.Path(__file__).resolve()
    ):
        raise WatchSmokeError("watch companion smoke receipt was not made by this producer")
    host = _require_dict(receipt.get("host"), "host")
    if type(host.get("xcode")) is not str or not host["xcode"]:
        raise WatchSmokeError("watch companion smoke receipt host record is invalid")
    simulators = _require_dict(receipt.get("simulators"), "simulators")
    created = set()
    for role in ("phone", "watch"):
        device = _require_dict(simulators.get(role), f"simulators {role}")
        udid = device.get("udid")
        if type(udid) is not str or not udid:
            raise WatchSmokeError("watch companion smoke receipt simulator record is invalid")
        created.add(udid)
    if len(created) != 2 or any(
        type(simulators.get(key)) is not str or not simulators[key]
        for key in ("pair", "pair_state")
    ):
        raise WatchSmokeError("watch companion smoke receipt simulator pair is invalid")
    cleanup = receipt.get("cleanup")
    if (
        not isinstance(cleanup, list)
        or len(cleanup) != len(created)
        or any(
            not isinstance(item, dict)
            or not (item.get("kept") is True or type(item.get("delete_exit")) is int)
            for item in cleanup
        )
        or {item.get("udid") for item in cleanup} != created
    ):
        raise WatchSmokeError("watch companion smoke receipt cleanup record is invalid")


def verify_receipt_document(
    receipt: Mapping[str, Any],
    *,
    release: str,
    source_commit: str,
    require_clean_tree: bool = True,
) -> None:
    """Every receipt claim the validators rely on, re-derived from the receipt.

    Validators always require a clean tree; only the producer's own self-check
    on a development tree passes ``require_clean_tree=False``.
    """

    if receipt.get("schema_version") != SCHEMA_VERSION or receipt.get("contract") != CONTRACT:
        raise WatchSmokeError("watch companion smoke receipt contract is invalid")
    if not RELEASE_RE.fullmatch(release) or receipt.get("release") != release:
        raise WatchSmokeError(
            f"watch companion smoke receipt release is {receipt.get('release')!r}, expected {release!r}"
        )
    version, _, build = release.partition("+")
    if receipt.get("app_version") != version or str(receipt.get("build_number")) != build:
        raise WatchSmokeError("watch companion smoke receipt version and build do not match")
    if receipt.get("statement") != STATEMENT:
        raise WatchSmokeError("watch companion smoke receipt must state it is a simulator build")
    if receipt.get("verdict") != "PASS":
        raise WatchSmokeError("watch companion smoke receipt verdict is not PASS")
    source = _require_dict(receipt.get("source"), "source")
    if not COMMIT_RE.fullmatch(source_commit or ""):
        raise WatchSmokeError("release candidate set does not record a 40-hex source commit")
    if source.get("git_commit") != source_commit:
        raise WatchSmokeError(
            "watch companion smoke receipt source commit does not match the release candidate set"
        )
    if require_clean_tree and source.get("tree_clean") is not True:
        raise WatchSmokeError("watch companion smoke receipt was produced from a dirty tree")
    artifacts = _require_dict(receipt.get("artifacts"), "artifacts")
    runner = _require_dict(artifacts.get("runner_app"), "runner_app")
    watch = _require_dict(artifacts.get("watch_app"), "watch_app")
    if (
        runner.get("bundle_id") != SIMULATOR_PHONE_BUNDLE_ID
        or runner.get("platform") != "iphonesimulator"
        or not SHA256_RE.fullmatch(str(runner.get("executable_sha256") or ""))
    ):
        raise WatchSmokeError("watch companion smoke receipt Runner.app identity is invalid")
    if (
        watch.get("bundle_id") != SIMULATOR_WATCH_BUNDLE_ID
        or watch.get("companion_bundle_id") != SIMULATOR_PHONE_BUNDLE_ID
        or watch.get("executable") != WATCH_EXECUTABLE
        or watch.get("platform") != "watchsimulator"
        or watch.get("build_platforms") != ["WATCHOSSIMULATOR"]
        or not SHA256_RE.fullmatch(str(watch.get("executable_sha256") or ""))
    ):
        raise WatchSmokeError("watch companion smoke receipt WinsWatch.app identity is invalid")
    _require_producer_record(receipt, release=release, runner=runner, watch=watch)
    positive, positive_checks = _require_case(receipt.get("positive"), "positive")
    if observation_verdict(positive_checks) != "PASS" or positive.get("verdict") != "PASS":
        raise WatchSmokeError(
            "watch companion smoke receipt positive observation does not prove the link"
        )
    retry_nonces = _require_activation_retries(positive, "positive")
    negatives = receipt.get("negative_cases")
    if not isinstance(negatives, list) or [
        item.get("case") if isinstance(item, dict) else None for item in negatives
    ] != list(NEGATIVE_CASES):
        raise WatchSmokeError(
            "watch companion smoke receipt must carry the not-running and not-installed controls"
        )
    nonces = {positive.get("nonce")}
    for index, item in enumerate(negatives):
        label = f"negative case {item.get('case')}"
        negative, negative_checks = _require_case(item, label)
        if negative.get("case") == NOT_INSTALLED_CASE:
            held = not_installed_control_held(negative, negative_checks)
        else:
            held = negative_control_held(negative_checks)
        if (
            negative.get("expected") != "FAIL"
            or negative.get("observed_verdict") != "FAIL"
            or observation_verdict(negative_checks) != "FAIL"
            or not held
            or negative.get("control_held") is not True
        ):
            raise WatchSmokeError(
                f"watch companion smoke receipt {label} did not fail on the link"
            )
        nonces.add(negative.get("nonce"))
        retry_nonces.extend(_require_activation_retries(negative, label))
    if len(nonces) != len(NEGATIVE_CASES) + 1 or len(nonces | set(retry_nonces)) != len(
        nonces
    ) + len(retry_nonces):
        raise WatchSmokeError("watch companion smoke receipt reuses one launch nonce")


def verify_receipt(
    root: pathlib.Path,
    receipt_path: object,
    receipt_sha256: object,
    *,
    release: str,
    source_commit: str,
) -> dict[str, Any]:
    """Re-hash a durable receipt and re-derive its verdict. Fails closed."""

    relative = require_receipt_relative_path(receipt_path)
    expected = str(receipt_sha256 or "")
    if not SHA256_RE.fullmatch(expected):
        raise WatchSmokeError("watch companion smoke receipt sha256 must be lowercase hex")
    payload = read_receipt_bytes(root, relative)
    if hashlib.sha256(payload).hexdigest() != expected:
        raise WatchSmokeError(
            "watch companion smoke receipt sha256 does not match the receipt bytes"
        )
    receipt = _strict_json(payload, "watch companion smoke receipt")
    verify_receipt_document(receipt, release=release, source_commit=source_commit)
    return receipt


def runtime_watch_smoke_sha256(
    root: pathlib.Path,
    runtime: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    release: str,
    require_passed: bool = False,
) -> str:
    """The receipt digest the owner evidence set may carry, or "" while pending.

    A pending smoke is unbound (empty path and digest). A passed smoke must name
    a durable receipt under .artifacts whose bytes hash to the recorded digest,
    whose verdict re-derives as PASS, and whose release and source commit match
    the complete release candidate set. Anything else is refused.
    """

    if "watch_companion_smoke_sha256" in runtime:
        raise WatchSmokeError(
            "runtime evidence must bind watch_companion_smoke as a receipt, not a bare digest"
        )
    smoke = runtime.get("watch_companion_smoke")
    if not isinstance(smoke, dict) or set(smoke) != SMOKE_KEYS:
        raise WatchSmokeError("runtime evidence watch_companion_smoke schema is invalid")
    status = smoke.get("status")
    if status == "pending":
        if smoke.get("receipt_path") != "" or smoke.get("receipt_sha256") != "":
            raise WatchSmokeError("pending watch companion smoke must not bind a receipt")
        if require_passed:
            raise WatchSmokeError("complete evidence requires a passed watch companion smoke")
        return ""
    if status != "passed":
        raise WatchSmokeError("watch companion smoke status must be pending or passed")
    if candidate.get("candidate_set_status") != COMPLETE_LOCAL_CANDIDATES:
        raise WatchSmokeError(
            "a passed watch companion smoke requires a complete release candidate set"
        )
    candidate_release = f"{candidate.get('app_version')}+{candidate.get('build_number')}"
    if candidate_release != release:
        raise WatchSmokeError("release candidate set is not the expected release")
    verify_receipt(
        root,
        smoke.get("receipt_path"),
        smoke.get("receipt_sha256"),
        release=release,
        source_commit=str(candidate.get("source_commit") or ""),
    )
    return str(smoke["receipt_sha256"])


# ---------------------------------------------------------------------------
# Producer: build, pair, observe, receipt.
# ---------------------------------------------------------------------------


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Runner:
    """Bounded subprocess runner that keeps a transcript in the receipt directory."""

    def __init__(self, transcript: pathlib.Path) -> None:
        self.transcript = transcript

    def log(self, text: str) -> None:
        line = f"[{utc_now()}] {text}\n"
        sys.stdout.write(line)
        sys.stdout.flush()
        with self.transcript.open("a", encoding="utf-8") as handle:
            handle.write(line)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        cwd: pathlib.Path | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        output: pathlib.Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.log("+ " + " ".join(argv))
        if output is not None:
            with output.open("a", encoding="utf-8") as handle:
                completed = subprocess.run(
                    list(argv),
                    cwd=str(cwd) if cwd else None,
                    env=dict(env) if env is not None else None,
                    stdin=subprocess.DEVNULL,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            completed = subprocess.CompletedProcess(completed.args, completed.returncode, "", "")
        else:
            completed = subprocess.run(
                list(argv),
                cwd=str(cwd) if cwd else None,
                env=dict(env) if env is not None else None,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            tail = (completed.stdout or "")[-2000:] + (completed.stderr or "")[-2000:]
            if tail.strip():
                with self.transcript.open("a", encoding="utf-8") as handle:
                    handle.write(tail if tail.endswith("\n") else tail + "\n")
        self.log(f"  exit {completed.returncode}")
        if check and completed.returncode != 0:
            raise WatchSmokeError(f"command failed ({completed.returncode}): {' '.join(argv)}")
        return completed


def _write_private_file(path: pathlib.Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        # os.write may accept fewer bytes than offered; write_receipt returns the
        # digest of the payload, so a short write must not leave a shorter file.
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def _fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def make_receipt_directory(root: pathlib.Path, stamp: str) -> pathlib.Path:
    if not STAMP_RE.fullmatch(stamp):
        raise WatchSmokeError("receipt stamp must be YYYYMMDDTHHMMSSZ")
    current = root
    for part in pathlib.PurePosixPath(RECEIPT_ROOT_RELATIVE).parts:
        current = current / part
        if current.is_symlink():
            raise WatchSmokeError(f"{current} must not be a symbolic link")
        if not current.exists():
            current.mkdir(mode=0o700)
            os.chmod(current, 0o700)
        elif not current.is_dir():
            raise WatchSmokeError(f"{current} must be a directory")
        if stat.S_IMODE(current.lstat().st_mode) & 0o077:
            raise WatchSmokeError(f"{current} must be owner-only")
    directory = current / stamp
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def write_receipt(directory: pathlib.Path, receipt: Mapping[str, Any]) -> tuple[pathlib.Path, str]:
    payload = (json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "ascii"
    )
    path = directory / RECEIPT_NAME
    _write_private_file(path, payload)
    _fsync_directory(directory)
    return path, hashlib.sha256(payload).hexdigest()


def read_release(root: pathlib.Path) -> str:
    text = (root / "pubspec.yaml").read_text(encoding="utf-8")
    matches = re.findall(r"(?m)^version:\s*([0-9]+\.[0-9]+\.[0-9]+\+[0-9]+)\s*$", text)
    if len(matches) != 1:
        raise WatchSmokeError("pubspec.yaml must declare exactly one version")
    return matches[0]


def git_source(root: pathlib.Path, runner: Runner) -> dict[str, Any]:
    head = runner.run(
        ["/usr/bin/git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"], timeout=60
    ).stdout.strip()
    if not COMMIT_RE.fullmatch(head):
        raise WatchSmokeError("git HEAD is not a 40-hex commit")
    status = runner.run(
        ["/usr/bin/git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=normal"],
        timeout=300,
    ).stdout
    entries = [line for line in status.splitlines() if line.strip()]
    tracked = sorted(line[3:] for line in entries if not line.startswith("??"))
    untracked = sorted(line[3:] for line in entries if line.startswith("??"))
    return {
        "git_commit": head,
        "tree_clean": not entries,
        "tracked_changes": tracked,
        "untracked_files": untracked,
    }


def _json_path(document: Mapping[str, Any], dotted: Sequence[str]) -> Any:
    value: Any = document
    for key in dotted:
        if not isinstance(value, dict) or key not in value:
            raise WatchSmokeError(f"engine provenance lacks {'.'.join(dotted)}")
        value = value[key]
    return value


def simulator_engine_inputs(root: pathlib.Path) -> list[dict[str, str]]:
    """Every simulator engine input and its committed provenance pin.

    ios/PacketTunnel links these for the iphonesimulator SDK and
    tools/stage_apple_engine_artifacts.sh verifies all five Winn archives, so a
    simulator build needs them on disk. They are not tracked; the committed
    provenance pins their exact bytes.
    """

    awg_file = "apple/EngineArtifacts/apple_awg_31_engine_provenance.json"
    xray_file = "apple/EngineArtifacts/apple_xray_vless_ws_engine_provenance.json"
    winn_file = "apple/EngineArtifacts/apple_winn_v3_engine_provenance.json"
    awg = json.loads((root / awg_file).read_text(encoding="utf-8"))
    xray = json.loads((root / xray_file).read_text(encoding="utf-8"))
    winn = json.loads((root / winn_file).read_text(encoding="utf-8"))
    inputs = [
        {
            "path": "apple/EngineArtifacts/ios/iphonesimulator/libWinsAmneziaWGPacketEngine.dylib",
            "sha256": _json_path(awg, ("wrappers", "iphonesimulator", "amneziawg_packet_engine", "sha256")),
            "provenance": awg_file,
        },
        {
            "path": "apple/EngineArtifacts/ios/iphonesimulator/libWinsXrayVlessWsTransport.dylib",
            "sha256": _json_path(xray, ("wrappers", "iphonesimulator", "sha256")),
            "provenance": xray_file,
        },
        {
            "path": "apple/EngineArtifacts/ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
            "sha256": _json_path(winn, ("wrappers", "iphonesimulator", "sha256")),
            "provenance": winn_file,
        },
    ]
    if _json_path(awg, ("wrappers", "iphonesimulator", "xray_vless_ws_transport", "sha256")) != inputs[1]["sha256"]:
        raise WatchSmokeError("AWG and Xray provenance disagree on the simulator Xray wrapper")
    archives = _json_path(winn, ("archives",))
    if not isinstance(archives, dict) or not archives:
        raise WatchSmokeError("Winn provenance lists no archives")
    for key in sorted(archives):
        entry = archives[key]
        for name_key, sha_key in (("path", "sha256"), ("header_path", "header_sha256")):
            name = _json_path(entry, (name_key,))
            if type(name) is not str or "/" in name or not name.startswith("libwinn-datapath-"):
                raise WatchSmokeError(f"Winn provenance archive {key} names an unsafe path")
            inputs.append(
                {
                    "path": f"tools/winn_conformance_build_out/{name}",
                    "sha256": _json_path(entry, (sha_key,)),
                    "provenance": winn_file,
                }
            )
    for item in inputs:
        if not SHA256_RE.fullmatch(str(item["sha256"])):
            raise WatchSmokeError(f"engine provenance pin for {item['path']} is not a sha256")
    return inputs


def stage_simulator_engines(
    root: pathlib.Path, source_root: pathlib.Path | None, runner: Runner
) -> list[dict[str, str]]:
    staged: list[dict[str, str]] = []
    for item in simulator_engine_inputs(root):
        destination = root / item["path"]
        origin = "already_present"
        if destination.is_symlink():
            raise WatchSmokeError(f"{item['path']} must not be a symbolic link")
        if not destination.exists():
            if source_root is None:
                raise WatchSmokeError(
                    f"{item['path']} is missing; pass --engine-source-root with the pinned bytes"
                )
            source = source_root / item["path"]
            if source.is_symlink() or not source.is_file():
                raise WatchSmokeError(f"engine source {source} is missing or symbolic")
            if sha256_file(source) != item["sha256"]:
                raise WatchSmokeError(f"engine source {source} does not match its provenance pin")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(4)}.tmp")
            shutil.copyfile(source, temporary)
            os.chmod(temporary, 0o755 if destination.suffix == ".dylib" else 0o644)
            os.replace(temporary, destination)
            origin = str(source_root)
        actual = sha256_file(destination)
        if actual != item["sha256"]:
            raise WatchSmokeError(f"{item['path']} does not match its committed provenance pin")
        runner.log(f"engine input {item['path']} sha256={actual} ({origin})")
        staged.append({**item, "origin": origin})
    return staged


def _plist(path: pathlib.Path) -> dict[str, Any]:
    value = plistlib.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise WatchSmokeError(f"{path} is not a dictionary plist")
    return value


def build_platforms(path: pathlib.Path, runner: Runner) -> list[str]:
    output = runner.run(["/usr/bin/xcrun", "vtool", "-show-build", str(path)], timeout=120).stdout
    platforms = sorted(set(re.findall(r"(?m)^\s*platform\s+(\S+)\s*$", output)))
    if not platforms:
        raise WatchSmokeError(f"{path} has no LC_BUILD_VERSION platform")
    return platforms


def inspect_build(root: pathlib.Path, runner: Runner) -> dict[str, Any]:
    app = root / "build/ios/iphonesimulator/Runner.app"
    watch_app = app / "Watch/WinsWatch.app"
    if not app.is_dir() or app.is_symlink():
        raise WatchSmokeError("build/ios/iphonesimulator/Runner.app was not produced")
    if not watch_app.is_dir() or watch_app.is_symlink():
        raise WatchSmokeError("Runner.app/Watch/WinsWatch.app was not produced")
    info = _plist(app / "Info.plist")
    watch_info = _plist(watch_app / "Info.plist")
    runner_executable = app / str(info.get("CFBundleExecutable") or "")
    watch_executable = watch_app / str(watch_info.get("CFBundleExecutable") or "")
    if info.get("CFBundleIdentifier") != SIMULATOR_PHONE_BUNDLE_ID:
        raise WatchSmokeError("simulator Runner.app is not the debug phone bundle")
    if info.get("DTPlatformName") != "iphonesimulator":
        raise WatchSmokeError("Runner.app is not an iphonesimulator build")
    if (
        watch_info.get("CFBundleIdentifier") != SIMULATOR_WATCH_BUNDLE_ID
        or watch_info.get("WKCompanionAppBundleIdentifier") != SIMULATOR_PHONE_BUNDLE_ID
        or watch_info.get("CFBundleExecutable") != WATCH_EXECUTABLE
    ):
        raise WatchSmokeError("embedded WinsWatch.app does not carry the debug Watch identity")
    if watch_info.get("DTPlatformName") != "watchsimulator":
        raise WatchSmokeError("embedded WinsWatch.app is not a watchsimulator build")
    platforms = build_platforms(watch_executable, runner)
    if platforms != ["WATCHOSSIMULATOR"]:
        raise WatchSmokeError(f"WinsWatch executable platforms are {platforms}")
    # Xcode Debug builds may place the code in <Name>.debug.dylib beside a stub.
    watch_code = [watch_executable] + sorted(watch_app.glob(f"{WATCH_EXECUTABLE}.debug.dylib"))
    hook_present = any(WATCH_SMOKE_BINARY_MARKER in path.read_bytes() for path in watch_code)
    if not hook_present:
        raise WatchSmokeError("the simulator Watch build does not contain the debug smoke hook")
    debug_dylib = watch_app / f"{WATCH_EXECUTABLE}.debug.dylib"
    runner_debug_dylib = app / f"{runner_executable.name}.debug.dylib"
    return {
        "runner_app": {
            "path": app.relative_to(root).as_posix(),
            "bundle_id": info.get("CFBundleIdentifier"),
            "version": info.get("CFBundleShortVersionString"),
            "build": info.get("CFBundleVersion"),
            "executable": runner_executable.name,
            "executable_sha256": sha256_file(runner_executable),
            "debug_dylib_sha256": sha256_file(runner_debug_dylib) if runner_debug_dylib.is_file() else "",
            "platform": info.get("DTPlatformName"),
            "build_kind": "flutter build ios --simulator --debug (simulator build, not the App Store IPA)",
        },
        "watch_app": {
            "path": watch_app.relative_to(root).as_posix(),
            "bundle_id": watch_info.get("CFBundleIdentifier"),
            "companion_bundle_id": watch_info.get("WKCompanionAppBundleIdentifier"),
            "version": watch_info.get("CFBundleShortVersionString"),
            "build": watch_info.get("CFBundleVersion"),
            "executable": watch_executable.name,
            "executable_sha256": sha256_file(watch_executable),
            "debug_dylib_sha256": sha256_file(debug_dylib) if debug_dylib.is_file() else "",
            "platform": watch_info.get("DTPlatformName"),
            "build_platforms": platforms,
            "smoke_hook_present": hook_present,
        },
    }


class Simulators:
    """Only ever touches the devices it created, by UDID."""

    def __init__(self, runner: Runner, ledger: pathlib.Path) -> None:
        self.runner = runner
        self.ledger = ledger
        self.created: list[str] = []

    def simctl(self, *args: str, timeout: float = 300, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self.runner.run(["/usr/bin/xcrun", "simctl", *args], timeout=timeout, check=check)

    def listing(self) -> dict[str, Any]:
        return json.loads(self.simctl("list", "-j", "runtimes", "devicetypes", timeout=120).stdout)

    def create(self, name: str, device_type: str, runtime: str) -> str:
        udid = self.simctl("create", name, device_type, runtime, timeout=300).stdout.strip()
        if not re.fullmatch(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", udid):
            raise WatchSmokeError(f"simctl create returned {udid!r}")
        self.created.append(udid)
        with self.ledger.open("a", encoding="utf-8") as handle:
            handle.write(f"{udid} {name}\n")
        return udid

    def pair_state(self, pair: str) -> str:
        pairs = json.loads(self.simctl("list", "-j", "pairs", timeout=120).stdout).get("pairs", {})
        record = pairs.get(pair) if isinstance(pairs, dict) else None
        return str(record.get("state") or "") if isinstance(record, dict) else ""

    def activate_pair(self, pair: str, *, timeout_seconds: float) -> str:
        """A new pair is often already active; activate only when it is not."""

        state = self.pair_state(pair)
        if "active" not in state.replace("inactive", ""):
            self.simctl("pair_activate", pair, timeout=300)
        end = time.monotonic() + timeout_seconds
        while True:
            state = self.pair_state(pair)
            active = "active" in state.replace("inactive", "")
            if active and "connected" in state.replace("disconnected", ""):
                return state
            if time.monotonic() >= end:
                raise WatchSmokeError(f"simulator pair {pair} did not become active and connected: {state!r}")
            time.sleep(3)

    def cleanup(self) -> list[dict[str, Any]]:
        results = []
        for udid in reversed(self.created):
            shutdown = self.simctl("shutdown", udid, timeout=300, check=False).returncode
            delete = self.simctl("delete", udid, timeout=300, check=False).returncode
            results.append({"udid": udid, "shutdown_exit": shutdown, "delete_exit": delete})
        return results


def _runtime(listing: Mapping[str, Any], platform: str, requested: str | None) -> dict[str, Any]:
    runtimes = [
        item
        for item in listing.get("runtimes", [])
        if item.get("platform") == platform and item.get("isAvailable") is True
    ]
    if requested:
        runtimes = [item for item in runtimes if item.get("identifier") == requested]
    if not runtimes:
        raise WatchSmokeError(f"no available {platform} simulator runtime")
    return max(runtimes, key=lambda item: [int(part) for part in str(item.get("version")).split(".")])


def _device_type(runtime: Mapping[str, Any], prefix: str, preferred: Sequence[str], requested: str | None) -> dict[str, Any]:
    supported = [item for item in runtime.get("supportedDeviceTypes", []) if str(item.get("name", "")).startswith(prefix)]
    if requested:
        supported = [item for item in supported if item.get("identifier") == requested or item.get("name") == requested]
        if not supported:
            raise WatchSmokeError(f"device type {requested!r} is not supported by {runtime.get('identifier')}")
        return supported[0]
    for name in preferred:
        for item in supported:
            if item.get("name") == name:
                return item
    if not supported:
        raise WatchSmokeError(f"{runtime.get('identifier')} supports no {prefix} device type")
    return supported[0]


def read_observation(
    sims: Simulators, watch_udid: str, nonce: str, *, deadline_seconds: float, copy_to: pathlib.Path
) -> dict[str, Any]:
    end = time.monotonic() + deadline_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < end:
        completed = sims.simctl(
            "get_app_container", watch_udid, SIMULATOR_WATCH_BUNDLE_ID, "data", timeout=120, check=False
        )
        container = pathlib.Path(completed.stdout.strip()) if completed.returncode == 0 else None
        if container is not None:
            path = container / WATCH_OBSERVATION_RELATIVE
            if path.is_file() and not path.is_symlink():
                try:
                    candidate = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    candidate = {}
                if isinstance(candidate, dict) and candidate.get("nonce") == nonce:
                    last = candidate
                    if candidate.get("complete") is True:
                        break
        time.sleep(2)
    _write_private_file(copy_to, (json.dumps(last, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return last


def watch_case(
    sims: Simulators,
    watch_udid: str,
    label: str,
    directory: pathlib.Path,
    *,
    deadline_seconds: float,
    launch_must_succeed: bool = True,
) -> dict[str, Any]:
    nonce = secrets.token_hex(16)
    started = utc_now()
    launched = sims.simctl(
        "launch",
        "--terminate-running-process",
        watch_udid,
        SIMULATOR_WATCH_BUNDLE_ID,
        WATCH_SMOKE_ARGUMENT,
        nonce,
        timeout=300,
        check=launch_must_succeed,
    )
    observation = read_observation(
        sims,
        watch_udid,
        nonce,
        deadline_seconds=deadline_seconds if launched.returncode == 0 else 10,
        copy_to=directory / f"observation-{label}.json",
    )
    sims.simctl("terminate", watch_udid, SIMULATOR_WATCH_BUNDLE_ID, timeout=120, check=False)
    checks = evaluate_observation(observation, nonce)
    return {
        "nonce": nonce,
        "started_at_utc": started,
        "finished_at_utc": utc_now(),
        "watch_launch_exit": launched.returncode,
        "observation": observation,
        "checks": checks,
        "verdict": observation_verdict(checks),
    }


def watch_case_after_activation(
    sims: Simulators,
    watch_udid: str,
    label: str,
    directory: pathlib.Path,
    *,
    deadline_seconds: float,
) -> dict[str, Any]:
    """Relaunch only while the Watch WatchConnectivity session never activated.

    On a freshly booted, heavily loaded host the watch simulator's session can
    stay notActivated for the whole window (measured 2026-10-18, final run 1).
    That says nothing about the link, so the launch is repeated, at most
    MAX_ACTIVATION_RETRIES times; every earlier launch is kept in the receipt
    and the validators refuse a retry of any launch that activated.
    """

    retries: list[dict[str, Any]] = []
    while True:
        attempt_label = label if not retries else f"{label}-attempt-{len(retries) + 1}"
        case = watch_case(sims, watch_udid, attempt_label, directory, deadline_seconds=deadline_seconds)
        if (
            case["checks"]["activation_activated"]
            or case["checks"]["reply_received"]
            or len(retries) >= MAX_ACTIVATION_RETRIES
        ):
            case["activation_retries"] = retries
            return case
        sims.runner.log(f"{label}: the Watch session never activated; relaunching")
        retries.append({key: value for key, value in case.items() if key != "verdict"})
        time.sleep(15)


def watch_app_installed(sims: Simulators, watch_udid: str) -> bool:
    listing = sims.simctl("listapps", watch_udid, timeout=120).stdout
    return re.search(r"CFBundleIdentifier = \"?" + re.escape(SIMULATOR_WATCH_BUNDLE_ID) + r"\"?;", listing) is not None


def unified_log(sims: Simulators, udid: str, process: str, path: pathlib.Path) -> None:
    completed = sims.runner.run(
        [
            "/usr/bin/xcrun",
            "simctl",
            "spawn",
            udid,
            "log",
            "show",
            "--last",
            "20m",
            "--style",
            "compact",
            "--info",
            "--predicate",
            f'process == "{process}" OR (subsystem == "com.apple.watchconnectivity" AND process != "")',
        ],
        timeout=600,
        check=False,
    )
    text = (completed.stdout or "")[-4 * 1024 * 1024 :]
    _write_private_file(path, text.encode("utf-8", errors="replace"))


def produce(args: argparse.Namespace) -> int:
    root = ROOT
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = make_receipt_directory(root, stamp)
    transcript = directory / "smoke.log"
    _write_private_file(transcript, b"")
    runner = Runner(transcript)
    ledger = directory / "created_simulators.txt"
    _write_private_file(ledger, b"")
    sims = Simulators(runner, ledger)
    started = utc_now()
    release = read_release(root)
    version, _, build_number = release.partition("+")
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "release": release,
        "app_version": version,
        "build_number": build_number,
        "statement": STATEMENT,
        "started_at_utc": started,
        "verdict": "FAIL",
        "tool": {"path": TOOL_RELATIVE, "sha256": sha256_file(root / TOOL_RELATIVE)},
    }
    exit_code = 1
    try:
        receipt["source"] = git_source(root, runner)
        xcode = runner.run(["/usr/bin/xcrun", "xcodebuild", "-version"], timeout=120).stdout
        flutter_bin = pathlib.Path(args.flutter)
        flutter_version = json.loads(
            runner.run([str(flutter_bin), "--version", "--machine"], timeout=300).stdout
        )
        receipt["host"] = {
            "xcode": " ".join(xcode.split()),
            "flutter_version": flutter_version.get("frameworkVersion"),
            "flutter_framework_revision": flutter_version.get("frameworkRevision"),
            "dart_sdk_version": flutter_version.get("dartSdkVersion"),
        }
        engines = stage_simulator_engines(
            root, pathlib.Path(args.engine_source_root) if args.engine_source_root else None, runner
        )
        environment = dict(os.environ)
        environment.update({"LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"})
        # The same transaction binding tools/build_apple_release_candidates.sh
        # exports: staging must verify the committed Winn provenance.
        environment["WINS_APPLE_ENGINE_TRANSACTION_PROVENANCE_SHA256"] = sha256_file(
            root / "apple/EngineArtifacts/apple_winn_v3_engine_provenance.json"
        )
        build_log = directory / "build.log"
        _write_private_file(build_log, b"")
        runner.run(
            [str(flutter_bin), "--suppress-analytics", "pub", "get", "--offline"],
            cwd=root, env=environment, timeout=1800, output=build_log,
        )
        runner.run(
            [str(flutter_bin), "--suppress-analytics", "build", "ios", "--simulator", "--debug", "--no-pub"],
            cwd=root, env=environment, timeout=5400, output=build_log,
        )
        artifacts = inspect_build(root, runner)
        artifacts["engine_inputs"] = engines
        receipt["artifacts"] = artifacts

        listing = sims.listing()
        ios_runtime = _runtime(listing, "iOS", args.ios_runtime)
        watch_runtime = _runtime(listing, "watchOS", args.watch_runtime)
        phone_type = _device_type(ios_runtime, "iPhone", ("iPhone 17 Pro", "iPhone 17", "iPhone 16 Pro"), args.phone_device_type)
        watch_type = _device_type(
            watch_runtime,
            "Apple Watch",
            ("Apple Watch Series 11 (46mm)", "Apple Watch Series 11 (42mm)", "Apple Watch Series 10 (46mm)"),
            args.watch_device_type,
        )
        phone = sims.create(f"wins-watchsmoke-phone-{stamp}", phone_type["identifier"], ios_runtime["identifier"])
        watch = sims.create(f"wins-watchsmoke-watch-{stamp}", watch_type["identifier"], watch_runtime["identifier"])
        pair = sims.simctl("pair", watch, phone, timeout=300).stdout.strip()
        receipt["simulators"] = {
            "phone": {
                "udid": phone,
                "device_type": phone_type["identifier"],
                "device_type_name": phone_type["name"],
                "runtime": ios_runtime["identifier"],
                "runtime_version": ios_runtime.get("version"),
                "runtime_build": ios_runtime.get("buildversion"),
            },
            "watch": {
                "udid": watch,
                "device_type": watch_type["identifier"],
                "device_type_name": watch_type["name"],
                "runtime": watch_runtime["identifier"],
                "runtime_version": watch_runtime.get("version"),
                "runtime_build": watch_runtime.get("buildversion"),
            },
            "pair": pair,
        }
        for udid in (phone, watch):
            sims.simctl("boot", udid, timeout=900)
        for udid in (phone, watch):
            sims.simctl("bootstatus", udid, "-b", timeout=1800)
        receipt["simulators"]["pair_state"] = sims.activate_pair(pair, timeout_seconds=600)

        watch_app = root / artifacts["watch_app"]["path"]
        phone_app = root / artifacts["runner_app"]["path"]
        # The phone app first: watchOS removes a Watch app that cannot run
        # without its companion when that companion is absent.
        sims.simctl("install", phone, str(phone_app), timeout=900)
        sims.simctl("install", watch, str(watch_app), timeout=900)
        time.sleep(args.install_settle_seconds)
        if not watch_app_installed(sims, watch):
            raise WatchSmokeError("the Watch app did not stay installed beside its companion")
        cases: dict[str, Any] = {}
        # Control 1: phone app installed but never launched in this boot.
        cases[NOT_RUNNING_CASES[0]] = watch_case_after_activation(
            sims, watch, NOT_RUNNING_CASES[0], directory, deadline_seconds=args.case_seconds
        )
        # The positive case: the phone app running in the foreground.
        sims.simctl("launch", "--terminate-running-process", phone, SIMULATOR_PHONE_BUNDLE_ID, timeout=300)
        time.sleep(args.phone_settle_seconds)
        positive = watch_case_after_activation(
            sims, watch, "positive", directory, deadline_seconds=args.case_seconds
        )
        sims.simctl("io", watch, "screenshot", str(directory / "watch-positive.png"), timeout=300, check=False)
        if (directory / "watch-positive.png").is_file():
            os.chmod(directory / "watch-positive.png", 0o600)
        # Control 2: the same phone app terminated.
        sims.simctl("terminate", phone, SIMULATOR_PHONE_BUNDLE_ID, timeout=120, check=False)
        time.sleep(5)
        cases[NOT_RUNNING_CASES[1]] = watch_case_after_activation(
            sims, watch, NOT_RUNNING_CASES[1], directory, deadline_seconds=args.case_seconds
        )
        # Control 3: the phone app removed from the same pair.
        sims.simctl("terminate", phone, SIMULATOR_PHONE_BUNDLE_ID, timeout=120, check=False)
        sims.simctl("uninstall", phone, SIMULATOR_PHONE_BUNDLE_ID, timeout=600)
        time.sleep(args.install_settle_seconds)
        still_installed = watch_app_installed(sims, watch)
        not_installed = watch_case(
            sims,
            watch,
            NOT_INSTALLED_CASE,
            directory,
            deadline_seconds=args.case_seconds,
            launch_must_succeed=False,
        )
        not_installed["watch_app_installed_after_phone_uninstall"] = still_installed
        cases[NOT_INSTALLED_CASE] = not_installed
        unified_log(sims, watch, WATCH_EXECUTABLE, directory / "watch-unified.log")
        unified_log(sims, phone, "Runner", directory / "phone-unified.log")

        negatives = []
        for name in NEGATIVE_CASES:
            case = cases[name]
            held = (
                not_installed_control_held(case, case["checks"])
                if name == NOT_INSTALLED_CASE
                else negative_control_held(case["checks"])
            )
            negatives.append(
                {
                    "case": name,
                    "expected": "FAIL",
                    **{key: value for key, value in case.items() if key != "verdict"},
                    "observed_verdict": case["verdict"],
                    "control_held": case["verdict"] == "FAIL" and held,
                }
            )
        receipt["positive"] = positive
        receipt["negative_cases"] = negatives
        if positive["verdict"] == "PASS" and all(item["control_held"] for item in negatives):
            receipt["verdict"] = "PASS"
            exit_code = 0
    except (WatchSmokeError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError) as exc:
        receipt["error"] = f"{type(exc).__name__}: {exc}"
        runner.log(f"ERROR {receipt['error']}")
        exit_code = 2
    finally:
        if sims.created and not args.keep_simulators:
            receipt["cleanup"] = sims.cleanup()
        else:
            receipt["cleanup"] = [{"udid": udid, "kept": True} for udid in sims.created]
    receipt["finished_at_utc"] = utc_now()
    source = receipt.get("source") if isinstance(receipt.get("source"), dict) else {}
    if receipt["verdict"] == "PASS":
        # The receipt must pass the validators' own document check (a dirty
        # development tree aside, which every validator still refuses).
        try:
            verify_receipt_document(
                receipt,
                release=release,
                source_commit=str(source.get("git_commit") or ""),
                require_clean_tree=False,
            )
        except WatchSmokeError as exc:
            receipt["verdict"] = "FAIL"
            receipt["error"] = f"self-check: {exc}"
            exit_code = 1
    path, digest = write_receipt(directory, receipt)
    relative = path.relative_to(root).as_posix()
    runner.log(f"WATCH COMPANION SMOKE: {receipt['verdict']} receipt={relative} sha256={digest}")
    if receipt["verdict"] == "PASS" and source.get("tree_clean") is not True:
        runner.log(
            "NOTE: the tree was not clean, so validators will refuse to bind this receipt; "
            "rerun from a clean checkout of the release commit."
        )
    return exit_code


# ---------------------------------------------------------------------------
# Recording.
# ---------------------------------------------------------------------------


def _load_object(path: pathlib.Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise WatchSmokeError(f"{label} is missing or symbolic")
    return _strict_json(path.read_bytes(), label)


def record(root: pathlib.Path, receipt_path: str) -> str:
    """Bind a verified receipt into runtime_evidence.json, or refuse."""

    candidate = _load_object(root / RELEASE_CANDIDATE_RELATIVE, "release_candidate.json")
    runtime_path = root / RUNTIME_EVIDENCE_RELATIVE
    runtime = _load_object(runtime_path, "runtime_evidence.json")
    release = read_release(root)
    if candidate.get("candidate_set_status") != COMPLETE_LOCAL_CANDIDATES:
        raise WatchSmokeError(
            "recording is refused: release_candidate.json is not a complete candidate set"
        )
    if runtime.get("candidate_set_status") not in RUNTIME_RECORDABLE_STATUSES:
        raise WatchSmokeError(
            "recording is refused: runtime_evidence.json has not left the not-started "
            f"state ({runtime.get('candidate_set_status')!r})"
        )
    if f"{runtime.get('app_version')}+{runtime.get('build_number')}" != release:
        raise WatchSmokeError("runtime_evidence.json is not the current release")
    relative = require_receipt_relative_path(receipt_path)
    digest = hashlib.sha256(read_receipt_bytes(root, relative)).hexdigest()
    current = runtime.get("watch_companion_smoke")
    if not isinstance(current, dict) or set(current) != SMOKE_KEYS:
        raise WatchSmokeError("runtime evidence watch_companion_smoke schema is invalid")
    if current.get("status") not in {"pending", "passed"}:
        raise WatchSmokeError("watch companion smoke status must be pending or passed")
    updated = dict(runtime)
    updated["watch_companion_smoke"] = {
        "status": "passed",
        "receipt_path": relative,
        "receipt_sha256": digest,
    }
    # The same check every reader applies, before anything is written.
    runtime_watch_smoke_sha256(root, updated, candidate, release=release, require_passed=True)
    payload = (json.dumps(updated, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    temporary = runtime_path.with_name(f".runtime_evidence.{secrets.token_hex(4)}.tmp")
    _write_private_file(temporary, payload)
    os.chmod(temporary, stat.S_IMODE(runtime_path.stat().st_mode))
    os.replace(temporary, runtime_path)
    _fsync_directory(runtime_path.parent)
    return digest


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="build, pair, observe and write the durable receipt")
    run.add_argument("--flutter", default="/Users/owner/.local/flutter-3.47.6/bin/flutter")
    run.add_argument(
        "--engine-source-root",
        help="a checkout holding the simulator engine inputs pinned by the committed provenance",
    )
    run.add_argument("--ios-runtime")
    run.add_argument("--watch-runtime")
    run.add_argument("--phone-device-type")
    run.add_argument("--watch-device-type")
    run.add_argument("--case-seconds", type=float, default=150.0)
    run.add_argument("--phone-settle-seconds", type=float, default=20.0)
    run.add_argument("--install-settle-seconds", type=float, default=15.0)
    run.add_argument("--keep-simulators", action="store_true")
    verify = sub.add_parser("verify", help="re-verify a receipt")
    verify.add_argument("receipt_path")
    verify.add_argument("receipt_sha256")
    verify.add_argument("--source-commit", required=True)
    rec = sub.add_parser("record", help="bind a verified receipt into runtime_evidence.json")
    rec.add_argument("receipt_path")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "run":
            return produce(args)
        if args.command == "verify":
            verify_receipt(
                ROOT,
                args.receipt_path,
                args.receipt_sha256,
                release=read_release(ROOT),
                source_commit=args.source_commit,
            )
            print("WATCH COMPANION SMOKE RECEIPT: PASS")
            return 0
        digest = record(ROOT, args.receipt_path)
        print(f"WATCH COMPANION SMOKE RECORDED: sha256={digest}")
        return 0
    except WatchSmokeError as exc:
        print(f"WATCH COMPANION SMOKE: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
