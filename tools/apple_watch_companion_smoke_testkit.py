"""Test fixtures for the Watch companion smoke receipt (R22 Y3 D2, part 2).

Builds receipts with the same shape the producer writes, so validator tests
exercise the real verification path against durable, owner-only files instead
of supplying a bare digest. Test support only; nothing here is a release input.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
from typing import Any

import apple_watch_companion_smoke as smoke


POSITIVE_NONCE = "1" * 32
NEGATIVE_NONCE = "2" * 32
NEGATIVE_NONCES = {
    smoke.NOT_RUNNING_CASES[0]: "2" * 32,
    smoke.NOT_RUNNING_CASES[1]: "3" * 32,
    smoke.NOT_INSTALLED_CASE: "4" * 32,
}


def observation(nonce: str, *, linked: bool, woken: bool = False) -> dict[str, Any]:
    """linked: a running phone app answered; woken: WatchConnectivity had to
    wake the phone app, whose bridge answers before Dart has published."""

    record: dict[str, Any] = {
        "contract": smoke.OBSERVATION_CONTRACT,
        "nonce": nonce,
        "complete": True,
        "started_at_utc": "2026-10-18T00:00:00.000Z",
        "written_at_utc": "2026-10-18T00:00:05.000Z",
        "elapsed_ms": 5000.0,
        "watch_bundle_id": smoke.SIMULATOR_WATCH_BUNDLE_ID,
        "companion_bundle_id": smoke.SIMULATOR_PHONE_BUNDLE_ID,
        "wc_supported": True,
        "activation_state": "activated",
        "activation_states_seen": ["notActivated", "activated"],
        "is_companion_app_installed": linked,
        "companion_app_installed_ever": linked,
        "is_reachable": linked,
        "reachable_ever": linked,
        "application_context": {"keys": [], "present": False},
        "probe": {"attempts": 1 if linked else 0, "errors": [], "reply_received": linked},
        "phone_link": {
            "observed": True,
            "link": "linked" if linked else "unreachable",
            "snapshot_updated_at_ms": 1792281600000.0 if linked else 0.0,
            "snapshot_status": "disconnected" if linked else "unknown",
        },
    }
    if linked or woken:
        status = "unknown" if woken else "disconnected"
        record.update(
            is_companion_app_installed=True,
            companion_app_installed_ever=True,
            is_reachable=True,
            reachable_ever=True,
        )
        record["probe"] = {
            "attempts": 1,
            "errors": [],
            "reply_received": True,
            "round_trip_ms": 41.0,
            "reply": {
                "keys": ["canConnect", "countries", "status", "updatedAt", "v"],
                "present": True,
                "protocol_version": smoke.WATCH_PROTOCOL_VERSION,
                "updated_at_ms": 1792281600000.0,
                "status": status,
            },
        }
        record["phone_link"].update(
            link="linked", snapshot_updated_at_ms=1792281600000.0, snapshot_status=status
        )
    return record


def negative_cases() -> list[dict[str, Any]]:
    cases = []
    for name in smoke.NEGATIVE_CASES:
        nonce = NEGATIVE_NONCES[name]
        if name == smoke.NOT_INSTALLED_CASE:
            case_observation: dict[str, Any] = {}
            extra = {"watch_launch_exit": 4, "watch_app_installed_after_phone_uninstall": False}
        else:
            case_observation = observation(nonce, linked=False, woken=True)
            extra = {"watch_launch_exit": 0}
        checks = smoke.evaluate_observation(case_observation, nonce)
        case = {"case": name, "expected": "FAIL", "nonce": nonce, **extra}
        held = (
            smoke.not_installed_control_held(case, checks)
            if name == smoke.NOT_INSTALLED_CASE
            else smoke.negative_control_held(checks)
        )
        case.update(
            observation=case_observation,
            checks=checks,
            observed_verdict=smoke.observation_verdict(checks),
            control_held=held,
        )
        cases.append(case)
    return cases


def receipt_document(
    *, release: str, source_commit: str, tree_clean: bool = True
) -> dict[str, Any]:
    version, _, build = release.partition("+")
    positive_observation = observation(POSITIVE_NONCE, linked=True)
    positive_checks = smoke.evaluate_observation(positive_observation, POSITIVE_NONCE)
    return {
        "schema_version": smoke.SCHEMA_VERSION,
        "contract": smoke.CONTRACT,
        "release": release,
        "app_version": version,
        "build_number": build,
        "statement": smoke.STATEMENT,
        "verdict": "PASS",
        "source": {
            "git_commit": source_commit,
            "tree_clean": tree_clean,
            "tracked_changes": [],
            "untracked_files": [],
        },
        "tool": {
            "path": smoke.TOOL_RELATIVE,
            "sha256": smoke.sha256_file(pathlib.Path(smoke.__file__).resolve()),
        },
        "host": {"xcode": "Xcode fixture"},
        "simulators": {
            "phone": {"udid": "FIXTURE-PHONE"},
            "watch": {"udid": "FIXTURE-WATCH"},
            "pair": "FIXTURE-PAIR",
            "pair_state": "(active, connected)",
        },
        "cleanup": [
            {"udid": "FIXTURE-WATCH", "shutdown_exit": 0, "delete_exit": 0},
            {"udid": "FIXTURE-PHONE", "shutdown_exit": 0, "delete_exit": 0},
        ],
        "artifacts": {
            "runner_app": {
                "bundle_id": smoke.SIMULATOR_PHONE_BUNDLE_ID,
                "platform": "iphonesimulator",
                "executable": "Runner",
                "executable_sha256": "c" * 64,
                "version": version,
                "build": build,
            },
            "watch_app": {
                "bundle_id": smoke.SIMULATOR_WATCH_BUNDLE_ID,
                "companion_bundle_id": smoke.SIMULATOR_PHONE_BUNDLE_ID,
                "executable": smoke.WATCH_EXECUTABLE,
                "executable_sha256": "d" * 64,
                "platform": "watchsimulator",
                "build_platforms": ["WATCHOSSIMULATOR"],
                "version": version,
                "build": build,
                "smoke_hook_present": True,
            },
        },
        "positive": {
            "nonce": POSITIVE_NONCE,
            "observation": positive_observation,
            "checks": positive_checks,
            "verdict": smoke.observation_verdict(positive_checks),
        },
        "negative_cases": negative_cases(),
    }


def write_receipt(
    root: pathlib.Path,
    document: dict[str, Any] | bytes,
    *,
    stamp: str = "20261018T000000Z",
) -> tuple[str, str]:
    """Write an owner-only receipt below root/.artifacts; return (path, sha256)."""

    current = root
    for part in (".artifacts", "apple-watch-companion-smoke", stamp):
        current = current / part
        current.mkdir(mode=0o700, exist_ok=True)
        os.chmod(current, 0o700)
    payload = (
        document
        if isinstance(document, bytes)
        else (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii")
    )
    path = current / smoke.RECEIPT_NAME
    if path.exists():
        path.unlink()
    path.write_bytes(payload)
    os.chmod(path, 0o600)
    return path.relative_to(root).as_posix(), hashlib.sha256(payload).hexdigest()
