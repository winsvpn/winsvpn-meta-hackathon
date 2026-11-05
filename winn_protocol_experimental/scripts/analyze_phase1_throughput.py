#!/usr/bin/env python3
"""Validate and summarize Winn Phase-1 paired throughput evidence.

This program intentionally uses only the Python standard library.  The shell
orchestrator archives child output; this analyzer turns that output into
strict, machine-readable pair records and a final fail-closed gate result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import sys
import tempfile
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Sequence


SCHEMA_PAIR = "winn-phase1-throughput-pair/v1"
SCHEMA_SCHEDULE = "winn-phase1-throughput-schedule/v1"
SCHEMA_SUMMARY = "winn-phase1-throughput-summary/v1"
SCHEMA_MANIFEST = "winn-phase1-throughput-manifest/v1"

ROLE_BASELINE = "baseline"
ROLE_WINN = "winn"
PATH_BASELINE = "raw-awg"
PATH_WINN = "production-directawg-candidate-v1"

METRIC_MARKERS = {
    ROLE_BASELINE: "BASELINE_THROUGHPUT_MBPS",
    ROLE_WINN: "WINN_THROUGHPUT_MBPS",
}


class EvidenceError(Exception):
    """Raised when evidence is incomplete, malformed, or contradictory."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_evidence(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise EvidenceError(f"required evidence file is missing: {path}")
    stat = path.stat()
    return {
        "path": str(path),
        "bytes": stat.st_size,
        "sha256": sha256_file(path),
    }


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_marker(path: Path, name: str) -> str:
    prefix = f"{name}="
    matches: list[str] = []
    with path.open("r", encoding="utf-8", errors="strict") as source:
        for raw_line in source:
            line = raw_line.rstrip("\r\n")
            if line.startswith(prefix):
                matches.append(line[len(prefix) :])
    if len(matches) != 1:
        raise EvidenceError(
            f"{path}: expected exactly one {name} marker, found {len(matches)}"
        )
    if not matches[0]:
        raise EvidenceError(f"{path}: {name} marker is empty")
    return matches[0]


def positive_decimal(value: str, label: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise EvidenceError(f"{label} is not numeric: {value!r}") from error
    if not parsed.is_finite() or parsed <= 0:
        raise EvidenceError(f"{label} must be finite and greater than zero")
    return parsed


def parse_gnu_time(path: Path) -> dict[str, Any]:
    evidence = file_evidence(path)
    cpu_percent: Decimal | None = None
    maximum_rss_kib: int | None = None
    elapsed = ""
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for raw_line in source:
            line = raw_line.strip()
            if line.startswith("Percent of CPU this job got:"):
                raw = line.split(":", 1)[1].strip().removesuffix("%")
                try:
                    cpu_percent = Decimal(raw)
                except InvalidOperation as error:
                    raise EvidenceError(
                        f"{path}: invalid GNU time CPU percentage"
                    ) from error
            elif line.startswith("Maximum resident set size (kbytes):"):
                raw = line.rsplit(":", 1)[1].strip()
                try:
                    maximum_rss_kib = int(raw)
                except ValueError as error:
                    raise EvidenceError(
                        f"{path}: invalid GNU time maximum RSS"
                    ) from error
            elif line.startswith("Elapsed (wall clock) time"):
                elapsed = line.rsplit(": ", 1)[-1]
    if cpu_percent is None or cpu_percent < 0:
        raise EvidenceError(f"{path}: GNU time CPU percentage is missing")
    if maximum_rss_kib is None or maximum_rss_kib < 1:
        raise EvidenceError(f"{path}: GNU time maximum RSS is missing")
    if not elapsed:
        raise EvidenceError(f"{path}: GNU time elapsed value is missing")
    return {
        **evidence,
        "cpu_percent": float(cpu_percent),
        "maximum_rss_kib": maximum_rss_kib,
        "elapsed": elapsed,
    }


def parse_iperf(path: Path) -> dict[str, Any]:
    evidence = file_evidence(path)
    try:
        with path.open("r", encoding="utf-8") as source:
            document = json.load(source)
        bits_per_second = Decimal(
            str(document["end"]["sum_sent"]["bits_per_second"])
        )
    except (KeyError, TypeError, ValueError, InvalidOperation, json.JSONDecodeError) as error:
        raise EvidenceError(
            f"{path}: missing valid end.sum_sent.bits_per_second"
        ) from error
    if not bits_per_second.is_finite() or bits_per_second <= 0:
        raise EvidenceError(f"{path}: iperf throughput must be positive and finite")
    return {
        **evidence,
        "bits_per_second": float(bits_per_second),
        "mbps": float(bits_per_second / Decimal(1_000_000)),
    }


def validate_raw_metric(
    raw: dict[str, Any],
    reported_mbps: Decimal,
    path: Path,
) -> None:
    raw_mbps = Decimal(str(raw["mbps"]))
    relative_error = abs(raw_mbps - reported_mbps) / raw_mbps
    if relative_error > Decimal("0.001"):
        raise EvidenceError(
            f"{path}: stdout metric differs from raw iperf JSON by more than 0.1%"
        )


def validate_child(
    role: str,
    stdout_path: Path,
    stderr_path: Path,
    time_path: Path,
    iperf_path: Path,
    gateway_endpoint: str,
    gateway_inner_ip: str,
    require_raw_json: bool,
) -> dict[str, Any]:
    stdout_evidence = file_evidence(stdout_path)
    stderr_evidence = file_evidence(stderr_path)
    expected_path = PATH_BASELINE if role == ROLE_BASELINE else PATH_WINN
    if read_marker(stdout_path, "THROUGHPUT_ROLE") != role:
        raise EvidenceError(f"{stdout_path}: child role does not match {role}")
    if read_marker(stdout_path, "THROUGHPUT_PATH") != expected_path:
        raise EvidenceError(
            f"{stdout_path}: child did not attest to {expected_path}"
        )
    if read_marker(stdout_path, "THROUGHPUT_GATEWAY_ENDPOINT") != gateway_endpoint:
        raise EvidenceError(f"{stdout_path}: gateway endpoint mismatch")
    if read_marker(stdout_path, "THROUGHPUT_GATEWAY_INNER_IP") != gateway_inner_ip:
        raise EvidenceError(f"{stdout_path}: gateway inner IP mismatch")
    metric_name = METRIC_MARKERS[role]
    reported_mbps = positive_decimal(
        read_marker(stdout_path, metric_name),
        f"{role} throughput",
    )
    raw: dict[str, Any] | None = None
    if iperf_path.is_file():
        raw = parse_iperf(iperf_path)
        expected_hash = read_marker(
            stdout_path,
            "THROUGHPUT_IPERF_JSON_SHA256",
        )
        if expected_hash != raw["sha256"]:
            raise EvidenceError(
                f"{stdout_path}: child-reported iperf JSON checksum mismatch"
            )
        validate_raw_metric(raw, reported_mbps, iperf_path)
    elif require_raw_json:
        raise EvidenceError(f"{role}: raw iperf JSON was required but not archived")
    return {
        "role": role,
        "path": expected_path,
        "throughput_mbps": float(reported_mbps),
        "stdout": stdout_evidence,
        "stderr": stderr_evidence,
        "resource_usage": parse_gnu_time(time_path),
        "iperf": raw,
    }


def command_pair(arguments: argparse.Namespace) -> int:
    if arguments.pair_index < 1:
        raise EvidenceError("pair index must be positive")
    baseline = validate_child(
        ROLE_BASELINE,
        Path(arguments.baseline_stdout),
        Path(arguments.baseline_stderr),
        Path(arguments.baseline_time),
        Path(arguments.baseline_iperf_json),
        arguments.gateway_endpoint,
        arguments.gateway_inner_ip,
        arguments.require_raw_json,
    )
    winn = validate_child(
        ROLE_WINN,
        Path(arguments.winn_stdout),
        Path(arguments.winn_stderr),
        Path(arguments.winn_time),
        Path(arguments.winn_iperf_json),
        arguments.gateway_endpoint,
        arguments.gateway_inner_ip,
        arguments.require_raw_json,
    )
    baseline_mbps = Decimal(str(baseline["throughput_mbps"]))
    winn_mbps = Decimal(str(winn["throughput_mbps"]))
    ratio = (winn_mbps / baseline_mbps) * Decimal(100)
    record = {
        "schema": SCHEMA_PAIR,
        "pair_index": arguments.pair_index,
        "order": arguments.order,
        "gateway": {
            "name": arguments.gateway_name,
            "endpoint": arguments.gateway_endpoint,
            "inner_ip": arguments.gateway_inner_ip,
        },
        "baseline": baseline,
        "winn": winn,
        "paired_ratio_percent": float(ratio),
        "raw_iperf_json_required": arguments.require_raw_json,
    }
    atomic_json(Path(arguments.output), record)
    print(
        f"PAIR index={arguments.pair_index} order={arguments.order} "
        f"baseline_mbps={baseline_mbps} winn_mbps={winn_mbps} "
        f"ratio_percent={ratio:.6f}"
    )
    return 0


def command_schedule(arguments: argparse.Namespace) -> int:
    if arguments.pairs < 10:
        raise EvidenceError("at least 10 pairs are required")
    first_count = arguments.pairs // 2
    orders = ["baseline-first"] * first_count
    orders.extend(["winn-first"] * (arguments.pairs - first_count))
    random.SystemRandom().shuffle(orders)
    schedule = {
        "schema": SCHEMA_SCHEDULE,
        "pairs": arguments.pairs,
        "randomization": "balanced-secrets-system-random",
        "orders": [
            {"pair_index": index, "order": order}
            for index, order in enumerate(orders, start=1)
        ],
    }
    atomic_json(Path(arguments.output), schedule)
    return 0


def load_schedule(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            schedule = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot load schedule {path}: {error}") from error
    if schedule.get("schema") != SCHEMA_SCHEDULE:
        raise EvidenceError(f"{path}: schedule schema is invalid")
    return schedule


def command_order(arguments: argparse.Namespace) -> int:
    schedule = load_schedule(Path(arguments.schedule))
    matches = [
        item["order"]
        for item in schedule.get("orders", [])
        if item.get("pair_index") == arguments.pair_index
    ]
    if len(matches) != 1 or matches[0] not in {"baseline-first", "winn-first"}:
        raise EvidenceError("schedule has no unique valid order for pair")
    print(matches[0])
    return 0


def nearest_rank(values: Sequence[Decimal], percentile: Decimal) -> Decimal:
    if not values:
        raise EvidenceError("cannot calculate a percentile of an empty sample")
    ordered = sorted(values)
    rank = max(1, math.ceil(float(percentile * len(ordered))))
    return ordered[rank - 1]


def command_summary(arguments: argparse.Namespace) -> int:
    if arguments.expected_pairs < 10:
        raise EvidenceError("at least 10 expected pairs are required")
    threshold = positive_decimal(arguments.gate_percent, "gate percentage")
    if threshold < Decimal(90):
        raise EvidenceError("Phase-1 throughput gate cannot be below 90%")
    root = Path(arguments.pairs_root)
    pair_paths = sorted(root.glob("pair-*/pair.json"))
    if len(pair_paths) != arguments.expected_pairs:
        raise EvidenceError(
            f"expected {arguments.expected_pairs} pair records, found {len(pair_paths)}"
        )
    records: list[dict[str, Any]] = []
    indices: list[int] = []
    ratios: list[Decimal] = []
    baseline_values: list[Decimal] = []
    winn_values: list[Decimal] = []
    gateway: dict[str, Any] | None = None
    for path in pair_paths:
        try:
            with path.open("r", encoding="utf-8") as source:
                record = json.load(source)
        except (OSError, json.JSONDecodeError) as error:
            raise EvidenceError(f"cannot load pair record {path}: {error}") from error
        if record.get("schema") != SCHEMA_PAIR:
            raise EvidenceError(f"{path}: pair schema is invalid")
        index = record.get("pair_index")
        if not isinstance(index, int):
            raise EvidenceError(f"{path}: pair index is invalid")
        indices.append(index)
        current_gateway = record.get("gateway")
        if gateway is None:
            gateway = current_gateway
        elif current_gateway != gateway:
            raise EvidenceError(f"{path}: pair used a different gateway")
        ratios.append(
            positive_decimal(
                str(record.get("paired_ratio_percent")),
                f"{path} ratio",
            )
        )
        baseline_values.append(
            positive_decimal(
                str(record["baseline"]["throughput_mbps"]),
                f"{path} baseline throughput",
            )
        )
        winn_values.append(
            positive_decimal(
                str(record["winn"]["throughput_mbps"]),
                f"{path} Winn throughput",
            )
        )
        records.append(record)
    expected_indices = list(range(1, arguments.expected_pairs + 1))
    if sorted(indices) != expected_indices:
        raise EvidenceError("pair indices are not contiguous and unique")
    failed_pairs = [
        record["pair_index"]
        for record, ratio in zip(records, ratios)
        if ratio < threshold
    ]
    gate_passed = not failed_pairs
    summary = {
        "schema": SCHEMA_SUMMARY,
        "expected_pairs": arguments.expected_pairs,
        "observed_pairs": len(records),
        "gateway": gateway,
        "gate": {
            "threshold_percent": float(threshold),
            "rule": (
                "every back-to-back paired Winn/raw-AWG throughput ratio "
                "must be greater than or equal to the threshold"
            ),
            "passed": gate_passed,
            "failed_pair_indices": failed_pairs,
        },
        "paired_ratio_percent": {
            "minimum": float(min(ratios)),
            "p50_nearest_rank": float(nearest_rank(ratios, Decimal("0.50"))),
            "p95_nearest_rank": float(nearest_rank(ratios, Decimal("0.95"))),
            "maximum": float(max(ratios)),
            "mean": float(sum(ratios) / Decimal(len(ratios))),
        },
        "baseline_mbps": {
            "minimum": float(min(baseline_values)),
            "p50_nearest_rank": float(
                nearest_rank(baseline_values, Decimal("0.50"))
            ),
            "maximum": float(max(baseline_values)),
            "mean": float(sum(baseline_values) / Decimal(len(baseline_values))),
        },
        "winn_mbps": {
            "minimum": float(min(winn_values)),
            "p50_nearest_rank": float(
                nearest_rank(winn_values, Decimal("0.50"))
            ),
            "maximum": float(max(winn_values)),
            "mean": float(sum(winn_values) / Decimal(len(winn_values))),
        },
    }
    atomic_json(Path(arguments.output), summary)
    print(
        f"THROUGHPUT_GATE passed={str(gate_passed).lower()} "
        f"pairs={len(records)} threshold_percent={threshold} "
        f"minimum_ratio_percent={min(ratios):.6f} "
        f"p50_ratio_percent={nearest_rank(ratios, Decimal('0.50')):.6f}"
    )
    return 0 if gate_passed else 1


def command_manifest(arguments: argparse.Namespace) -> int:
    if arguments.expected_pairs < 10:
        raise EvidenceError("at least 10 expected pairs are required")
    threshold = positive_decimal(arguments.gate_percent, "gate percentage")
    if threshold < Decimal(90):
        raise EvidenceError("Phase-1 throughput gate cannot be below 90%")
    files: dict[str, Any] = {}
    for specification in arguments.file:
        if "=" not in specification:
            raise EvidenceError("--file must use label=/absolute/path")
        label, raw_path = specification.split("=", 1)
        if not label or label in files:
            raise EvidenceError(f"manifest file label is empty or duplicated: {label}")
        path = Path(raw_path)
        if not path.is_absolute():
            raise EvidenceError(f"manifest file must be absolute: {path}")
        files[label] = file_evidence(path)
    manifest = {
        "schema": SCHEMA_MANIFEST,
        "run_id": arguments.run_id,
        "created_at": arguments.created_at,
        "expected_pairs": arguments.expected_pairs,
        "gate": {
            "threshold_percent": float(threshold),
            "rule": (
                "every back-to-back paired Winn/raw-AWG throughput ratio "
                "must be greater than or equal to the threshold"
            ),
        },
        "gateway": {
            "name": arguments.gateway_name,
            "endpoint": arguments.gateway_endpoint,
            "inner_ip": arguments.gateway_inner_ip,
        },
        "raw_iperf_json_required": arguments.require_raw_json,
        "files": files,
    }
    atomic_json(Path(arguments.output), manifest)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    schedule = subparsers.add_parser("schedule")
    schedule.add_argument("--pairs", type=int, required=True)
    schedule.add_argument("--output", required=True)
    schedule.set_defaults(handler=command_schedule)

    order = subparsers.add_parser("order")
    order.add_argument("--schedule", required=True)
    order.add_argument("--pair-index", type=int, required=True)
    order.set_defaults(handler=command_order)

    pair = subparsers.add_parser("pair")
    pair.add_argument("--pair-index", type=int, required=True)
    pair.add_argument(
        "--order",
        choices=("baseline-first", "winn-first"),
        required=True,
    )
    pair.add_argument("--baseline-stdout", required=True)
    pair.add_argument("--baseline-stderr", required=True)
    pair.add_argument("--baseline-time", required=True)
    pair.add_argument("--baseline-iperf-json", required=True)
    pair.add_argument("--winn-stdout", required=True)
    pair.add_argument("--winn-stderr", required=True)
    pair.add_argument("--winn-time", required=True)
    pair.add_argument("--winn-iperf-json", required=True)
    pair.add_argument("--gateway-name", required=True)
    pair.add_argument("--gateway-endpoint", required=True)
    pair.add_argument("--gateway-inner-ip", required=True)
    pair.add_argument("--require-raw-json", action="store_true")
    pair.add_argument("--output", required=True)
    pair.set_defaults(handler=command_pair)

    summary = subparsers.add_parser("summary")
    summary.add_argument("--pairs-root", required=True)
    summary.add_argument("--expected-pairs", type=int, required=True)
    summary.add_argument("--gate-percent", required=True)
    summary.add_argument("--output", required=True)
    summary.set_defaults(handler=command_summary)

    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--run-id", required=True)
    manifest.add_argument("--created-at", required=True)
    manifest.add_argument("--expected-pairs", type=int, required=True)
    manifest.add_argument("--gate-percent", required=True)
    manifest.add_argument("--gateway-name", required=True)
    manifest.add_argument("--gateway-endpoint", required=True)
    manifest.add_argument("--gateway-inner-ip", required=True)
    manifest.add_argument("--require-raw-json", action="store_true")
    manifest.add_argument("--file", action="append", default=[])
    manifest.add_argument("--output", required=True)
    manifest.set_defaults(handler=command_manifest)
    return parser


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()
    try:
        return int(arguments.handler(arguments))
    except EvidenceError as error:
        print(f"EVIDENCE_ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
