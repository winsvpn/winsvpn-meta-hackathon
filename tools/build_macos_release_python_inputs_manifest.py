#!/usr/bin/env python3
"""Build or check the fixed ReleasePython input-custody manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


CONTRACT = "winsvpn-release-python-input-custody-v1"
DESTINATION_ROOT = Path("/Library/WinsVPN/ReleasePythonInputs/sha256")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "tools" / "toolchain-pins.json"
OUTPUT = ROOT / "tools" / "macos_release_python_inputs.custody.json"


def canonical(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact(kind: str, record: object, mode: str) -> dict[str, str]:
    if type(record) is not dict or set(record) != {"path", "sha256"}:
        raise ValueError(f"{kind} pin keys are not exact")
    path = Path(record["path"])
    sha256 = record["sha256"]
    if (
        not path.is_absolute()
        or path.name in {"", ".", ".."}
        or type(sha256) is not str
        or HEX64.fullmatch(sha256) is None
        or path != DESTINATION_ROOT / sha256 / path.name
    ):
        raise ValueError(f"{kind} pin is outside fixed content-addressed custody")
    return {
        "kind": kind,
        "leaf": path.name,
        "mode": mode,
        "path": str(path),
        "sha256": sha256,
    }


def build(pin_data: bytes) -> dict[str, object]:
    try:
        pins = json.loads(pin_data.decode("ascii"))
        custody = pins["tools"]["python"]["archive_custody"]["darwin_arm64"]
        runtime_count = custody["runtime_wheel_count"]
        count = custody["wheel_count"]
        wheels = custody["wheels"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"ReleasePython pin manifest is invalid: {exc}") from exc
    if type(runtime_count) is not int or runtime_count != 25:
        raise ValueError("ReleasePython custody requires exactly 25 runtime wheels")
    if type(count) is not int or count != 28:
        raise ValueError("ReleasePython custody requires exactly 28 total wheels")
    if type(wheels) is not dict or set(wheels) != {str(i) for i in range(count)}:
        raise ValueError("ReleasePython wheel pin keys are not exact")
    wheel_artifacts = [
        artifact("wheel", wheels[str(index)], "0444") for index in range(count)
    ]
    expected_x86 = (
        "pillow-12.3.0-cp314-cp314-macosx_10_15_x86_64.whl",
        "pydantic_core-2.46.4-cp314-cp314-macosx_10_12_x86_64.whl",
        "pyyaml-6.0.3-cp314-cp314-macosx_10_13_x86_64.whl",
    )
    if (
        any(item["leaf"].endswith("_x86_64.whl") for item in wheel_artifacts[:runtime_count])
        or tuple(item["leaf"] for item in wheel_artifacts[runtime_count:]) != expected_x86
    ):
        raise ValueError("ReleasePython runtime and producer-only wheel partitions are not exact")
    artifacts = [
        artifact("package", custody.get("package"), "0444"),
        artifact("sigstore-bundle", custody.get("sigstore_bundle"), "0444"),
        artifact("source-archive", custody.get("source_archive"), "0444"),
        artifact("source-sigstore-bundle", custody.get("source_sigstore_bundle"), "0444"),
        artifact("sigstore-trusted-root", custody.get("sigstore_trusted_root"), "0444"),
        artifact("sigstore-verifier", custody.get("sigstore_verifier"), "0555"),
    ]
    artifacts.extend(wheel_artifacts)
    if len({item["path"] for item in artifacts}) != len(artifacts):
        raise ValueError("ReleasePython custody destinations are not unique")
    return {
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "contract": CONTRACT,
        "destination_root": str(DESTINATION_ROOT),
        "pin_manifest_sha256": digest(pin_data),
        "schema_version": 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    pin_data = PINS.read_bytes()
    generated = canonical(build(pin_data))
    if args.check:
        try:
            current = OUTPUT.read_bytes()
        except OSError as exc:
            print(f"ReleasePython input manifest is unavailable: {exc}", file=sys.stderr)
            return 1
        if current != generated:
            print("ReleasePython input manifest is stale", file=sys.stderr)
            return 1
        print(f"ReleasePython input manifest: PASS ({digest(current)})")
        return 0
    OUTPUT.write_bytes(generated)
    print(f"wrote {OUTPUT} ({digest(generated)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
