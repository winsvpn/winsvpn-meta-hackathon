#!/usr/bin/env python3
"""Stage the exact control-plane threat-triage files for a bounded repair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from validate_deployment_scripts import parse_heredocs


EXPECTED_MODEL = 'MODEL_VERSION = "wins-triage-v3-local-health-context"'
TARGETS = {
    "cat > /usr/local/lib/wins_threat_triage.py <<'PYEOF'": (
        "wins_threat_triage.py",
        0o600,
    ),
    "cat > /usr/local/bin/wins-threat-triage <<'PYEOF'": (
        "wins-threat-triage",
        0o700,
    ),
    "cat > /etc/systemd/system/wins-threat-triage-report.service <<'EOF'": (
        "wins-threat-triage-report.service",
        0o644,
    ),
    "cat > /etc/systemd/system/wins-threat-triage-report.timer <<'EOF'": (
        "wins-threat-triage-report.timer",
        0o644,
    ),
}


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(source: pathlib.Path, output: pathlib.Path) -> dict[str, object]:
    source = source.resolve(strict=True)
    if not source.is_file() or source.is_symlink():
        raise ValueError("Control-plane source must be a regular non-symlink file.")
    if output.exists():
        if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
            raise ValueError("Staging output must be absent or an empty non-symlink directory.")
    else:
        output.mkdir(parents=True, mode=0o700)
    output = output.resolve(strict=True)

    selected: dict[str, str] = {}
    for block in parse_heredocs(source):
        header = block.header.strip()
        if header in TARGETS:
            if header in selected:
                raise ValueError(f"Duplicate triage heredoc: {header}")
            selected[header] = block.body
    if set(selected) != set(TARGETS):
        missing = sorted(set(TARGETS) - set(selected))
        raise ValueError(f"Missing exact triage heredocs: {missing}")
    if EXPECTED_MODEL not in selected[
        "cat > /usr/local/lib/wins_threat_triage.py <<'PYEOF'"
    ]:
        raise ValueError("Current source does not contain the expected v3 triage model.")

    entries: list[dict[str, object]] = []
    for header, (name, mode) in TARGETS.items():
        body = selected[header]
        if "\x00" in body or not body.endswith("\n"):
            raise ValueError(f"Triage heredoc is not canonical UTF-8 text: {name}")
        path = output / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        os.chmod(path, mode)
        entries.append(
            {
                "name": name,
                "sha256": sha256(path),
                "size_bytes": path.stat().st_size,
                "mode": f"{mode:04o}",
            }
        )

    manifest = {
        "schema_version": 1,
        "contract": "winsvpn-control-triage-staging-v1",
        "source_sha256": sha256(source),
        "model_version": "wins-triage-v3-local-health-context",
        "files": entries,
        "secret_material_present": False,
        "publication_authorized": False,
    }
    manifest_path = output / "manifest.json"
    descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {**manifest, "manifest_sha256": sha256(manifest_path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = stage(pathlib.Path(args.source), pathlib.Path(args.output))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
