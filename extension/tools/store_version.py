from pathlib import Path
import re


def read_pubspec_manifest_version(pubspec: Path) -> str:
    versions = []
    for line in pubspec.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("version:"):
            value = stripped.split(":", 1)[1].split("#", 1)[0].strip()
            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in {"'", '"'}
            ):
                value = value[1:-1]
            versions.append(value)

    if len(versions) != 1:
        raise ValueError("pubspec.yaml must contain exactly one version")

    raw = versions[0]
    core = raw.split("+", 1)[0]
    if "-" in core:
        raise ValueError("prerelease pubspec versions cannot produce store packages")

    match = re.fullmatch(
        r"(0|[1-9][0-9]{0,4})"
        r"\.(0|[1-9][0-9]{0,4})"
        r"\.(0|[1-9][0-9]{0,4})"
        r"(?:\+[0-9]+)?",
        raw,
    )
    if match is None or any(int(part) > 65535 for part in match.groups()):
        raise ValueError("pubspec version is not an accepted store version")

    return ".".join(match.groups())
