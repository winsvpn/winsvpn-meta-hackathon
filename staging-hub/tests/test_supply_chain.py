"""Offline staging-hub supply-chain contracts.

Staging only. These checks do not prove release readiness. They freeze the
staging image inputs: immutable base digest, architecture list, hashed
Python closure, single pip index, and a Debian snapshot apt input.

No image build and no network.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

HUB_DIR = Path(__file__).resolve().parent.parent
DOCKERFILE = HUB_DIR / "Dockerfile"
REQUIREMENTS = HUB_DIR / "requirements.txt"
LOCK = HUB_DIR / "requirements.lock"
PIN = HUB_DIR / "base-image.pin"

REVIEWED_IMAGE = (
    "python:3.14.7-slim-trixie@"
    "sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
)
REVIEWED_SNAPSHOT = "20260823T000000Z"
REQUIRED_ARCHES = ("linux/amd64", "linux/arm64")
RUNTIME_PINS = (
    "fastapi==0.142.2",
    "uvicorn==0.54.0",
    "httpx==0.28.1",
)
PIN_RE = re.compile(r"^[A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,\-]+\])?==[A-Za-z0-9_.\-]+$")
REQ_BLOCK_RE = re.compile(r"^[A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,\-]+\])?==[A-Za-z0-9_.\-]+")
HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}\b")
DIGEST_RE = re.compile(r"^python:3\.14\.7-slim-trixie@sha256:[0-9a-f]{64}$")
SNAPSHOT_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
MUTABLE_FROM = (
    "python:latest",
    "python:3",
    "python:3.12",
    "python:3.12-slim",
    "python:3.13-slim",
    "python:3.14-slim",
    "python:3.14.7-slim-trixie",
    "python:3.15-slim",
    "debian:trixie-slim",
    "ubuntu:24.04",
    "ubuntu:latest",
)
FLOATING_APT_MIRRORS = (
    "deb.debian.org",
    "security.debian.org",
    "ftp.debian.org",
    "httpredir.debian.org",
    "cdn-aws.deb.debian.org",
)
BANNED_PIP_STEPS = (
    "pip install --upgrade pip",
    "pip install --upgrade wheel",
    "pip install -U pip",
    "pip install -U wheel",
    "pip install -r requirements.txt",
)
SECRET_PATTERNS = (
    "DEMO_KEY=",
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "AKIA",
    "ghp_",
    "github_pat_",
)
INDEX_URL_RE = re.compile(
    r"(?:--extra-index-url|--index-url|-i|--find-links)\s+(\S+)",
    re.IGNORECASE,
)
ENV_INDEX_RE = re.compile(
    r"PIP_(?:EXTRA_INDEX_URL|FIND_LINKS|INDEX_URL)=([^\s\\]+)",
)
STAGING_MARKERS = (
    "staging only",
    "not release evidence",
)


def _strip_comments(text: str) -> list[str]:
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def _load_pin(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def _requirement_blocks(lock_text: str) -> list[str]:
    lines = lock_text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        if not REQ_BLOCK_RE.match(lines[index]):
            index += 1
            continue
        block = [lines[index]]
        index += 1
        while index < len(lines) and lines[index][:1] in (" ", "\t"):
            block.append(lines[index])
            if not lines[index].rstrip().endswith("\\"):
                index += 1
                break
            index += 1
        blocks.append("\n".join(block))
    return blocks


def _ascii_only(text: str, label: str) -> list[str]:
    bad = [f"{label} contains non-ascii" for ch in text if ord(ch) > 127]
    return bad[:1]


def _lower(text: str) -> str:
    return text.lower()


def _normalized(text: str) -> str:
    collapsed = re.sub(r"[#\-]+", " ", _lower(text))
    return re.sub(r"\s+", " ", collapsed)


def _has_staging_disclaimer(text: str) -> bool:
    collapsed = _normalized(text)
    return all(marker in collapsed for marker in STAGING_MARKERS)


def _empty_env_value(value: str) -> bool:
    return value in ("", '""', "''")


def audit_dockerfile(dockerfile: str, pin: dict[str, str]) -> list[str]:
    problems: list[str] = []
    problems.extend(_ascii_only(dockerfile, "Dockerfile"))
    if not _has_staging_disclaimer(dockerfile):
        problems.append("Dockerfile must declare staging only and not release evidence")
    from_lines = [
        line for line in dockerfile.splitlines() if line.startswith("FROM ")
    ]
    expected_from = f"FROM {pin.get('image', '')}"
    if from_lines != [expected_from]:
        problems.append(f"FROM must be exactly {expected_from!r}, got {from_lines!r}")
    from_args = [line[5:].strip() for line in from_lines]
    for from_arg in from_args:
        if "@sha256:" not in from_arg or not re.search(
            r"@sha256:[0-9a-f]{64}$", from_arg
        ):
            problems.append(f"mutable base tag is forbidden: {from_arg}")
        for tag in MUTABLE_FROM:
            if from_arg == tag:
                problems.append(f"mutable base tag is forbidden: {tag}")
    if any("python:3.12-slim" == arg for arg in from_args):
        problems.append("floating python tag is forbidden")
    if any(arg.endswith(":latest") or arg == "python:latest" for arg in from_args):
        problems.append("latest tag is forbidden")
    install = (
        "pip install --no-cache-dir --require-hashes --only-binary=:all:"
    )
    collapsed = " ".join(dockerfile.split())
    if install not in collapsed:
        problems.append("Dockerfile must install the hashed binary-only lock")
    if "--index-url https://pypi.org/simple" not in collapsed:
        problems.append("pip install must use --index-url https://pypi.org/simple")
    if "-r requirements.lock" not in collapsed:
        problems.append("pip install must consume requirements.lock")
    lowered = _lower(dockerfile)
    for banned in BANNED_PIP_STEPS:
        if banned in dockerfile:
            problems.append(f"banned pip step: {banned}")
    if "PIP_CONFIG_FILE=/dev/null" not in dockerfile:
        problems.append("PIP_CONFIG_FILE=/dev/null is required to ignore ambient pip.conf")
    if "PIP_INDEX_URL=https://pypi.org/simple" not in dockerfile:
        problems.append("PIP_INDEX_URL must be https://pypi.org/simple")
    extra = ENV_INDEX_RE.findall(dockerfile)
    for match in INDEX_URL_RE.findall(dockerfile):
        extra.append(match)
    for value in extra:
        if value.startswith("PIP_"):
            continue
        if _empty_env_value(value):
            continue
        if value.rstrip('"').rstrip("'") == "https://pypi.org/simple":
            continue
        problems.append(f"extra or non-pypi index is forbidden: {value}")
    if re.search(r"PIP_EXTRA_INDEX_URL=\s*https?://", dockerfile):
        problems.append("PIP_EXTRA_INDEX_URL must not set a URL")
    if re.search(r"PIP_FIND_LINKS=\s*\S+", dockerfile) and 'PIP_FIND_LINKS=""' not in dockerfile:
        if "PIP_FIND_LINKS=" in dockerfile and 'PIP_FIND_LINKS=""' not in dockerfile:
            problems.append("PIP_FIND_LINKS must be empty")
    if "--extra-index-url" in lowered or "extra-index-url" in lowered:
        problems.append("extra-index-url is forbidden")
    if "--trusted-host" in lowered:
        problems.append("--trusted-host is forbidden")
    snapshot = pin.get("debian_snapshot", "")
    if f"DEBIAN_SNAPSHOT={snapshot}" not in dockerfile:
        problems.append("Dockerfile DEBIAN_SNAPSHOT must match the pin")
    if "snapshot.debian.org/archive/debian/" not in dockerfile:
        problems.append("apt sources must use snapshot.debian.org")
    if "snapshot.debian.org/archive/debian-security/" not in dockerfile:
        problems.append("apt security sources must use snapshot.debian.org")
    if "${DEBIAN_SNAPSHOT}" not in dockerfile:
        problems.append("apt snapshot URL must interpolate DEBIAN_SNAPSHOT")
    for mirror in FLOATING_APT_MIRRORS:
        if mirror in dockerfile:
            problems.append(f"floating apt mirror is forbidden: {mirror}")
    if "apt-get upgrade" in dockerfile or "apt-get dist-upgrade" in dockerfile:
        problems.append("apt upgrade/dist-upgrade is forbidden")
    if "apt-get" in dockerfile:
        if "--no-upgrade" not in dockerfile:
            problems.append("apt-get install must pass --no-upgrade")
        if "rm -f /etc/apt/sources.list.d/" not in dockerfile:
            problems.append("default apt sources.list.d inputs must be removed")
        if "check-valid-until=no" not in dockerfile:
            problems.append("snapshot apt sources must disable valid-until")
        if re.search(r"apt-get install[^\n]*openssl[^\n]*$", dockerfile) is None:
            if "openssl" not in dockerfile.split("apt-get", 1)[-1]:
                problems.append("snapshot apt install must pin openssl as the apt input")
    return problems


def audit_requirements(req_text: str, lock_text: str) -> list[str]:
    problems: list[str] = []
    problems.extend(_ascii_only(req_text, "requirements.txt"))
    problems.extend(_ascii_only(lock_text, "requirements.lock"))
    if not _has_staging_disclaimer(req_text):
        problems.append("requirements.txt must declare staging only and not release evidence")
    if not _has_staging_disclaimer(lock_text):
        problems.append("requirements.lock must declare staging only and not release evidence")
    pins = _strip_comments(req_text)
    if pins != list(RUNTIME_PINS):
        problems.append(f"requirements.txt pins must be {RUNTIME_PINS}, got {pins}")
    for pin in pins:
        if not PIN_RE.match(pin):
            problems.append(f"unpinned or ranged requirement: {pin}")
    lowered_req = _lower(req_text)
    lowered_lock = _lower(lock_text)
    for banned in ("git+", "github.com", "paramiko", "pytest", "--extra-index-url", "extra-index-url"):
        if banned in lowered_req:
            problems.append(f"requirements.txt contains forbidden token: {banned}")
        if banned == "pytest" and f"{banned}==" in lowered_lock:
            problems.append("pytest must not enter the image lock")
        elif banned == "paramiko" and f"{banned}==" in lowered_lock:
            problems.append("paramiko must not enter the image lock")
        elif banned not in ("pytest", "paramiko") and banned in lowered_lock:
            problems.append(f"requirements.lock contains forbidden token: {banned}")
    if "--only-binary :all:" not in lock_text:
        problems.append("lock must set --only-binary :all:")
    blocks = _requirement_blocks(lock_text)
    if len(blocks) < len(RUNTIME_PINS):
        problems.append("lock is missing runtime packages")
    for pin in RUNTIME_PINS:
        if not any(block.startswith(pin) for block in blocks):
            problems.append(f"lock missing hashed pin {pin}")
    for block in blocks:
        if not HASH_RE.search(block):
            problems.append(f"unhashed requirement: {block.splitlines()[0]}")
    hashes = re.findall(r"--hash=([a-z0-9]+):([0-9a-fA-F]+)", lock_text)
    if not hashes:
        problems.append("lock has no hashes")
    for algo, digest in hashes:
        if algo != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", digest):
            problems.append(f"invalid hash {algo}:{digest}")
    core = next((block for block in blocks if block.startswith("pydantic-core==")), "")
    if len(HASH_RE.findall(core)) < 100:
        problems.append("pydantic-core must retain architecture-aware wheel hashes")
    return problems


def audit_pin(pin_text: str) -> list[str]:
    problems: list[str] = []
    problems.extend(_ascii_only(pin_text, "base-image.pin"))
    if not _has_staging_disclaimer(pin_text):
        problems.append("base-image.pin must declare staging only and not release evidence")
    pin = _load_pin(pin_text)
    if pin.get("scope") != "staging":
        problems.append("pin scope must be staging")
    if pin.get("release_evidence") != "false":
        problems.append("pin must set release_evidence=false")
    image = pin.get("image", "")
    if not DIGEST_RE.fullmatch(image) or image != REVIEWED_IMAGE:
        problems.append(f"pin image must be the reviewed digest, got {image!r}")
    if pin.get("digest_kind") != "oci_image_index":
        problems.append("digest_kind must be oci_image_index")
    arches = tuple(a.strip() for a in pin.get("architectures", "").split(",") if a.strip())
    if set(arches) != set(REQUIRED_ARCHES) or len(arches) != 2:
        problems.append("pin must list linux/amd64 and linux/arm64")
    snapshot = pin.get("debian_snapshot", "")
    if not SNAPSHOT_RE.fullmatch(snapshot) or snapshot != REVIEWED_SNAPSHOT:
        problems.append(f"debian_snapshot must be the frozen timestamp {REVIEWED_SNAPSHOT}")
    if pin.get("debian_suite") != "trixie":
        problems.append("debian_suite must be trixie")
    if pin.get("apt_package") != "openssl":
        problems.append("apt_package must be openssl")
    if "3.15" in image or "rc" in image.lower() or "beta" in image.lower():
        problems.append("base image must be stable, not rc/beta/3.15")
    return problems


def audit_files(
    dockerfile: str,
    req_text: str,
    lock_text: str,
    pin_text: str,
) -> list[str]:
    pin = _load_pin(pin_text)
    problems = []
    problems.extend(audit_pin(pin_text))
    problems.extend(audit_dockerfile(dockerfile, pin))
    problems.extend(audit_requirements(req_text, lock_text))
    for pattern in SECRET_PATTERNS:
        for label, text in (
            ("Dockerfile", dockerfile),
            ("requirements.txt", req_text),
            ("requirements.lock", lock_text),
            ("base-image.pin", pin_text),
        ):
            if pattern in text:
                problems.append(f"{label} contains secret pattern {pattern}")
    return problems


def test_staging_hub_supply_chain_files_are_frozen():
    problems = audit_files(
        DOCKERFILE.read_text(encoding="utf-8"),
        REQUIREMENTS.read_text(encoding="utf-8"),
        LOCK.read_text(encoding="utf-8"),
        PIN.read_text(encoding="utf-8"),
    )
    assert problems == [], problems


def test_does_not_claim_release_readiness():
    for path in (DOCKERFILE, REQUIREMENTS, LOCK, PIN):
        text = _normalized(path.read_text(encoding="utf-8"))
        assert "staging" in text
        assert "not release evidence" in text
        assert "release ready" not in text
        assert "proves release" not in text


@pytest.mark.parametrize("tag", MUTABLE_FROM)
def test_rejects_mutable_base_tags(tag: str):
    pin_text = PIN.read_text(encoding="utf-8")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8").replace(
        f"FROM {REVIEWED_IMAGE}", f"FROM {tag}", 1
    )
    problems = audit_files(
        dockerfile,
        REQUIREMENTS.read_text(encoding="utf-8"),
        LOCK.read_text(encoding="utf-8"),
        pin_text,
    )
    joined = " ".join(problems).lower()
    assert problems
    assert "from" in joined or "mutable" in joined or "floating" in joined or "latest" in joined


def test_rejects_unhashed_requirements_and_lock_drift():
    req = REQUIREMENTS.read_text(encoding="utf-8").replace("fastapi==0.142.2", "fastapi", 1)
    lock = LOCK.read_text(encoding="utf-8").replace(
        "httpx==0.28.1 \\\n    --hash=sha256:d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad",
        "httpx==0.28.1",
        1,
    )
    problems = audit_files(
        DOCKERFILE.read_text(encoding="utf-8"),
        req,
        lock,
        PIN.read_text(encoding="utf-8"),
    )
    joined = " ".join(problems).lower()
    assert "unpinned" in joined or "pins must be" in joined
    assert "unhashed" in joined


def test_rejects_pip_install_of_unhashed_requirements_txt():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8").replace(
        "requirements.lock", "requirements.txt"
    )
    problems = audit_files(
        dockerfile,
        REQUIREMENTS.read_text(encoding="utf-8"),
        LOCK.read_text(encoding="utf-8"),
        PIN.read_text(encoding="utf-8"),
    )
    joined = " ".join(problems).lower()
    assert problems
    assert (
        "requirements.lock" in joined
        or "hashed" in joined
        or "banned pip step" in joined
    )


def test_rejects_extra_indexes():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8").replace(
        'PIP_EXTRA_INDEX_URL=""',
        "PIP_EXTRA_INDEX_URL=https://evil.example/simple",
        1,
    )
    dockerfile = dockerfile.replace(
        "--index-url https://pypi.org/simple",
        "--index-url https://pypi.org/simple --extra-index-url https://evil.example/simple",
        1,
    )
    req = REQUIREMENTS.read_text(encoding="utf-8") + "\n--extra-index-url https://evil.example/simple\n"
    problems = audit_files(
        dockerfile,
        req,
        LOCK.read_text(encoding="utf-8"),
        PIN.read_text(encoding="utf-8"),
    )
    joined = " ".join(problems).lower()
    assert "extra" in joined
    assert problems


def test_rejects_apt_latest_drift():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    dockerfile = dockerfile.replace("snapshot.debian.org/archive/debian/", "deb.debian.org/debian/")
    dockerfile = dockerfile.replace("snapshot.debian.org/archive/debian-security/", "security.debian.org/")
    dockerfile = dockerfile.replace("--no-upgrade", "")
    dockerfile = dockerfile.replace(
        "rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list",
        "true",
    )
    problems = audit_files(
        dockerfile,
        REQUIREMENTS.read_text(encoding="utf-8"),
        LOCK.read_text(encoding="utf-8"),
        PIN.read_text(encoding="utf-8"),
    )
    joined = " ".join(problems).lower()
    assert "snapshot.debian.org" in joined or "floating apt mirror" in joined
    assert "--no-upgrade" in joined or "sources.list.d" in joined
    assert problems


def test_rejects_unpinned_apt_openssl_without_snapshot():
    dockerfile = """FROM python:3.14.7-slim-trixie@sha256:%s
ENV PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL=https://pypi.org/simple PIP_EXTRA_INDEX_URL="" PIP_FIND_LINKS=""
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: --index-url https://pypi.org/simple --no-input -r requirements.lock
RUN apt-get update && apt-get install -y --no-install-recommends openssl
""" % ("a" * 64)
    pin_text = PIN.read_text(encoding="utf-8")
    problems = audit_dockerfile(dockerfile, _load_pin(pin_text))
    joined = " ".join(problems).lower()
    assert problems
    assert "snapshot" in joined or "debian_snapshot" in joined or "floating" in joined


def _build_minimal_wheel(directory: Path) -> Path:
    name, version = "winsvpnstaginghubtestpkg", "0.0.1"
    wheel_path = directory / f"{name}-{version}-py3-none-any.whl"
    dist_info = f"{name}-{version}.dist-info"
    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{name}/__init__.py", "VALUE = 1\n")
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: winsvpn-staging-hub-test\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/RECORD", "")
    return wheel_path


def _pip_install(tmp_path: Path, wheel_dir: Path, req_hash: str) -> subprocess.CompletedProcess:
    req_file = tmp_path / f"req-{req_hash[:8]}.txt"
    req_file.write_text(
        f"winsvpnstaginghubtestpkg==0.0.1 \\\n    --hash=sha256:{req_hash}\n",
        encoding="utf-8",
    )
    install_dir = tmp_path / f"install_{req_hash[:8]}"
    install_dir.mkdir(exist_ok=True)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-index",
            f"--find-links={wheel_dir}",
            f"--target={install_dir}",
            "-r",
            str(req_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_require_hashes_accepts_correct_hash_and_rejects_tamper(tmp_path: Path):
    wheel_dir = tmp_path / "wheelhouse"
    wheel_dir.mkdir()
    wheel_path = _build_minimal_wheel(wheel_dir)
    real_hash = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    ok = _pip_install(tmp_path, wheel_dir, real_hash)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    wrong = _pip_install(tmp_path, wheel_dir, "0" * 64)
    assert wrong.returncode != 0
    assert "DO NOT MATCH THE HASHES" in wrong.stderr.upper()
