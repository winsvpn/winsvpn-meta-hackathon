"""Offline contracts for the Smart Router image and hashed Python closure."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROUTER_DIR = Path(__file__).resolve().parent.parent
REPOSITORY_ROOT = ROUTER_DIR.parent
RETIRED_DEPLOY_ROOT = REPOSITORY_ROOT / "deploy" / "edge-router-aicore"
DOCKERFILE = ROUTER_DIR / "Dockerfile"
REQUIREMENTS = ROUTER_DIR / "requirements.txt"
LOCK = ROUTER_DIR / "requirements.lock"
BASE_IMAGE_PIN = ROUTER_DIR / "base-image.pin"
SYSTEMD_UNIT = ROUTER_DIR / "wins-edge-router.service.example"
INSTALLER = ROUTER_DIR / "install_aicore_router.sh"
INSTALLER_TEST = ROUTER_DIR / "tests" / "test_aicore_install.py"
REPLAY_TEST = ROUTER_DIR / "tests" / "test_replay_journal.py"

PIN_RE = re.compile(r"^[A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,\-]+\])?==[A-Za-z0-9_.\-]+$")
REQ_BLOCK_RE = re.compile(r"^[A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,\-]+\])?==[A-Za-z0-9_.\-]+")
HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}\b")
REVIEWED_IMAGE = (
    "python:3.14.7-slim-trixie@"
    "sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
)
FROM_RE = re.compile(
    r"^FROM python:3\.14\.7-slim-trixie@sha256:[0-9a-f]{64}$",
    re.MULTILINE,
)
SECRET_PATTERNS = (
    "GEMINI_API_KEY=",
    "SMART_ROUTER_HMAC_SECRET=",
    "EDGE_ROUTER_SECRET=",
    "VLLM_API_KEY=",
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "AKIA",
    "ghp_",
    "github_pat_",
)
FORBIDDEN_COPY_NAMES = (
    ".env",
    ".env.example",
    "aicore.env.example",
    "receipts",
)
BANNED_INSTALL_STEPS = (
    "pip install --upgrade pip",
    "pip install --upgrade wheel",
    "pip install -U pip",
    "pip install -U wheel",
    "pip install -r requirements.txt",
)
RUNTIME_PINS = (
    "fastapi==0.142.2",
    "uvicorn==0.54.0",
    "pydantic==2.13.5",
    "httpx2==2.13.1",
)
PRODUCTION_EXCLUDES = (
    "pytest",
    "google-genai",
    "google_genai",
)


def _strip_comments(text: str) -> list[str]:
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def _requirement_blocks(lock_text: str) -> list[str]:
    lines = lock_text.splitlines()
    blocks: list[list[str]] = []
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
        blocks.append(block)
    return ["\n".join(block) for block in blocks]


def _pin_image() -> str:
    for line in _strip_comments(BASE_IMAGE_PIN.read_text(encoding="utf-8")):
        return line
    raise AssertionError("base-image.pin has no image pin")


def test_base_image_pin_is_immutable_latest_stable_python_slim():
    image = _pin_image()
    match = re.fullmatch(
        r"python:3\.14\.7-slim-trixie@sha256:([0-9a-f]{64})",
        image,
    )
    assert match, f"pin must be exact latest-stable slim digest, got {image!r}"
    assert image == REVIEWED_IMAGE
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    from_lines = [
        line for line in dockerfile.splitlines() if line.startswith("FROM ")
    ]
    assert from_lines == [f"FROM {image}"]
    assert FROM_RE.search(dockerfile)
    assert "python:latest" not in dockerfile
    assert "python:3.15" not in dockerfile
    assert "rc" not in image.lower()
    assert "beta" not in image.lower()
    assert "preview" not in image.lower()


def test_dockerfile_installs_hashed_binary_only_lock():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert (
        "pip install --no-cache-dir --require-hashes --only-binary=:all: "
        "-r requirements.lock"
    ) in dockerfile
    for banned in BANNED_INSTALL_STEPS:
        assert banned not in dockerfile
    assert "COPY requirements.lock" in dockerfile
    assert "--no-access-log" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "http://127.0.0.1:%s/ready" in dockerfile


def test_dockerfile_does_not_copy_secrets_or_env_files():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    copy_lines = [
        line for line in dockerfile.splitlines() if line.startswith("COPY ")
    ]
    joined = "\n".join(copy_lines)
    for name in FORBIDDEN_COPY_NAMES:
        assert name not in joined
    for pattern in SECRET_PATTERNS:
        assert pattern not in dockerfile
    assert "ARG " not in dockerfile


def test_container_and_aicore_unit_provision_private_durable_replay_state():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert "install -d -o winsrouter -g winsrouter -m 0700 /var/lib/winsvpn-router" in dockerfile
    assert "USER winsrouter:winsrouter" in dockerfile
    assert "USER root" not in dockerfile
    assert (
        "SMART_ROUTER_NONCE_JOURNAL_PATH=/var/lib/winsvpn-router/replay-nonces.sqlite3"
        in dockerfile
    )
    assert "DECISIONS_FILE=/var/lib/winsvpn-router/router-decisions.jsonl" in dockerfile

    unit = SYSTEMD_UNIT.read_text(encoding="utf-8")
    assert "User=aicore" in unit
    assert "Group=aicore" in unit
    assert "UMask=0077" in unit
    assert "StateDirectory=winsvpn-router" in unit
    assert "StateDirectoryMode=0700" in unit
    assert "ProtectSystem=strict" in unit
    assert "NoNewPrivileges=true" in unit


def test_aicore_deployment_source_and_its_tests_are_tracked():
    required = (INSTALLER, SYSTEMD_UNIT, INSTALLER_TEST, REPLAY_TEST)
    for path in required:
        assert path.is_file(), f"required Smart Router source is absent: {path.name}"
    result = subprocess.run(
        [
            "git",
            "-C",
            str(ROUTER_DIR.parent),
            "ls-files",
            "--error-unmatch",
            *(str(path.relative_to(ROUTER_DIR.parent)) for path in required),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        "Smart Router deployment source and its tests must be tracked before release: "
        + result.stderr.strip()
    )


def test_canonical_router_is_the_only_aicore_router_source_and_unit():
    assert not (REPOSITORY_ROOT / "edge_router.py").exists()
    assert not (REPOSITORY_ROOT / "tools" / "test_edge_router_snapshot.py").exists()
    assert not (RETIRED_DEPLOY_ROOT / "env" / "wins-edge-router.env.example").exists()
    assert not (RETIRED_DEPLOY_ROOT / "systemd" / "wins-edge-router.service").exists()
    retired_dropins = RETIRED_DEPLOY_ROOT / "systemd" / "wins-edge-router.service.d"
    assert not retired_dropins.exists() or not any(retired_dropins.iterdir())

    readme = (RETIRED_DEPLOY_ROOT / "README.md").read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())
    assert "`router/` is the only AICORE Smart Router implementation" in normalized_readme
    assert "HMAC" in readme
    assert "nonce" in readme
    assert "rate" in readme.lower()


def test_canonical_unit_has_direct_ai_slice_and_hmac_runtime_contract():
    unit = SYSTEMD_UNIT.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")
    assert "Slice=wins-ai.slice" in unit
    assert "EnvironmentFile=/etc/winsvpn/router.env" in unit
    assert "main:app" in unit
    assert "validate_installed_unit" in installer
    assert "wins-edge-router.service.d" in installer


def test_requirements_are_exact_runtime_pins():
    pins = [line for line in _strip_comments(REQUIREMENTS.read_text(encoding="utf-8"))]
    assert pins == list(RUNTIME_PINS)
    for pin in pins:
        assert PIN_RE.match(pin), pin
    lower = REQUIREMENTS.read_text(encoding="utf-8").lower()
    for name in PRODUCTION_EXCLUDES:
        assert name not in lower
    for pattern in SECRET_PATTERNS:
        assert pattern not in REQUIREMENTS.read_text(encoding="utf-8")
    assert "git+" not in lower
    assert "github.com" not in lower


def test_lock_is_complete_hash_pinned_runtime_closure():
    lock = LOCK.read_text(encoding="utf-8")
    assert "pip-compile" in lock
    assert "--generate-hashes" in lock
    assert "--no-strip-extras" in lock
    assert "--only-binary=:all:" in lock
    assert "--only-binary :all:" in lock
    assert "router/requirements.lock" in lock
    assert "router/requirements.txt" in lock
    blocks = _requirement_blocks(lock)
    assert len(blocks) >= len(RUNTIME_PINS)
    for pin in RUNTIME_PINS:
        assert any(block.startswith(pin) for block in blocks), pin
    for block in blocks:
        assert HASH_RE.search(block), block.splitlines()[0]
    lower = lock.lower()
    for name in PRODUCTION_EXCLUDES:
        assert f"{name}==" not in lower
    for pattern in SECRET_PATTERNS:
        assert pattern not in lock
    assert "git+" not in lower
    assert "github.com" not in lower
    names = {block.split("==", 1)[0].lower() for block in blocks}
    assert "pytest" not in names
    assert "google-genai" not in names
    core_block = next(block for block in blocks if block.startswith("pydantic-core=="))
    assert len(HASH_RE.findall(core_block)) >= 100


def test_lock_hashes_are_sha256_hex_only():
    lock = LOCK.read_text(encoding="utf-8")
    hashes = re.findall(r"--hash=([a-z0-9]+):([0-9a-fA-F]+)", lock)
    assert hashes
    for algo, digest in hashes:
        assert algo == "sha256"
        assert re.fullmatch(r"[0-9a-f]{64}", digest)


@pytest.mark.parametrize("path", [DOCKERFILE, REQUIREMENTS, LOCK, BASE_IMAGE_PIN])
def test_supply_chain_files_contain_no_secret_assignments(path: Path):
    text = path.read_text(encoding="utf-8")
    for pattern in SECRET_PATTERNS:
        assert pattern not in text
    assert not re.search(
        r"^[A-Z0-9_]*(PASSWORD|TOKEN|SECRET|API_KEY)=.+$",
        text,
        re.MULTILINE,
    )


def _build_minimal_wheel(directory: Path) -> Path:
    name, version = "winsvpnroutertestpkg", "0.0.1"
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
            "Wheel-Version: 1.0\nGenerator: winsvpn-router-test\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/RECORD", "")
    return wheel_path


def _pip_install(tmp_path: Path, wheel_dir: Path, req_hash: str) -> subprocess.CompletedProcess:
    req_file = tmp_path / f"req-{req_hash[:8]}.txt"
    req_file.write_text(
        f"winsvpnroutertestpkg==0.0.1 \\\n    --hash=sha256:{req_hash}\n",
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
