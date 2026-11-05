#!/usr/bin/env python3
"""Focused fail-closed tests for the GCP deployment-input manifest."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import unicodedata
from unittest import mock
import zipfile

import pytest

import tools.gcp_deployment_inputs as subject


AWG_VALUES = {
    "AWG_SERVER_IMAGE": "amneziavpn/amneziawg-go:v3.1.20260828",
    "AWG_GO_REPOSITORY": "https://github.com/amnezia-vpn/amneziawg-go",
    "AWG_GO_TAG": "v3.1.20260828",
    "AWG_GO_COMMIT": "b5928efb6ca19f0153958460c3d141f04abc5c2e",
    "AWG_GO_SOURCE_SHA256": "1" * 64,
    "AWG_GO_BINARY_SHA256_AMD64": "2" * 64,
    "AWG_GO_BINARY_SHA256_ARM64": "3" * 64,
    "AWG_TOOLS_REPOSITORY": "https://github.com/amnezia-vpn/amneziawg-tools",
    "AWG_TOOLS_TAG": "v3.1.20260812",
    "AWG_TOOLS_COMMIT": "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843",
    "AWG_TOOLS_SOURCE_SHA256": "4" * 64,
    "AWG_QUICK_SHA256": "5" * 64,
    "GO_VERSION": "1.27.1",
    "GO_ARCHIVE_SHA256_AMD64": "6" * 64,
    "GO_ARCHIVE_SHA256_ARM64": "7" * 64,
    "ALPINE_VERSION": "3.24.2",
    "ALPINE_BASE_DIGEST_AMD64": "sha256:" + "8" * 64,
    "ALPINE_BASE_DIGEST_ARM64": "sha256:" + "9" * 64,
}


def _write(path: Path, data: bytes | str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = data.encode("utf-8") if isinstance(data, str) else data
    path.write_bytes(payload)
    path.chmod(mode)


def _header_only_elf(*, machine: int = 62, elf_type: int = 2) -> bytes:
    data = bytearray(64)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    data[16:18] = elf_type.to_bytes(2, "little")
    data[18:20] = machine.to_bytes(2, "little")
    data[20:24] = (1).to_bytes(4, "little")
    return bytes(data)


def _gateway_elf(
    *,
    machine: int = 62,
    elf_type: int = 2,
    entry: int | None = None,
    load_flags: int = 0x5,
    product: str = "winn3-gateway",
    runtime: str | None = None,
    extra: bytes = b"",
    debug: bool = False,
) -> bytearray:
    if runtime is None:
        runtime = "linux-amd64" if machine == 62 else "linux-arm64"
    payload = (
        b"winsvpn.product="
        + product.encode("ascii")
        + b"\x00"
        + b"winsvpn.runtime="
        + runtime.encode("ascii")
        + b"\x00"
        + extra
        + b"\x90" * 16
    )
    payload_off = 64 + 56
    if debug:
        shstrtab = b"\x00.text\x00.debug_info\x00.shstrtab\x00"
        shnum = 4
        shstrndx = 3
    else:
        shstrtab = b"\x00.text\x00.shstrtab\x00"
        shnum = 3
        shstrndx = 2
    shstr_off = payload_off + len(payload)
    shoff = shstr_off + len(shstrtab)
    pad = (8 - (shoff % 8)) % 8
    shoff += pad
    total = shoff + shnum * 64
    vaddr = 0x400000
    if entry is None:
        entry = vaddr + payload_off
    data = bytearray(total)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        elf_type,
        machine,
        1,
        entry,
        64,
        shoff,
        0,
        64,
        56,
        1,
        64,
        shnum,
        shstrndx,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        1,
        load_flags,
        0,
        vaddr,
        vaddr,
        total,
        total,
        0x1000,
    )
    data[payload_off : payload_off + len(payload)] = payload
    data[shstr_off : shstr_off + len(shstrtab)] = shstrtab
    struct.pack_into("<I", data, shoff + 64, 1)
    struct.pack_into("<I", data, shoff + 64 + 4, 1)
    struct.pack_into("<Q", data, shoff + 64 + 8, 6)
    struct.pack_into("<Q", data, shoff + 64 + 16, vaddr + payload_off)
    struct.pack_into("<Q", data, shoff + 64 + 24, payload_off)
    struct.pack_into("<Q", data, shoff + 64 + 32, len(payload))
    if debug:
        struct.pack_into("<I", data, shoff + 128, 7)
        struct.pack_into("<I", data, shoff + 128 + 4, 1)
        struct.pack_into("<Q", data, shoff + 128 + 24, payload_off)
        struct.pack_into("<Q", data, shoff + 128 + 32, 8)
        struct.pack_into("<I", data, shoff + 192, 19)
        struct.pack_into("<I", data, shoff + 192 + 4, 3)
        struct.pack_into("<Q", data, shoff + 192 + 24, shstr_off)
        struct.pack_into("<Q", data, shoff + 192 + 32, len(shstrtab))
    else:
        struct.pack_into("<I", data, shoff + 128, 7)
        struct.pack_into("<I", data, shoff + 128 + 4, 3)
        struct.pack_into("<Q", data, shoff + 128 + 24, shstr_off)
        struct.pack_into("<Q", data, shoff + 128 + 32, len(shstrtab))
    return data


def _fake_amd64_elf() -> bytes:
    return bytes(_gateway_elf(machine=62, runtime="linux-amd64"))


def _proof_artifact_args(repo: Path, gateway: Path) -> tuple[Path, Path, Path]:
    architecture = gateway.name.rsplit("-", 1)[-1]
    return (
        gateway,
        repo / f".artifacts/gcp-proof/winn3-probe-linux-{architecture}",
        repo / f".artifacts/gcp-proof/winn-ech-keygen-linux-{architecture}",
    )


def _client_runtime_artifact_args(repo: Path) -> tuple[Path, Path, Path]:
    root = repo / ".artifacts/gcp-proof"
    return (
        root / "amneziawg-go-linux-amd64",
        root / "awg-linux-amd64",
        root / "xray-linux-amd64",
    )


def _all_artifact_args(repo: Path, gateway: Path) -> tuple[Path, ...]:
    return _proof_artifact_args(repo, gateway) + _client_runtime_artifact_args(repo)


def _linux_client_builder(hashes: dict[str, str], awg_values: dict[str, str]) -> str:
    return (
        "#!/bin/sh\n"
        f'AWG_GO_TAG="{awg_values["AWG_GO_TAG"]}"\n'
        f'AWG_GO_COMMIT="{awg_values["AWG_GO_COMMIT"]}"\n'
        f'AWG_GO_SOURCE_SHA256="{awg_values["AWG_GO_SOURCE_SHA256"]}"\n'
        f'AWG_GO_BINARY_SHA256="{hashes["amneziawg-go"]}"\n'
        f'AWG_TOOLS_VERSION="{awg_values["AWG_TOOLS_TAG"]}"\n'
        f'AWG_BINARY_SHA256="{hashes["awg"]}"\n'
        f'AWG_QUICK_SHA256="{awg_values["AWG_QUICK_SHA256"]}"\n'
        f'XRAY_SHA256_AMD64="{hashes["xray"]}"\n'
        f'GO_VERSION="{awg_values["GO_VERSION"]}"\n'
    )


def _xray_engine_builder() -> str:
    return (
        "#!/bin/sh\n"
        'XRAY_REPO="https://github.com/XTLS/Xray-core.git"\n'
        f'XRAY_TAG="{subject.REVIEWED_XRAY_TAG}"\n'
        f'XRAY_COMMIT="{subject.REVIEWED_XRAY_COMMIT}"\n'
        f'REVIEWED_GO_VERSION="{subject.REVIEWED_GO_VERSION}"\n'
    )


def _build(
    repo: Path, gateway: Path, *, created_utc: str | None = None
) -> dict[str, object]:
    return subject.build_manifest(
        repo,
        *_all_artifact_args(repo, gateway),
        created_utc=created_utc,
    )


def _create_manifest(
    repo: Path, output: Path, gateway: Path, *, created_utc: str | None = None
) -> dict[str, object]:
    return subject.create_manifest(
        repo,
        output,
        *_all_artifact_args(repo, gateway),
        created_utc=created_utc,
    )


def _zip_bytes(members: dict[str, bytes], compress: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compress) as bundle:
        for name, payload in members.items():
            bundle.writestr(name, payload)
    return buffer.getvalue()


def _write_python_runtime_receipt(
    root: Path, *, executable: Path | None = None
) -> Path:
    executable_path = Path(executable or sys.executable).resolve(strict=True)
    root.mkdir(parents=True, exist_ok=True)
    archive = root / "python-archive.bin"
    source = root / "python-source.bin"
    tree = root / "python-tree"
    tree.mkdir(exist_ok=True)
    archive.write_bytes(b"winsvpn-python-archive\n")
    source.write_bytes(b"winsvpn-python-source\n")
    marker = tree / "marker"
    marker.write_bytes(b"winsvpn-python-tree\n")
    archive.chmod(0o400)
    source.chmod(0o400)
    marker.chmod(0o400)
    measured = subject.measure_python_runtime_identity(
        executable=executable_path,
        archive=archive,
        install_tree=tree,
        source=source,
    )
    record = {
        "archive_path": measured["archive_path"],
        "archive_sha256": measured["archive_sha256"],
        "contract": subject.PYTHON_RUNTIME_CONTRACT,
        "executable_path": measured["executable_path"],
        "executable_sha256": measured["executable_sha256"],
        "implementation": "cpython",
        "install_tree_path": measured["install_tree_path"],
        "install_tree_sha256": measured["install_tree_sha256"],
        "kind": subject.PYTHON_RUNTIME_KIND,
        "schema_version": subject.PYTHON_RUNTIME_SCHEMA_VERSION,
        "source_path": measured["source_path"],
        "source_sha256": measured["source_sha256"],
        "version": "%d.%d.%d" % sys.version_info[:3],
    }
    path = root / "python-runtime-receipt.json"
    path.write_bytes(subject.canonical_bytes(record))
    path.chmod(0o400)
    return path


def _load_receipt(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes().decode("ascii"))


def _rewrite_runtime_receipt(path: Path, record: dict[str, object]) -> None:
    path.chmod(0o600)
    path.write_bytes(subject.canonical_bytes(record))
    path.chmod(0o400)


@pytest.fixture(autouse=True)
def python_runtime_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    receipt = _write_python_runtime_receipt(tmp_path / "runtime-auth")
    monkeypatch.setenv(subject.PYTHON_RUNTIME_RECEIPT_ENV, str(receipt))
    return receipt


def _make_repo(root: Path) -> tuple[Path, Path]:
    repo = root / "repo"
    repo.mkdir()
    _write(repo / subject.INSTALLERS[0], "#!/bin/sh\nexit 0\n", 0o644)
    _write(
        repo / subject.INSTALLERS[1],
        "#!/bin/sh\n"
        'XRAY_VERSION_DEFAULT="${XRAY_VERSION:-26.9.30}"\n'
        f'XRAY_LINUX_64_SHA256_DEFAULT="${{XRAY_LINUX_64_SHA256:-{"a" * 64}}}"\n',
        0o644,
    )
    _write(repo / subject.INSTALLERS[2], "#!/bin/sh\nexit 0\n", 0o644)
    _write(repo / "server/nested/unit.conf", "[Unit]\nDescription=fixture\n")

    for relative in subject.ROUTER_REQUIRED:
        if relative == "router/base-image.pin":
            value = "python:3.14.7-slim-trixie@sha256:" + "b" * 64 + "\n"
        elif relative == "router/Dockerfile":
            value = "FROM scratch\n"
        elif relative.endswith(".py"):
            value = "VALUE = 1\n"
        else:
            value = "fixture==1.0\n"
        mode = 0o755 if relative == "router/install_aicore_router.sh" else 0o644
        _write(repo / relative, value, mode)
    _write(repo / "router/receipts/prod_sanity.sh", "#!/bin/sh\nexit 0\n", 0o755)
    _write(repo / "router/receipts/prod_sanity.txt", "PASS\n")
    _write(repo / "router/tests/test_router.py", "def test_fixture(): pass\n")

    _write(repo / "winn_protocol_experimental/go.mod", "module example.test/winn\n")
    _write(repo / "winn_protocol_experimental/go.sum", "fixture checksum\n")
    _write(repo / "winn_protocol_experimental/cmd/winn3-gateway/main.go", "package main\n")
    _write(repo / "winn_protocol_experimental/deploy/systemd/winn3.service", "[Unit]\n")
    _write(repo / "winn_protocol_experimental/scripts/build.sh", "#!/bin/sh\n", 0o755)

    artifact = repo / ".artifacts/gcp-proof/winn3-gateway-linux-amd64"
    for product, path in zip(subject.PROOF_CLIENT_PRODUCTS, _proof_artifact_args(repo, artifact)):
        _write(
            path,
            bytes(
                _gateway_elf(
                    machine=62,
                    runtime="linux-amd64",
                    product=product,
                    extra=("artifact=" + product).encode("ascii"),
                )
            ),
            0o755,
        )
    runtime_hashes: dict[str, str] = {}
    for product, path in zip(
        subject.CLIENT_RUNTIME_PRODUCTS, _client_runtime_artifact_args(repo)
    ):
        payload = bytes(
            _gateway_elf(
                machine=62,
                runtime="linux-amd64",
                product=product,
                extra=("artifact=" + product).encode("ascii"),
            )
        )
        _write(path, payload, 0o755)
        runtime_hashes[product] = hashlib.sha256(payload).hexdigest()
    awg_values = dict(AWG_VALUES)
    awg_script = "#!/bin/sh\n" + "".join(
        f'{key}="{value}"\n' for key, value in awg_values.items()
    )
    _write(repo / "server/build_amneziawg_go_server_image.sh", awg_script, 0o755)
    for relative, _ in subject.PROVENANCE_INPUTS:
        if relative == "tools/gcp_deployment_inputs.py":
            _write(repo / relative, Path(subject.__file__).read_bytes(), 0o755)
        elif relative == "tools/gcp_proof_remote_action.py":
            _write(
                repo / relative,
                Path(subject.__file__).with_name("gcp_proof_remote_action.py").read_bytes(),
                0o755,
            )
        elif relative == "tools/gcp_proof_attempt_broker.py":
            _write(
                repo / relative,
                Path(subject.__file__).with_name("gcp_proof_attempt_broker.py").read_bytes(),
                0o755,
            )
        elif relative.startswith("tools/gcp_proof_attempt_broker/"):
            source = Path(subject.__file__).resolve().parent.joinpath(
                *Path(relative).parts[1:]
            )
            mode = 0o755 if source.suffix == ".py" else 0o644
            _write(repo / relative, source.read_bytes(), mode)
        elif relative == "tools/build_linux_release.sh":
            _write(repo / relative, _linux_client_builder(runtime_hashes, awg_values), 0o755)
        elif relative == "tools/build_xray_engine.sh":
            _write(repo / relative, _xray_engine_builder(), 0o755)
        else:
            _write(
                repo / relative,
                f"fixture for {relative}\n",
                0o755 if relative.endswith((".py", ".sh")) else 0o644,
            )
    return repo, artifact


@pytest.fixture()
def closure(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo, artifact = _make_repo(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    return repo, artifact, state / "DEPLOYMENT_INPUTS.json"


def _create(closure: tuple[Path, Path, Path]) -> tuple[Path, Path, Path, dict[str, object]]:
    repo, artifact, manifest = closure
    record = _create_manifest(
        repo,
        manifest,
        artifact,
        created_utc="2026-08-23T12:34:56Z",
    )
    return repo, artifact, manifest, record


def _rewrite_manifest(manifest: Path, record: object, *, canonical: bool = True) -> None:
    payload = (
        subject.canonical_bytes(record)
        if canonical
        else (json.dumps(record, indent=2) + "\n").encode("ascii")
    )
    manifest.write_bytes(payload)
    manifest.chmod(0o600)
    manifest.with_name(manifest.name + ".sha256").write_text(
        f"{hashlib.sha256(payload).hexdigest()}  {manifest.name}\n",
        encoding="ascii",
    )
    manifest.with_name(manifest.name + ".sha256").chmod(0o600)


def test_create_verify_canonical_ascii_and_exact_closure(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, manifest, record = _create(closure)
    verified = subject.verify_manifest(repo, manifest)
    assert verified == record
    payload = manifest.read_bytes()
    assert payload == subject.canonical_bytes(record)
    payload.decode("ascii")
    assert record["publication_authorized"] is False
    assert record["scope_roots"] == list(subject.SCOPE_ROOTS)
    assert [item["path"] for item in record["installers"]] == list(subject.INSTALLERS)
    assert subject.INSTALLERS[-1] == "router/install_aicore_router.sh"
    router_installer = next(
        item for item in record["inputs"]
        if item["path"] == "router/install_aicore_router.sh"
    )
    assert router_installer["class"] == "router"
    assert router_installer["mode"] == 0o755
    assert any(item["path"] == artifact.relative_to(repo).as_posix() for item in record["inputs"])
    gateway = record["gateway_artifact"]
    assert gateway["path"] == artifact.relative_to(repo).as_posix()
    assert gateway["architecture"] == "amd64"
    assert gateway["elf_machine"] == 62
    assert gateway["product"] == "winn3-gateway"
    assert gateway["runtime"] == "linux-amd64"
    assert gateway["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    proof_artifacts = record["proof_client_artifacts"]
    assert [item["product"] for item in proof_artifacts] == list(
        subject.PROOF_CLIENT_PRODUCTS
    )
    assert [item["architecture"] for item in proof_artifacts] == ["amd64"] * 3
    assert [item["elf_machine"] for item in proof_artifacts] == [62] * 3
    assert len({item["path"] for item in proof_artifacts}) == 3
    assert len({item["sha256"] for item in proof_artifacts}) == 3
    assert gateway == proof_artifacts[0]
    artifact_input = next(
        item for item in record["inputs"] if item["path"] == gateway["path"]
    )
    assert gateway["sha256"] == artifact_input["sha256"]
    assert gateway["entry"] != 0
    helper = record["remote_action_helper"]
    assert helper["path"] == subject.REMOTE_ACTION_HELPER_PATH
    assert helper["install_path"] == subject.REMOTE_ACTION_HELPER_INSTALL_PATH
    assert helper["contract"] == subject.REMOTE_ACTION_HELPER_CONTRACT
    assert helper["required_roles"] == list(subject.REMOTE_ACTION_HELPER_REQUIRED_ROLES)
    assert helper["required_roles"] == ["control", "data-cover", "data-winn3"]
    helper_input = next(
        item for item in record["inputs"] if item["path"] == subject.REMOTE_ACTION_HELPER_PATH
    )
    assert helper_input["class"] == "tool"
    assert helper["sha256"] == helper_input["sha256"]
    assert helper["bytes"] == helper_input["bytes"]
    assert helper["mode"] == helper_input["mode"]
    assert helper["mode"] & 0o022 == 0
    broker = record["attempt_broker"]
    assert broker["path"] == subject.ATTEMPT_BROKER_PATH
    assert broker["install_path"] == subject.ATTEMPT_BROKER_INSTALL_PATH
    assert broker["contract"] == subject.ATTEMPT_BROKER_CONTRACT
    assert broker["required_roles"] == list(subject.ATTEMPT_BROKER_REQUIRED_ROLES)
    assert broker["required_roles"] == ["control"]
    broker_input = next(
        item for item in record["inputs"] if item["path"] == subject.ATTEMPT_BROKER_PATH
    )
    assert broker_input["class"] == "tool"
    assert broker["sha256"] == broker_input["sha256"]
    assert broker["bytes"] == broker_input["bytes"]
    assert broker["mode"] == broker_input["mode"]
    assert broker["mode"] & 0o022 == 0
    assert broker["socket"]["path"] == subject.ATTEMPT_BROKER_SOCKET_SOURCE
    assert broker["socket"]["install_path"] == subject.ATTEMPT_BROKER_SOCKET_INSTALL_PATH
    assert broker["service"]["path"] == subject.ATTEMPT_BROKER_SERVICE_SOURCE
    assert broker["service"]["install_path"] == subject.ATTEMPT_BROKER_SERVICE_INSTALL_PATH
    assert [item["name"] for item in broker["units"]] == [
        name for _path, _install, name in subject.ATTEMPT_BROKER_UNITS
    ]
    assert [item["name"] for item in broker["configs"]] == [
        name for _path, _install, name in subject.ATTEMPT_BROKER_CONFIGS
    ]
    runtime_artifacts = record["client_runtime_artifacts"]
    assert [item["product"] for item in runtime_artifacts] == list(
        subject.CLIENT_RUNTIME_PRODUCTS
    )
    assert [item["architecture"] for item in runtime_artifacts] == ["amd64"] * 3
    assert [item["elf_machine"] for item in runtime_artifacts] == [62] * 3
    assert [item["runtime"] for item in runtime_artifacts] == ["linux-amd64"] * 3
    assert len({item["path"] for item in runtime_artifacts}) == 3
    assert len({item["sha256"] for item in runtime_artifacts}) == 3
    pins = record["external_pins"]["client_runtime"]
    for item in runtime_artifacts:
        pin = pins[item["product"]]
        assert item["sha256"] == pin["sha256"]
        assert item["provenance"]["tag"] == pin["tag"]
        assert item["provenance"]["commit"] == pin["commit"]
        runtime_input = next(
            entry for entry in record["inputs"] if entry["path"] == item["path"]
        )
        assert runtime_input["class"] == subject.CLIENT_RUNTIME_CLASS
        assert runtime_input["sha256"] == item["sha256"]
        assert runtime_input["bytes"] == item["bytes"]
        assert runtime_input["mode"] == item["mode"]
        assert item["mode"] & 0o111
        assert item["mode"] & 0o022 == 0
    assert pins["amneziawg-go"]["tag"] == "v3.1.20260828"
    assert pins["xray"]["tag"] == "v26.9.30"
    assert record["external_pins"]["xray"]["version"] == "26.9.30"


def test_candidate_id_excludes_created_timestamp(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    first = _build(repo, artifact, created_utc="2026-08-23T00:00:00Z")
    second = _build(repo, artifact, created_utc="2026-08-24T00:00:00Z")
    assert first["candidate_id"] == second["candidate_id"]
    assert first["created_utc"] != second["created_utc"]


@pytest.mark.parametrize("created", ["2026-99-23T00:00:00Z", "2026-08-23T00:00:00+00:00"])
def test_invalid_or_noncanonical_timestamp_is_rejected(
    closure: tuple[Path, Path, Path], created: str
) -> None:
    repo, artifact, _ = closure
    with pytest.raises(subject.DeploymentInputsError, match="created_utc"):
        _build(repo, artifact, created_utc=created)


def test_cli_create_and_verify(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, manifest = closure
    script = Path(subject.__file__)
    cli_executable = Path(sys._base_executable).resolve(strict=True)
    cli_receipt = _write_python_runtime_receipt(
        manifest.parent / "cli-runtime-auth",
        executable=cli_executable,
    )
    cli_environment = os.environ.copy()
    cli_environment.pop("PYTHONEXECUTABLE", None)
    cli_environment[subject.PYTHON_RUNTIME_RECEIPT_ENV] = str(cli_receipt)
    cli = [str(cli_executable), "-I", "-S", "-B", str(script)]
    created = subprocess.run(
        cli
        + [
            "create",
            "--repo-root",
            str(repo),
            "--output",
            str(manifest),
            "--winn3-gateway-artifact",
            str(artifact),
            "--winn3-probe-artifact",
            str(_proof_artifact_args(repo, artifact)[1]),
            "--winn-ech-keygen-artifact",
            str(_proof_artifact_args(repo, artifact)[2]),
            "--amneziawg-go-artifact",
            str(_client_runtime_artifact_args(repo)[0]),
            "--awg-artifact",
            str(_client_runtime_artifact_args(repo)[1]),
            "--xray-artifact",
            str(_client_runtime_artifact_args(repo)[2]),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=cli_environment,
    )
    assert created.returncode == 0, created.stderr
    checked = subprocess.run(
        cli
        + ["verify", "--repo-root", str(repo), "--manifest", str(manifest)],
        text=True,
        capture_output=True,
        check=False,
        env=cli_environment,
    )
    assert checked.returncode == 0, checked.stderr
    assert "PASS verified" in checked.stdout


def test_immutable_output_refuses_overwrite(closure: tuple[Path, Path, Path]) -> None:
    _create(closure)
    repo, artifact, manifest = closure
    with pytest.raises(subject.DeploymentInputsError, match="overwrite"):
        _create_manifest(repo, manifest, artifact)


@pytest.mark.parametrize("member_kind", ["empty", "symlink", "hardlink", "fifo"])
def test_nonregular_empty_and_multiply_linked_members_fail_closed(
    closure: tuple[Path, Path, Path], member_kind: str
) -> None:
    repo, artifact, _ = closure
    target = repo / "winn_protocol_experimental/bad-member"
    if member_kind == "empty":
        target.touch()
    elif member_kind == "symlink":
        target.symlink_to("go.mod")
    elif member_kind == "hardlink":
        os.link(repo / "winn_protocol_experimental/go.mod", target)
    else:
        os.mkfifo(target)
    with pytest.raises(subject.DeploymentInputsError):
        _build(repo, artifact)


def test_device_input_is_rejected_as_nonregular(closure: tuple[Path, Path, Path]) -> None:
    repo, _, _ = closure
    target = repo / "winn_protocol_experimental/device"
    target.write_bytes(b"placeholder\n")
    real_stat = subject.os.stat

    def device_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if path == "device" and kwargs.get("dir_fd") is not None:
            return real_stat("/dev/null")
        return real_stat(path, *args, **kwargs)

    with mock.patch.object(subject.os, "stat", side_effect=device_stat):
        with pytest.raises(subject.DeploymentInputsError, match="not a regular file"):
            subject._read_regular(repo, "winn_protocol_experimental/device", "winn")


def test_wrong_architecture_or_non_elf_artifact_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    artifact.write_bytes(b"not an ELF binary")
    with pytest.raises(subject.DeploymentInputsError, match="ELF"):
        _build(repo, artifact)


def test_unclassified_router_config_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    _write(repo / "router/new-provider.yaml", "enabled: true\n")
    with pytest.raises(subject.DeploymentInputsError, match="unclassified router"):
        _build(repo, artifact)


def test_duplicate_awg_pin_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    path = repo / "server/build_amneziawg_go_server_image.sh"
    with path.open("a", encoding="utf-8") as handle:
        handle.write('AWG_GO_TAG="v3.1.20990101"\n')
    with pytest.raises(subject.DeploymentInputsError, match="exactly once"):
        _build(repo, artifact)


def test_unpinned_router_image_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    (repo / "router/base-image.pin").write_text("python:latest\n", encoding="ascii")
    with pytest.raises(subject.DeploymentInputsError, match="tag-and-digest"):
        _build(repo, artifact)


def test_missing_xray_pin_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    installer = repo / subject.INSTALLERS[1]
    installer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    installer.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="Xray pins"):
        _build(repo, artifact)


def test_file_mutation_during_read_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, _, _ = closure
    target = repo / "server/nested/unit.conf"
    real_fstat = subject.os.fstat
    calls = 0

    def mutating_fstat(fd: int) -> os.stat_result:
        nonlocal calls
        result = real_fstat(fd)
        if stat.S_ISREG(result.st_mode):
            calls += 1
        if calls == 1 and stat.S_ISREG(result.st_mode):
            target.write_text("changed during read and now larger\n", encoding="utf-8")
        return result

    with mock.patch.object(subject.os, "fstat", side_effect=mutating_fstat):
        with pytest.raises(subject.DeploymentInputsError, match="changed while being read"):
            subject._read_regular(repo, "server/nested/unit.conf", "server")


def test_ancestor_swap_cannot_substitute_external_bytes(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, _ = closure
    external = repo.parent / f"{repo.name}-external"
    moved = repo / "server-original"
    external.mkdir()
    (external / "unit.conf").write_bytes(b"external substituted bytes\n")
    real_open = subject.os.open
    swapped = False

    def swapping_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        if path == "unit.conf" and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            (repo / "server").rename(moved)
            (repo / "server").symlink_to(external, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    try:
        with mock.patch.object(subject.os, "open", side_effect=swapping_open):
            with pytest.raises(
                subject.DeploymentInputsError,
                match="repository root changed|ancestor changed",
            ):
                subject._read_regular(repo, "server/nested/unit.conf", "server")
    finally:
        link = repo / "server"
        if link.is_symlink():
            link.unlink()
        if moved.exists():
            moved.rename(repo / "server")
        if external.exists():
            (external / "unit.conf").unlink(missing_ok=True)
            external.rmdir()


@pytest.mark.parametrize("change", ["addition", "removal", "mutation", "root-replacement"])
def test_scope_changes_and_root_replacement_between_snapshots_are_rejected(
    closure: tuple[Path, Path, Path], change: str
) -> None:
    repo, artifact, _ = closure
    real_collect = subject._collect_snapshot
    calls = 0

    def changing_collect(
        repo_arg: Path, artifact_relatives: tuple[tuple[str, str], ...]
    ):
        nonlocal calls
        result = real_collect(repo_arg, artifact_relatives)
        calls += 1
        if calls == 1:
            if change == "addition":
                _write(repo / "server/added.conf", "new input\n")
            elif change == "removal":
                (repo / "winn_protocol_experimental/deploy/systemd/winn3.service").unlink()
            elif change == "mutation":
                (repo / "winn_protocol_experimental/go.mod").write_text(
                    "module changed.test/winn\n", encoding="utf-8"
                )
            else:
                moved = repo.with_name("repo-replaced")
                repo.rename(moved)
                repo.mkdir()
        return result

    with mock.patch.object(subject, "_collect_snapshot", side_effect=changing_collect):
        with pytest.raises(subject.DeploymentInputsError):
            _build(repo, artifact)


@pytest.mark.parametrize(
    "bad_path",
    [
        "/absolute/input",
        "../traversal",
        "server/../traversal",
        "server\\windows-path",
        unicodedata.normalize("NFD", "server/caf\u00e9"),
    ],
)
def test_manifest_rejects_noncanonical_paths(
    closure: tuple[Path, Path, Path], bad_path: str
) -> None:
    repo, _, manifest, record = _create(closure)
    record["inputs"][0]["path"] = bad_path
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError):
        subject.verify_manifest(repo, manifest)


def test_manifest_rejects_duplicate_input_path(closure: tuple[Path, Path, Path]) -> None:
    repo, _, manifest, record = _create(closure)
    record["inputs"].append(dict(record["inputs"][0]))
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="duplicate manifest input"):
        subject.verify_manifest(repo, manifest)


def test_boolean_schema_version_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, _, manifest, record = _create(closure)
    record["schema_version"] = True
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="policy fields"):
        subject.verify_manifest(repo, manifest)


@pytest.mark.parametrize("installer_change", ["reorder", "duplicate", "unsafe-mode"])
def test_installer_records_are_exact_and_safe(
    closure: tuple[Path, Path, Path], installer_change: str
) -> None:
    repo, _, manifest, record = _create(closure)
    if installer_change == "reorder":
        record["installers"][0], record["installers"][1] = (
            record["installers"][1],
            record["installers"][0],
        )
    elif installer_change == "duplicate":
        record["installers"][1] = dict(record["installers"][0])
    else:
        record["installers"][0]["mode"] = 0o666
        for item in record["inputs"]:
            if item["path"] == subject.INSTALLERS[0]:
                item["mode"] = 0o666
                break
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError):
        subject.verify_manifest(repo, manifest)


def test_manifest_rejects_duplicate_json_key(closure: tuple[Path, Path, Path]) -> None:
    repo, _, manifest, _ = _create(closure)
    payload = manifest.read_bytes()
    if not payload.startswith(b"{"):
        raise AssertionError("canonical manifest must start with an object")
    tampered = b'{"kind":"duplicate",' + payload[1:]
    manifest.write_bytes(tampered)
    sidecar = manifest.with_name(manifest.name + ".sha256")
    sidecar.write_text(
        f"{hashlib.sha256(tampered).hexdigest()}  {manifest.name}\n", encoding="ascii"
    )
    with pytest.raises(subject.DeploymentInputsError, match="duplicate JSON key"):
        subject.verify_manifest(repo, manifest)


def test_noncanonical_json_and_bad_sidecar_are_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, _, manifest, record = _create(closure)
    _rewrite_manifest(manifest, record, canonical=False)
    with pytest.raises(subject.DeploymentInputsError, match="not canonical"):
        subject.verify_manifest(repo, manifest)
    _rewrite_manifest(manifest, record)
    manifest.with_name(manifest.name + ".sha256").write_text("0" * 64 + "  wrong.json\n")
    with pytest.raises(subject.DeploymentInputsError, match="sidecar"):
        subject.verify_manifest(repo, manifest)


def test_live_scope_addition_and_removal_invalidate_existing_manifest(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, manifest, _ = _create(closure)
    added = repo / "server/late-addition.conf"
    _write(added, "late\n")
    with pytest.raises(subject.DeploymentInputsError, match="no longer matches"):
        subject.verify_manifest(repo, manifest)
    added.unlink()
    removed = repo / "winn_protocol_experimental/go.sum"
    removed.unlink()
    with pytest.raises(subject.DeploymentInputsError):
        subject.verify_manifest(repo, manifest)


def test_manifest_and_sidecar_permissions_fail_closed(closure: tuple[Path, Path, Path]) -> None:
    repo, _, manifest, _ = _create(closure)
    manifest.chmod(0o666)
    with pytest.raises(subject.DeploymentInputsError, match="immutable"):
        subject.verify_manifest(repo, manifest)


def test_manifest_must_be_outside_repo_and_have_exact_name(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    with pytest.raises(subject.DeploymentInputsError, match="outside"):
        _create_manifest(repo, repo / "DEPLOYMENT_INPUTS.json", artifact)
    with pytest.raises(subject.DeploymentInputsError, match="filename"):
        _create_manifest(repo, repo.parent / "state/not-the-manifest.json", artifact)


def test_header_only_64_byte_elf_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    artifact.write_bytes(_header_only_elf())
    artifact.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="header-only ELF"):
        _build(repo, artifact)


@pytest.mark.parametrize(
    "mutate,pattern",
    [
        ("truncate-program", "program table is truncated"),
        ("truncate-section", "section table is truncated"),
        ("overlap", "tables overlap"),
    ],
)
def test_elf_table_truncation_and_overlap_are_rejected(
    closure: tuple[Path, Path, Path], mutate: str, pattern: str
) -> None:
    repo, artifact, _ = closure
    data = _gateway_elf()
    if mutate == "truncate-program":
        struct.pack_into("<H", data, 56, 8)
    elif mutate == "truncate-section":
        data[:] = data[:-24]
    else:
        struct.pack_into("<Q", data, 40, 64)
    artifact.write_bytes(bytes(data))
    artifact.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match=pattern):
        _build(repo, artifact)


@pytest.mark.parametrize(
    "mutate,pattern",
    [
        ("machine", "machine"),
        ("type", "ELF type"),
        ("entry-zero", "entry is zero"),
        ("entry-unmapped", "executable load segment"),
    ],
)
def test_wrong_elf_machine_type_and_entry_are_rejected(
    closure: tuple[Path, Path, Path], mutate: str, pattern: str
) -> None:
    repo, artifact, _ = closure
    if mutate == "machine":
        data = _gateway_elf(machine=183, runtime="linux-amd64")
    elif mutate == "type":
        data = _gateway_elf(elf_type=1)
    elif mutate == "entry-zero":
        data = _gateway_elf(entry=0)
    else:
        data = _gateway_elf(entry=0x1000)
    artifact.write_bytes(bytes(data))
    artifact.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match=pattern):
        _build(repo, artifact)


def test_elf_without_executable_load_segment_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, artifact, _ = closure
    artifact.write_bytes(bytes(_gateway_elf(load_flags=0x4)))
    artifact.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="no executable load segment"):
        _build(repo, artifact)


def test_probe_without_executable_load_segment_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, artifact, _ = closure
    probe = _proof_artifact_args(repo, artifact)[1]
    probe.write_bytes(
        bytes(
            _gateway_elf(
                load_flags=0x4,
                product="winn3-probe",
                runtime="linux-amd64",
            )
        )
    )
    probe.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="no executable load segment"):
        _build(repo, artifact)


def test_proof_client_artifacts_must_share_one_machine(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, artifact, _ = closure
    probe = _proof_artifact_args(repo, artifact)[1]
    probe.write_bytes(
        bytes(
            _gateway_elf(
                machine=183,
                product="winn3-probe",
                runtime="linux-amd64",
            )
        )
    )
    probe.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="machine"):
        _build(repo, artifact)


def test_proof_client_artifact_paths_and_digests_cannot_be_reused(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, gateway, _ = closure
    _, probe, keygen = _proof_artifact_args(repo, gateway)
    runtime = _client_runtime_artifact_args(repo)
    with pytest.raises(subject.DeploymentInputsError, match="paths must be distinct"):
        subject.build_manifest(repo, gateway, gateway, keygen, *runtime)

    shared = bytes(
        _gateway_elf(
            product="winn3-gateway",
            extra=(
                b"winsvpn.product=winn3-probe\x00"
                b"winsvpn.product=winn-ech-keygen\x00shared"
            ),
        )
    )
    gateway.write_bytes(shared)
    probe.write_bytes(shared)
    gateway.chmod(0o755)
    probe.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="ambiguous|digests must be distinct"):
        _build(repo, gateway)


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_proof_client_artifact_links_are_rejected(
    closure: tuple[Path, Path, Path], link_kind: str
) -> None:
    repo, gateway, _ = closure
    probe = _proof_artifact_args(repo, gateway)[1]
    probe.unlink()
    if link_kind == "symlink":
        probe.symlink_to(gateway.name)
    else:
        os.link(gateway, probe)
    with pytest.raises(subject.DeploymentInputsError, match="regular file|hard-linked"):
        _build(repo, gateway)


def test_same_byte_artifact_path_replacement_between_snapshots_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, gateway, _ = closure
    probe = _proof_artifact_args(repo, gateway)[1]
    real_collect = subject._collect_snapshot
    calls = 0

    def replacing_collect(
        repo_arg: Path, artifact_relatives: tuple[tuple[str, str], ...]
    ):
        nonlocal calls
        result = real_collect(repo_arg, artifact_relatives)
        calls += 1
        if calls == 1:
            payload = probe.read_bytes()
            probe.unlink()
            _write(probe, payload, 0o755)
        return result

    with mock.patch.object(subject, "_collect_snapshot", side_effect=replacing_collect):
        with pytest.raises(subject.DeploymentInputsError, match="mutated during capture"):
            _build(repo, gateway)


def test_valid_x64_and_arm64_gateway_elf_controls() -> None:
    x64 = bytes(_gateway_elf(machine=62, runtime="linux-amd64"))
    arm64 = bytes(_gateway_elf(machine=183, runtime="linux-arm64"))
    x64_id = subject._inspect_elf64(
        x64, expected_machine=62, product="winn3-gateway", runtime="linux-amd64"
    )
    arm64_id = subject._inspect_elf64(
        arm64, expected_machine=183, product="winn3-gateway", runtime="linux-arm64"
    )
    assert x64_id["architecture"] == "amd64"
    assert arm64_id["architecture"] == "arm64"
    assert x64_id["elf_machine"] == 62
    assert arm64_id["elf_machine"] == 183
    assert x64_id["entry"] != 0 and arm64_id["entry"] != 0
    assert x64_id["sha256"] == hashlib.sha256(x64).hexdigest()
    assert arm64_id["sha256"] == hashlib.sha256(arm64).hexdigest()


def test_arm64_gateway_artifact_binds_digest_and_runtime(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, _ = closure
    artifact = repo / ".artifacts/gcp-proof/winn3-gateway-linux-arm64"
    paths = _proof_artifact_args(repo, artifact)
    payload = bytes(_gateway_elf(machine=183, runtime="linux-arm64"))
    for product, path in zip(subject.PROOF_CLIENT_PRODUCTS, paths):
        artifact_payload = (
            payload
            if product == subject.GATEWAY_PRODUCT
            else bytes(
                _gateway_elf(
                    machine=183,
                    runtime="linux-arm64",
                    product=product,
                    extra=("artifact=" + product).encode("ascii"),
                )
            )
        )
        _write(path, artifact_payload, 0o755)
    record = _build(repo, artifact, created_utc="2026-08-23T12:34:56Z")
    gateway = record["gateway_artifact"]
    assert gateway["architecture"] == "arm64"
    assert gateway["runtime"] == "linux-arm64"
    assert gateway["elf_machine"] == 183
    assert gateway["sha256"] == hashlib.sha256(payload).hexdigest()
    artifact_input = next(
        item for item in record["inputs"] if item["path"] == gateway["path"]
    )
    assert artifact_input["path"] == artifact.relative_to(repo).as_posix()
    assert artifact_input["sha256"] == gateway["sha256"]


def test_zip_pairing_length_mismatch_is_rejected() -> None:
    with pytest.raises(subject.DeploymentInputsError, match="length mismatch"):
        subject._strict_zip(["a"], ["a", "b"], "deployment installer")
    paired = subject._strict_zip(["a", "b"], ["x", "y"], "deployment installer")
    assert paired == [("a", "x"), ("b", "y")]


def test_zip_member_length_mismatch_is_rejected() -> None:
    payload = b"unique-gateway-zip-member"
    raw = _zip_bytes({"member.bin": payload})
    original = len(payload).to_bytes(4, "little")
    tampered = raw.replace(original, (len(payload) + 7).to_bytes(4, "little"))
    assert tampered != raw
    with pytest.raises(subject.DeploymentInputsError, match="length mismatch|unsafe or malformed"):
        subject._inspect_zip_archive(tampered)


def test_archive_bombs_are_rejected_before_allocation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subject, "MAX_ARCHIVE_RATIO", 2)
    ratio_bomb = _zip_bytes({"zeros.bin": b"\x00" * 4096}, compress=zipfile.ZIP_DEFLATED)
    with pytest.raises(subject.DeploymentInputsError, match="ratio"):
        subject._inspect_zip_archive(ratio_bomb)

    monkeypatch.setattr(subject, "MAX_ARCHIVE_RATIO", 100)
    monkeypatch.setattr(subject, "MAX_ARCHIVE_COUNT", 1)
    with pytest.raises(subject.DeploymentInputsError, match="member count"):
        subject._inspect_zip_archive(_zip_bytes({"a": b"one", "b": b"two"}))

    monkeypatch.setattr(subject, "MAX_ARCHIVE_COUNT", 4096)
    monkeypatch.setattr(subject, "MAX_ARCHIVE_MEMBER", 4)
    with pytest.raises(subject.DeploymentInputsError, match="member exceeds"):
        subject._inspect_zip_archive(_zip_bytes({"big.bin": b"12345"}))

    monkeypatch.setattr(subject, "MAX_ARCHIVE_MEMBER", 32 * 1024 * 1024)
    monkeypatch.setattr(subject, "MAX_ARCHIVE_AGGREGATE", 6)
    with pytest.raises(subject.DeploymentInputsError, match="aggregate"):
        subject._inspect_zip_archive(_zip_bytes({"a.bin": b"1234", "b.bin": b"5678"}))

    monkeypatch.setattr(subject, "MAX_ARCHIVE_AGGREGATE", 128 * 1024 * 1024)
    monkeypatch.setattr(subject, "MAX_ARCHIVE_OUTER", 8)
    with pytest.raises(subject.DeploymentInputsError, match="outer size"):
        subject._inspect_zip_archive(_zip_bytes({"a.bin": b"12345678"}))

    monkeypatch.setattr(subject, "MAX_ARCHIVE_OUTER", 64 * 1024 * 1024)
    inner = _zip_bytes({"leaf.bin": b"leaf"})
    nested = _zip_bytes({"inner.zip": inner})
    outer = _zip_bytes({"nested.zip": nested})
    monkeypatch.setattr(subject, "MAX_ARCHIVE_DEPTH", 0)
    with pytest.raises(subject.DeploymentInputsError, match="depth"):
        subject._inspect_zip_archive(outer)


def test_archive_bomb_in_closure_is_rejected(
    closure: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, artifact, _ = closure
    monkeypatch.setattr(subject, "MAX_ARCHIVE_RATIO", 2)
    _write(repo / "server/bomb.zip", _zip_bytes({"zeros.bin": b"\x00" * 4096}, compress=zipfile.ZIP_DEFLATED))
    with pytest.raises(subject.DeploymentInputsError, match="ratio|archive"):
        _build(repo, artifact)


def test_runtime_mismatch_is_rejected(
    closure: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, artifact, _ = closure
    monkeypatch.setattr(subject.sys, "version_info", (3, 12, 0, "final", 0))
    with pytest.raises(subject.DeploymentInputsError, match="incompatible Python runtime"):
        subject._authenticate_compatible_runtime()
    with pytest.raises(subject.DeploymentInputsError, match="incompatible Python runtime"):
        _build(repo, artifact)
    monkeypatch.setattr(subject.sys, "version_info", (3, 14, 7, "final", 0))
    monkeypatch.setattr(subject.sys.implementation, "name", "pypy")
    with pytest.raises(subject.DeploymentInputsError, match="incompatible Python runtime"):
        subject._authenticate_compatible_runtime()


def test_boolean_input_bytes_and_mode_are_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, _, manifest, record = _create(closure)
    record["inputs"][0]["bytes"] = True
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="byte count"):
        subject.verify_manifest(repo, manifest)


def test_boolean_publication_authorized_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, _, manifest, record = _create(closure)
    record["publication_authorized"] = 0
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="policy fields"):
        subject.verify_manifest(repo, manifest)


def test_boolean_gateway_entry_is_rejected(closure: tuple[Path, Path, Path]) -> None:
    repo, _, manifest, record = _create(closure)
    record["gateway_artifact"]["entry"] = True
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="exact integer"):
        subject.verify_manifest(repo, manifest)


@pytest.mark.parametrize("tamper", ["extra", "reorder", "gateway-divergence"])
def test_proof_client_artifact_schema_is_exact(
    closure: tuple[Path, Path, Path], tamper: str
) -> None:
    repo, _, manifest, record = _create(closure)
    if tamper == "extra":
        extra = dict(record["inputs"][0])
        extra.update(
            {
                "class": "artifact",
                "path": ".artifacts/gcp-proof/extra-linux-amd64",
            }
        )
        record["inputs"].append(extra)
        record["inputs"].sort(key=lambda item: item["path"])
    elif tamper == "reorder":
        record["proof_client_artifacts"][0], record["proof_client_artifacts"][1] = (
            record["proof_client_artifacts"][1],
            record["proof_client_artifacts"][0],
        )
    else:
        record["gateway_artifact"]["sha256"] = "f" * 64
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(
        subject.canonical_bytes(timestamp_free)
    ).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError):
        subject.verify_manifest(repo, manifest)


def test_exact_int_and_bool_helpers_reject_bool_and_nonzero() -> None:
    assert subject._exact_int(7, "sample") == 7
    with pytest.raises(subject.DeploymentInputsError, match="exact integer"):
        subject._exact_int(True, "sample")
    assert subject._exact_bool(False, False, "publication_authorized") is False
    with pytest.raises(subject.DeploymentInputsError, match="exactly False"):
        subject._exact_bool(0, False, "publication_authorized")


def test_authenticated_runtime_contract_accepts_cpython_314(
    python_runtime_receipt: Path,
) -> None:
    identity = subject._authenticate_compatible_runtime()
    assert identity["implementation"] == "cpython"
    assert identity["version_info"][:2] == (3, 14)
    receipt = identity["receipt"]
    assert receipt["executable_path"] == str(Path(sys.executable).resolve(strict=True))
    assert receipt["executable_sha256"] == subject.measure_python_runtime_identity(
        executable=Path(receipt["executable_path"]),
        archive=Path(receipt["archive_path"]),
        install_tree=Path(receipt["install_tree_path"]),
        source=Path(receipt["source_path"]),
    )["executable_sha256"]
    assert Path(receipt["archive_path"]).is_file()
    assert Path(receipt["install_tree_path"]).is_dir()
    assert Path(receipt["source_path"]).is_file()


def test_missing_python_runtime_receipt_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(subject.PYTHON_RUNTIME_RECEIPT_ENV, raising=False)
    with pytest.raises(subject.DeploymentInputsError, match="runtime receipt"):
        subject._authenticate_compatible_runtime()


def test_substituted_python_runtime_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    impostor = tmp_path / "impostor-python"
    impostor.write_bytes(b"#!/bin/sh\nexit 1\n")
    impostor.chmod(0o400)
    receipt = _write_python_runtime_receipt(tmp_path / "substituted", executable=impostor)
    monkeypatch.setenv(subject.PYTHON_RUNTIME_RECEIPT_ENV, str(receipt))
    with pytest.raises(subject.DeploymentInputsError, match="substituted"):
        subject.authenticate_local_python_runtime(receipt)


def test_stale_python_runtime_receipt_is_refused(python_runtime_receipt: Path) -> None:
    record = _load_receipt(python_runtime_receipt)
    Path(record["archive_path"]).chmod(0o600)
    Path(record["archive_path"]).write_bytes(b"stale-archive\n")
    Path(record["archive_path"]).chmod(0o400)
    with pytest.raises(subject.DeploymentInputsError, match="stale"):
        subject.authenticate_local_python_runtime(python_runtime_receipt)


def test_extra_python_runtime_receipt_fields_are_refused(
    python_runtime_receipt: Path,
) -> None:
    record = _load_receipt(python_runtime_receipt)
    record["extra"] = "nope"
    _rewrite_runtime_receipt(python_runtime_receipt, record)
    with pytest.raises(subject.DeploymentInputsError, match="schema fields"):
        subject.parse_python_runtime_receipt(python_runtime_receipt)


def test_bool_python_runtime_receipt_fields_are_refused(
    python_runtime_receipt: Path,
) -> None:
    record = _load_receipt(python_runtime_receipt)
    record["schema_version"] = True
    _rewrite_runtime_receipt(python_runtime_receipt, record)
    with pytest.raises(subject.DeploymentInputsError, match="exact integer"):
        subject.parse_python_runtime_receipt(python_runtime_receipt)


def test_wrong_type_python_runtime_receipt_fields_are_refused(
    python_runtime_receipt: Path,
) -> None:
    record = _load_receipt(python_runtime_receipt)
    record["executable_path"] = ["not", "a", "path"]
    _rewrite_runtime_receipt(python_runtime_receipt, record)
    with pytest.raises(subject.DeploymentInputsError, match="absolute path"):
        subject.parse_python_runtime_receipt(python_runtime_receipt)


def test_missing_remote_action_helper_fails_closed(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    (repo / subject.REMOTE_ACTION_HELPER_PATH).unlink()
    with pytest.raises(subject.DeploymentInputsError, match="unreadable|outside the closure"):
        _build(repo, artifact)


def test_remote_action_helper_without_contract_identity_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, artifact, _ = closure
    path = repo / subject.REMOTE_ACTION_HELPER_PATH
    path.write_bytes(b"#!/usr/bin/python3\nprint('fixture')\n")
    path.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="contract identity"):
        _build(repo, artifact)


def test_boolean_remote_action_helper_schema_version_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, manifest, record = _create(closure)
    record["remote_action_helper"]["schema_version"] = True
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="exact integer"):
        subject.verify_manifest(repo, manifest)


def test_world_writable_remote_action_helper_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, artifact, _ = closure
    path = repo / subject.REMOTE_ACTION_HELPER_PATH
    path.chmod(0o666)
    with pytest.raises(subject.DeploymentInputsError, match="world-writable"):
        _build(repo, artifact)


def test_remote_action_helper_role_substitution_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, manifest, record = _create(closure)
    record["remote_action_helper"]["required_roles"] = [
        "control",
        "data-cover",
        "data-winn3",
        "core",
    ]
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="not bound"):
        subject.verify_manifest(repo, manifest)


def test_remote_action_helper_install_path_substitution_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, manifest, record = _create(closure)
    record["remote_action_helper"]["install_path"] = "/tmp/winsvpn-gcp-proof-remote"
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="not bound"):
        subject.verify_manifest(repo, manifest)


def test_missing_attempt_broker_fails_closed(closure: tuple[Path, Path, Path]) -> None:
    repo, artifact, _ = closure
    (repo / subject.ATTEMPT_BROKER_PATH).unlink()
    with pytest.raises(subject.DeploymentInputsError, match="unreadable|outside the closure"):
        _build(repo, artifact)


def test_attempt_broker_without_contract_identity_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, artifact, _ = closure
    path = repo / subject.ATTEMPT_BROKER_PATH
    path.write_bytes(b"#!/usr/bin/python3\nprint('fixture')\n")
    path.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="contract identity"):
        _build(repo, artifact)


def test_boolean_attempt_broker_schema_version_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, manifest, record = _create(closure)
    record["attempt_broker"]["schema_version"] = True
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="exact integer"):
        subject.verify_manifest(repo, manifest)


def test_world_writable_attempt_broker_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, artifact, _ = closure
    path = repo / subject.ATTEMPT_BROKER_PATH
    path.chmod(0o666)
    with pytest.raises(subject.DeploymentInputsError, match="world-writable"):
        _build(repo, artifact)


def test_attempt_broker_role_substitution_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, manifest, record = _create(closure)
    record["attempt_broker"]["required_roles"] = ["control", "data-cover", "data-winn3"]
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="not bound"):
        subject.verify_manifest(repo, manifest)


def test_attempt_broker_install_path_substitution_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, manifest, record = _create(closure)
    record["attempt_broker"]["install_path"] = "/tmp/winsvpn-gcp-proof-attempt-broker"
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="not bound"):
        subject.verify_manifest(repo, manifest)


def test_attempt_broker_unit_and_config_substitution_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, manifest, record = _create(closure)
    record["attempt_broker"]["units"][0]["install_path"] = "/tmp/winsvpn-proof-winn3-probe.service"
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="not bound"):
        subject.verify_manifest(repo, manifest)


def test_attempt_broker_config_hash_substitution_is_rejected(
    closure: tuple[Path, Path, Path]
) -> None:
    repo, _, manifest, record = _create(closure)
    record["attempt_broker"]["configs"][0]["sha256"] = "f" * 64
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError, match="not bound"):
        subject.verify_manifest(repo, manifest)


def test_cli_refuses_caller_authored_pin_arguments(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, manifest = closure
    script = Path(subject.__file__)
    forbidden = (
        "--amneziawg-go-sha256",
        "--awg-sha256",
        "--awg-quick-artifact",
        "--xray-sha256",
        "--tag",
        "--commit",
        "--pin",
    )
    create = [
        sys.executable,
        str(script),
        "create",
        "--repo-root",
        str(repo),
        "--output",
        str(manifest),
        "--winn3-gateway-artifact",
        str(artifact),
        "--winn3-probe-artifact",
        str(_proof_artifact_args(repo, artifact)[1]),
        "--winn-ech-keygen-artifact",
        str(_proof_artifact_args(repo, artifact)[2]),
        "--amneziawg-go-artifact",
        str(_client_runtime_artifact_args(repo)[0]),
        "--awg-artifact",
        str(_client_runtime_artifact_args(repo)[1]),
        "--xray-artifact",
        str(_client_runtime_artifact_args(repo)[2]),
    ]
    for flag in forbidden:
        result = subprocess.run(
            create + [flag, "0" * 64],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode != 0
        assert "unrecognized arguments" in result.stderr


def test_cli_requires_all_client_runtime_artifacts(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, manifest = closure
    script = Path(subject.__file__)
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "create",
            "--repo-root",
            str(repo),
            "--output",
            str(manifest),
            "--winn3-gateway-artifact",
            str(artifact),
            "--winn3-probe-artifact",
            str(_proof_artifact_args(repo, artifact)[1]),
            "--winn-ech-keygen-artifact",
            str(_proof_artifact_args(repo, artifact)[2]),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "amneziawg-go-artifact" in result.stderr


def test_missing_client_runtime_product_is_rejected(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, _ = closure
    _client_runtime_artifact_args(repo)[2].unlink()
    with pytest.raises(subject.DeploymentInputsError, match="unreadable|xray"):
        _build(repo, artifact)


def test_client_runtime_cross_product_swap_is_rejected(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, _ = closure
    amnezia, awg, _xray = _client_runtime_artifact_args(repo)
    swapped = awg.read_bytes()
    amnezia.write_bytes(swapped)
    amnezia.chmod(0o755)
    with pytest.raises(
        subject.DeploymentInputsError,
        match="ambiguous|unproven|distinct",
    ):
        _build(repo, artifact)


def test_client_runtime_rename_is_rejected(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, _ = closure
    amnezia = _client_runtime_artifact_args(repo)[0]
    renamed = amnezia.with_name("amneziawg-go-linux-x64")
    amnezia.rename(renamed)
    with pytest.raises(subject.DeploymentInputsError, match="must be named"):
        subject.build_manifest(
            repo,
            *_proof_artifact_args(repo, artifact),
            renamed,
            *_client_runtime_artifact_args(repo)[1:],
        )


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_client_runtime_artifact_links_are_rejected(
    closure: tuple[Path, Path, Path], link_kind: str
) -> None:
    repo, artifact, _ = closure
    amnezia, awg, _xray = _client_runtime_artifact_args(repo)
    amnezia.unlink()
    if link_kind == "symlink":
        amnezia.symlink_to(awg.name)
    else:
        os.link(awg, amnezia)
    with pytest.raises(subject.DeploymentInputsError, match="regular file|hard-linked"):
        _build(repo, artifact)


def test_client_runtime_symlink_ancestor_is_rejected(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, _ = closure
    proof_dir = repo / ".artifacts/gcp-proof"
    moved = repo / ".artifacts/gcp-proof-real"
    proof_dir.rename(moved)
    proof_dir.symlink_to(moved.name, target_is_directory=True)
    with pytest.raises(
        subject.DeploymentInputsError,
        match="symlink|regular file|unreadable|ancestor",
    ):
        _build(repo, artifact)


def test_client_runtime_wrong_architecture_is_rejected(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, _ = closure
    amnezia = _client_runtime_artifact_args(repo)[0]
    amnezia.write_bytes(
        bytes(
            _gateway_elf(
                machine=183,
                runtime="linux-amd64",
                product="amneziawg-go",
            )
        )
    )
    amnezia.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="machine"):
        _build(repo, artifact)


def test_client_runtime_debug_elf_is_rejected(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, _ = closure
    amnezia = _client_runtime_artifact_args(repo)[0]
    amnezia.write_bytes(
        bytes(
            _gateway_elf(
                machine=62,
                runtime="linux-amd64",
                product="amneziawg-go",
                debug=True,
            )
        )
    )
    amnezia.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="debug"):
        _build(repo, artifact)


def test_unproven_client_runtime_binary_is_rejected(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, _ = closure
    amnezia = _client_runtime_artifact_args(repo)[0]
    amnezia.write_bytes(
        bytes(
            _gateway_elf(
                machine=62,
                runtime="linux-amd64",
                product="amneziawg-go",
                extra=b"unproven-bytes",
            )
        )
    )
    amnezia.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="unproven"):
        _build(repo, artifact)


def test_client_runtime_toctou_replacement_is_rejected(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, _ = closure
    amnezia = _client_runtime_artifact_args(repo)[0]
    real_fstat = subject.os.fstat
    calls = 0

    def mutating_fstat(fd: int) -> os.stat_result:
        nonlocal calls
        result = real_fstat(fd)
        if stat.S_ISREG(result.st_mode) and result.st_size == amnezia.stat().st_size:
            calls += 1
            if calls == 1:
                amnezia.write_bytes(amnezia.read_bytes() + b"\x00")
        return result

    with mock.patch.object(subject.os, "fstat", side_effect=mutating_fstat):
        with pytest.raises(subject.DeploymentInputsError, match="changed while being read"):
            subject._read_regular(
                repo,
                amnezia.relative_to(repo).as_posix(),
                subject.CLIENT_RUNTIME_CLASS,
            )


def test_client_runtime_duplicate_digest_is_rejected(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, artifact, _ = closure
    amnezia, awg, _xray = _client_runtime_artifact_args(repo)
    shared = bytes(
        _gateway_elf(
            machine=62,
            runtime="linux-amd64",
            product="amneziawg-go",
            extra=b"winsvpn.product=awg\x00shared-runtime",
        )
    )
    amnezia.write_bytes(shared)
    awg.write_bytes(shared)
    amnezia.chmod(0o755)
    awg.chmod(0o755)
    with pytest.raises(subject.DeploymentInputsError, match="ambiguous|distinct"):
        _build(repo, artifact)


def test_client_runtime_schema_rejects_reordered_products(
    closure: tuple[Path, Path, Path],
) -> None:
    repo, _, manifest, record = _create(closure)
    record["client_runtime_artifacts"][0], record["client_runtime_artifacts"][1] = (
        record["client_runtime_artifacts"][1],
        record["client_runtime_artifacts"][0],
    )
    timestamp_free = {
        key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}
    }
    record["candidate_id"] = hashlib.sha256(subject.canonical_bytes(timestamp_free)).hexdigest()
    _rewrite_manifest(manifest, record)
    with pytest.raises(subject.DeploymentInputsError):
        subject.verify_manifest(repo, manifest)
