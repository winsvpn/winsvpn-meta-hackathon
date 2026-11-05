#!/usr/bin/env python3
"""Produce or verify the exact internal Snapcraft manifest artifact."""

from __future__ import annotations

import os
import sys

if __name__ == "__main__" and not getattr(sys.flags, "isolated", 0):
    os.execv(
        sys.executable,
        [sys.executable, "-I", os.path.abspath(__file__), *sys.argv[1:]],
    )

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import secrets
import stat
import types


TARGET_ID = "linux-snap-manifest"
ARTIFACT_FORMAT = "snapcraft-yaml"
PRODUCER_PATH = "linux/packaging/snap/manifest_artifact.py"
CANONICAL_ARTIFACT_NAME = "snapcraft.yaml"
CONTRACT_MODULE_IDENTITY = "winsvpn-linux-store-manifest-contract-module-v1"
CONTRACT_MODULE_RELATIVE = "linux/packaging/store_manifest_contract.py"
REVIEWED_FLUTTER_VERSION = "3.47.6"
REVIEWED_FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"
SOURCE_FREEZE_RECEIPT_CONTRACT = "winsvpn-linux-store-source-freeze-receipt-v1"
SOURCE_FREEZE_ISSUER = "winsvpn-release-source-freeze"
SOURCE_FREEZE_RECEIPT_NAME = "STORE_SOURCE_RECEIPT.json"
EXTERNAL_TRUST_RELATIVE = "linux/packaging/STORE_SOURCE_TRUST.json"
EXTERNAL_TRUST_CONTRACT = "winsvpn-linux-store-source-toolchain-trust-v1"
EXTERNAL_TRUST_ISSUER = "winsvpn-release-source-freeze"
IDENTITY_RELATIVE = "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
MAX_BIND_BYTES = 8 * 1024 * 1024
MAX_MODULE_BYTES = 32 * 1024 * 1024
MAX_FREEZE_AGE = dt.timedelta(hours=72)
MAX_CLOCK_SKEW = dt.timedelta(minutes=5)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
        info.st_uid,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
    )


def _is_special_node(info: os.stat_result) -> bool:
    mode = info.st_mode
    return bool(
        stat.S_ISFIFO(mode)
        or stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISSOCK(mode)
    )


def _open_flags(*, directory: bool = False) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RuntimeError("contract loading requires O_NOFOLLOW and O_DIRECTORY")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _read_repo_file(repo: pathlib.Path, relative: str, max_bytes: int, label: str) -> bytes:
    posix = relative.replace("\\", "/")
    parts = tuple(part for part in posix.split("/") if part)
    if not parts or posix != "/".join(parts) or any(part in {".", ".."} for part in parts):
        raise RuntimeError(f"{label} path is not canonical")
    parent_fd = os.open(repo, _open_flags(directory=True))
    try:
        for index, part in enumerate(parts):
            is_leaf = index == len(parts) - 1
            try:
                path_info = os.lstat(part, dir_fd=parent_fd)
            except FileNotFoundError as suc:
                raise RuntimeError(f"{label} does not exist") from suc
            except OSError as suc:
                raise RuntimeError(f"{label} is unreadable") from suc
            if stat.S_ISLNK(path_info.st_mode):
                raise RuntimeError(f"{label} traverses a symbolic link")
            if _is_special_node(path_info):
                raise RuntimeError(
                    f"{label} is a FIFO or special node and is rejected before opening"
                )
            if is_leaf:
                if not stat.S_ISREG(path_info.st_mode) or path_info.st_nlink != 1:
                    raise RuntimeError(f"{label} must be a distinct regular file")
            elif not stat.S_ISDIR(path_info.st_mode):
                raise RuntimeError(f"{label} parent is not a directory")
            flags = _open_flags(directory=not is_leaf)
            try:
                child_fd = os.open(part, flags, dir_fd=parent_fd)
            except OSError as suc:
                raise RuntimeError(f"{label} is unreadable") from suc
            try:
                opened = os.fstat(child_fd)
                path_after = os.lstat(part, dir_fd=parent_fd)
            except OSError as suc:
                os.close(child_fd)
                raise RuntimeError(f"{label} is unreadable") from suc
            if _identity(opened) != _identity(path_info) or _identity(opened) != _identity(
                path_after
            ):
                os.close(child_fd)
                raise RuntimeError(f"{label} changed while it was bound")
            os.close(parent_fd)
            parent_fd = child_fd
        info = os.fstat(parent_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError(f"{label} must be a distinct regular file")
        if info.st_size <= 0 or info.st_size > max_bytes:
            raise RuntimeError(f"{label} exceeds the outer size ceiling before reading")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            block = os.read(parent_fd, min(1024 * 1024, remaining))
            if not block:
                raise RuntimeError(f"{label} ended before its declared size")
            remaining -= len(block)
            chunks.append(block)
        if os.read(parent_fd, 1):
            raise RuntimeError(f"{label} grew while it was read")
        finished = os.fstat(parent_fd)
        if _identity(info) != _identity(finished):
            raise RuntimeError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(parent_fd)


def _strict_object(payload: bytes, label: str) -> dict[str, object]:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise RuntimeError(f"{label} has a duplicate JSON key")
            document[key] = value
        return document

    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicate)
    except (UnicodeError, json.JSONDecodeError) as suc:
        raise RuntimeError(f"{label} is not valid UTF-8 JSON") from suc
    if type(document) is not dict:
        raise RuntimeError(f"{label} must be one JSON object")
    return document


def _hex64(value: object) -> bool:
    return type(value) is str and len(value) == 64 and not set(value) - set("0123456789abcdef")


def _expected_module_digest(repo: pathlib.Path, origin_payload: bytes) -> str:
    origin_digest = hashlib.sha256(origin_payload).hexdigest()
    identity = _strict_object(
        _read_repo_file(repo, IDENTITY_RELATIVE, MAX_BIND_BYTES, "release identity ruling"),
        "release identity ruling",
    )
    release = identity.get("canonical_release")
    if type(release) is not str or not release or "/" in release:
        raise RuntimeError("release identity ruling is malformed")
    freeze_relative = f".artifacts/release-freeze-{release}/{SOURCE_FREEZE_RECEIPT_NAME}"
    try:
        freeze = _strict_object(
            _read_repo_file(repo, freeze_relative, MAX_BIND_BYTES, "source-freeze receipt"),
            "source-freeze receipt",
        )
    except RuntimeError as suc:
        raise RuntimeError(
            "source-freeze receipt is required to bind the support module: "
            f"{suc}"
        ) from suc
    created = freeze.get("created_utc")
    if type(created) is not str or not created.endswith("Z"):
        raise RuntimeError("source-freeze receipt is stale or unauthenticated")
    parsed = dt.datetime.fromisoformat(created[:-1] + "+00:00").astimezone(dt.timezone.utc)
    now = dt.datetime.now(tz=dt.timezone.utc)
    if parsed > now + MAX_CLOCK_SKEW or now - parsed > MAX_FREEZE_AGE:
        raise RuntimeError("source-freeze receipt is stale or future-dated")
    try:
        trust = _strict_object(
            _read_repo_file(
                repo,
                EXTERNAL_TRUST_RELATIVE,
                MAX_BIND_BYTES,
                "externally bound source/toolchain identity",
            ),
            "externally bound source/toolchain identity",
        )
    except RuntimeError as suc:
        raise RuntimeError(
            "current externally bound source/toolchain identity is unavailable: "
            f"{suc}"
        ) from suc
    if "authenticated" in trust:
        raise RuntimeError(
            "self-asserted authenticated:true is not an externally bound "
            "source/toolchain identity"
        )
    module = freeze.get("module")
    trust_module = trust.get("module")
    if type(module) is not dict or type(trust_module) is not dict:
        raise RuntimeError("source-freeze receipt does not bind the support module")
    digest = module.get("sha256")
    path = module.get("path")
    if (
        freeze.get("contract") != SOURCE_FREEZE_RECEIPT_CONTRACT
        or freeze.get("authenticated") is not True
        or freeze.get("issuer") != SOURCE_FREEZE_ISSUER
        or trust.get("contract") != EXTERNAL_TRUST_CONTRACT
        or trust.get("issuer") != EXTERNAL_TRUST_ISSUER
        or trust.get("issuance_id") != freeze.get("issuance_id")
        or trust_module.get("sha256") != digest
        or path != CONTRACT_MODULE_RELATIVE
        or not _hex64(digest)
        or digest != origin_digest
    ):
        raise RuntimeError(
            "malicious or substituted support module is not bound to the current "
            "source-freeze receipt; calculating a digest from current bytes is not "
            "a trust anchor"
        )
    return origin_digest


def _load_authenticated_contract() -> types.ModuleType:
    producer = pathlib.Path(os.path.abspath(__file__))
    try:
        producer_info = producer.lstat()
    except OSError as suc:
        raise RuntimeError("manifest producer is unreadable") from suc
    if (
        stat.S_ISLNK(producer_info.st_mode)
        or _is_special_node(producer_info)
        or not stat.S_ISREG(producer_info.st_mode)
        or producer_info.st_nlink != 1
    ):
        raise RuntimeError("manifest producer must be a regular file")
    repo = producer.parents[3]
    origin = producer.parent.parent / "store_manifest_contract.py"
    origin_text = os.path.abspath(origin)
    if origin.name != "store_manifest_contract.py" or not origin_text.replace(
        "\\", "/"
    ).endswith("linux/packaging/store_manifest_contract.py"):
        raise RuntimeError("contract origin is not the exact packaging module")
    payload = _read_repo_file(
        repo, CONTRACT_MODULE_RELATIVE, MAX_MODULE_BYTES, "manifest support module"
    )
    digest = _expected_module_digest(repo, payload)
    if hashlib.sha256(payload).hexdigest() != digest:
        raise RuntimeError(
            "malicious or substituted support module is not bound to the current "
            "source-freeze receipt; calculating a digest from current bytes is not "
            "a trust anchor"
        )
    origin_key = hashlib.sha256(origin_text.encode("utf-8")).hexdigest()
    token = secrets.token_hex(16)
    module_name = f"_winsvpn_store_manifest_contract_{digest}_{origin_key}_{token}"
    predicted = f"_winsvpn_store_manifest_contract_{digest}_{origin_key}"
    existing = sys.modules.get(module_name)
    if existing is not None or predicted in sys.modules:
        raise RuntimeError(
            "rejecting sys.modules substitution of the private contract identity"
        )
    module = types.ModuleType(module_name)
    module.__file__ = origin_text
    module.__package__ = None
    module.__loader__ = None
    module.__spec__ = None
    module.__winsvpn_contract_sha256__ = digest
    module.__winsvpn_contract_origin__ = origin_text
    sys.modules[module_name] = module
    try:
        exec(compile(payload, origin_text, "exec"), module.__dict__, module.__dict__)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    if (
        getattr(module, "CONTRACT_MODULE_IDENTITY", None) != CONTRACT_MODULE_IDENTITY
        or getattr(module, "REVIEWED_FLUTTER_VERSION", None) != REVIEWED_FLUTTER_VERSION
        or getattr(module, "REVIEWED_FLUTTER_REVISION", None)
        != REVIEWED_FLUTTER_REVISION
        or getattr(module, "__winsvpn_contract_sha256__", None) != digest
        or os.path.abspath(getattr(module, "__file__", "")) != origin_text
        or sys.modules.get("store_manifest_contract") is module
        or sys.modules.get(predicted) is module
    ):
        sys.modules.pop(module_name, None)
        raise RuntimeError("contract module identity or origin was rejected")
    freeze_relative = None
    try:
        identity = _strict_object(
            _read_repo_file(
                repo, IDENTITY_RELATIVE, MAX_BIND_BYTES, "release identity ruling"
            ),
            "release identity ruling",
        )
        release = identity.get("canonical_release")
        if type(release) is not str or not release or "/" in release:
            raise RuntimeError("release identity ruling is malformed")
        freeze_relative = (
            f".artifacts/release-freeze-{release}/{SOURCE_FREEZE_RECEIPT_NAME}"
        )
        _read_repo_file(repo, freeze_relative, MAX_BIND_BYTES, "source-freeze receipt")
        module.assert_support_module_bound(repo, digest)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


contract = _load_authenticated_contract()


def _quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _build_script() -> str:
    return (
        "set -eu\n"
        + contract.architecture_case_script("snap")
        + contract.host_target_arch_bind_script()
        + 'flutter_sdk="$CRAFT_STAGE/flutter/bin/flutter"\n'
        + 'test -x "$flutter_sdk"\n'
        + '"$flutter_sdk" pub get --offline\n'
        + '"$flutter_sdk" build linux --release --no-pub --obfuscate '
        '--split-debug-info="$CRAFT_PART_BUILD/symbols" '
        "--extra-gen-snapshot-options=--strip\n"
        'bundle="build/linux/${flutter_arch}/release/bundle"\n'
        'install -Dm0755 "$bundle/wins_vpn" "$CRAFT_PART_INSTALL/bin/wins_vpn"\n'
        'install -Dm0755 "$bundle/winsvpn-bypass-bpf" "$CRAFT_PART_INSTALL/bin/winsvpn-bypass-bpf"\n'
        + contract.engine_stage_script("snap")
        + 'cp -a "$bundle/lib" "$CRAFT_PART_INSTALL/bin/lib"\n'
        'install -Dm0644 "$bundle/data/icudtl.dat" "$CRAFT_PART_INSTALL/bin/data/icudtl.dat"\n'
        'mkdir -p "$CRAFT_PART_INSTALL/bin/data/flutter_assets"\n'
        'cp -a "$bundle/data/flutter_assets/." "$CRAFT_PART_INSTALL/bin/data/flutter_assets/"\n'
        'install -Dm0755 "$bundle/tools/native_messaging/host/wins_bridge_host" '
        '"$CRAFT_PART_INSTALL/lib/wins-vpn/wins_bridge_host"\n'
        'install -Dm0755 "$bundle/tools/native_messaging/install_native_host.sh" '
        '"$CRAFT_PART_INSTALL/lib/wins-vpn/install_native_host.sh"\n'
        'install -Dm0644 linux/packaging/org.winsvpn.app.desktop '
        '"$CRAFT_PART_INSTALL/share/applications/org.winsvpn.app.desktop"\n'
        'install -Dm0644 linux/packaging/org.winsvpn.app.metainfo.xml '
        '"$CRAFT_PART_INSTALL/share/metainfo/org.winsvpn.app.metainfo.xml"\n'
        'install -Dm0644 web/icons/Icon-512.png '
        '"$CRAFT_PART_INSTALL/share/icons/hicolor/512x512/apps/org.winsvpn.app.png"\n'
        'mkdir -p "$CRAFT_PART_INSTALL/share/winsvpn"\n'
        'install -Dm0644 "$bundle/winn3-descriptor-ring-attestation.json" '
        '"$CRAFT_PART_INSTALL/share/winsvpn/winn3-descriptor-ring-attestation.json"\n'
        "printf '%s  snapcraft.yaml\\n' "
        "\"$(sha256sum snapcraft.yaml | awk '{print $1}')\" "
        '> "$CRAFT_PART_INSTALL/share/winsvpn/store-recipe.sha256"\n'
        '( cd "$CRAFT_PART_INSTALL" && find . -type f ! -name release-manifest.sha256 | '
        "sed 's|^./||' | LC_ALL=C sort | while IFS= read -r path; do "
        'sha256sum -- "$path"; done ) > "$CRAFT_PART_INSTALL/share/winsvpn/release-manifest.sha256"\n'
    )


def _yaml_block(script: str) -> str:
    if not script.endswith("\n"):
        raise contract.ManifestContractError("Snap override-build must be newline-terminated.")
    return "\n".join("      " + line for line in script[:-1].split("\n"))


def render_manifest(
    source_url: str,
    source_sha256: str,
    version: str,
    flutter: object,
) -> bytes:
    x64 = flutter.archives["x64"]
    arm64 = flutter.archives["arm64"]
    script = _build_script()
    contract.validate_shell(script)
    contract.validate_recipe_payload(script)
    lines = [
        "name: wins-vpn",
        "title: Win's VPN",
        "base: core26",
        f"version: {_quoted(version)}",
        "summary: Privacy-focused VPN for hostile or unstable networks",
        "description: |",
        "  Win's VPN provides Winn Protocol v3 as the primary tunnel protocol.",
        "  Winn v1 over AWG then Xray remains available only when the trusted served configuration selects that cover path.",
        "  A failed Winn v3 security check is a connection refusal, not an implicit fallback.",
        "  This manifest remains local release evidence until Store review is complete.",
        f"  {contract.CLASSIC_SNAP_UNBOUNDED}.",
        "  This recipe does not claim Snap Store approval.",
        "  Publication remains unauthorized pending a fail-closed Snap Store classic-confinement review.",
        "grade: stable",
        "confinement: classic",
        f"# {contract.CLASSIC_SNAP_UNBOUNDED};",
        "# this recipe does not claim Snap Store approval.",
        "license: LicenseRef-proprietary",
        "platforms:",
        "  amd64:",
        "  arm64:",
        "apps:",
        "  wins-vpn:",
        "    command: bin/wins_vpn",
        "    desktop: share/applications/org.winsvpn.app.desktop",
        "parts:",
        "  flutter-sdk-x64:",
        "    plugin: dump",
        f"    source: {_quoted(x64.url)}",
        "    source-type: tar",
        f"    source-checksum: sha256/{x64.sha256}",
        "    build-for: [amd64]",
        "  flutter-sdk-arm64:",
        "    plugin: dump",
        f"    source: {_quoted(arm64.url)}",
        "    source-type: tar",
        f"    source-checksum: sha256/{arm64.sha256}",
        "    build-for: [arm64]",
    ]
    lines.extend(contract.engine_source_snap_parts())
    lines.extend(
        [
            "  winsvpn:",
            f"    after: [{contract.ENGINE_SOURCE_SNAP_AFTER}]",
            "    plugin: nil",
            f"    source: {_quoted(source_url)}",
            "    source-type: tar",
            f"    source-checksum: sha256/{source_sha256}",
            "    build-packages:",
            "      - unzip",
            "      - python3",
            "      - tar",
            "      - xz-utils",
            "      - clang",
            "      - make",
            "      - binutils",
            "    override-build: |",
            _yaml_block(script),
        ]
    )
    artifact = ("\n".join(lines) + "\n").encode("utf-8")
    contract.validate_engine_source_declarations(artifact.decode("utf-8"))
    return artifact


def extract_shell(artifact_bytes: bytes) -> str:
    try:
        text = artifact_bytes.decode("utf-8")
    except UnicodeError as suc:
        raise contract.ManifestContractError("Snap manifest is not UTF-8.") from suc
    if "confinement: classic\n" not in text:
        raise contract.ManifestContractError(
            "Snap recipe must disclose classic confinement without claiming store approval."
        )
    if contract.CLASSIC_SNAP_UNBOUNDED not in text:
        raise contract.ManifestContractError(
            "Snap recipe must disclose classic confinement as unbounded host access."
        )
    if contract.CLASSIC_SNAP_NO_APPROVAL not in text:
        raise contract.ManifestContractError(
            "Snap recipe must disclose classic confinement without claiming store approval."
        )
    if contract.CLASSIC_SNAP_REVIEW not in text:
        raise contract.ManifestContractError(
            "Snap recipe must keep classic confinement behind a fail-closed review gate."
        )
    if "plugs are not granted" in text:
        raise contract.ManifestContractError(
            "Snap recipe must not claim classic confinement withholds plugs."
        )
    if (
        "\n    plugs:" in text
        or re.search(r"(?m)^(?:    )?- network-control\s*$", text) is not None
        or "--device=all" in text
    ):
        raise contract.ManifestContractError(
            "Snap recipe must not grant broad device or network-control plugs "
            "without a fail-closed store-policy gate."
        )
    contract.validate_engine_source_declarations(text)
    captured: list[str] = []
    in_override = False
    for line in text.splitlines():
        if line == "    override-build: |":
            in_override = True
            continue
        if in_override:
            if line.startswith("      "):
                captured.append(line[6:])
            elif line == "      ":
                captured.append("")
            else:
                break
    if not captured:
        raise contract.ManifestContractError("Snap override-build shell is missing.")
    script = "\n".join(captured) + "\n"
    contract.validate_recipe_payload(script)
    return script


def produce_manifest(
    repo: pathlib.Path,
    source_url: str,
    source_sha256: str,
    version: str,
    output: pathlib.Path,
    receipt: pathlib.Path,
    source_archive: pathlib.Path,
    toolchain_receipt: pathlib.Path,
) -> dict[str, object]:
    return contract.produce(
        repo=repo,
        target_id=TARGET_ID,
        artifact_format=ARTIFACT_FORMAT,
        producer_path=PRODUCER_PATH,
        source_url=source_url,
        source_sha256=source_sha256,
        source_archive=source_archive,
        toolchain_receipt=toolchain_receipt,
        version=version,
        output=output,
        receipt=receipt,
        render=render_manifest,
        extract_shell=extract_shell,
    )


def verify_receipt(
    repo: pathlib.Path,
    receipt: pathlib.Path,
    artifact: pathlib.Path,
) -> dict[str, object]:
    result = contract.verify(
        repo=repo,
        target_id=TARGET_ID,
        artifact_format=ARTIFACT_FORMAT,
        producer_path=PRODUCER_PATH,
        receipt=receipt,
        artifact=artifact,
        render=render_manifest,
        extract_shell=extract_shell,
    )
    if result.get("manifest_only") is not True or result.get("package_verified") is not False:
        raise contract.ManifestContractError(
            "Snap verification must be manifest_only and must never claim package verification."
        )
    if "bound_packages" in result:
        raise contract.ManifestContractError(
            "Snap verification must never claim package verification."
        )
    return result


def canonical_gate_verify(target_id: str, raw_path: str) -> dict[str, object]:
    if target_id != TARGET_ID:
        raise contract.ManifestContractError(
            f"unsupported exact Snap manifest target: {target_id}"
        )
    relative = pathlib.PurePosixPath(raw_path)
    if (
        not raw_path
        or "\\" in raw_path
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise contract.ManifestContractError(
            "Snap artifact must be one canonical repository-relative path."
        )
    repo = pathlib.Path(os.path.abspath(__file__)).parents[3]
    artifact = contract.secure_repo_path(
        repo, pathlib.Path(raw_path), "Snap manifest artifact", must_exist=True
    )
    if artifact.name != CANONICAL_ARTIFACT_NAME:
        raise contract.ManifestContractError(
            "Snap manifest filename does not match the exact target."
        )
    if artifact.name.endswith((".flatpak", ".snap")):
        raise contract.ManifestContractError(
            "Snap verification is manifest_only and does not accept native package filenames."
        )
    receipt = artifact.with_name(artifact.name + ".receipt.json")
    before = (artifact.lstat().st_size, artifact.lstat().st_mtime_ns, contract.sha256_file(artifact))
    result = verify_receipt(repo, receipt, artifact)
    after = (artifact.lstat().st_size, artifact.lstat().st_mtime_ns, contract.sha256_file(artifact))
    if after != before:
        raise contract.ManifestContractError(
            "Snap manifest changed during artifact-only verification."
        )
    if result.get("manifest_only") is not True:
        raise contract.ManifestContractError(
            "Snap verification must explicitly be manifest_only."
        )
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    produce_parser = subparsers.add_parser("produce")
    produce_parser.add_argument("--repo", default=".")
    produce_parser.add_argument("--source-url", required=True)
    produce_parser.add_argument("--source-sha256", required=True)
    produce_parser.add_argument("--source-archive", required=True)
    produce_parser.add_argument("--toolchain-receipt", required=True)
    produce_parser.add_argument("--version", required=True)
    produce_parser.add_argument("--output", required=True)
    produce_parser.add_argument("--receipt", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--repo", default=".")
    verify_parser.add_argument("--artifact", required=True)
    verify_parser.add_argument("--receipt", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv[:1] == ["--verify"]:
        if len(raw_argv) != 3:
            raise contract.ManifestContractError(
                "canonical cross-store usage is exactly --verify <target-id> <artifact-path>"
            )
        result = canonical_gate_verify(raw_argv[1], raw_argv[2])
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    args = _parser().parse_args(raw_argv)
    try:
        if args.command == "produce":
            result = produce_manifest(
                pathlib.Path(args.repo),
                args.source_url,
                args.source_sha256,
                args.version,
                pathlib.Path(args.output),
                pathlib.Path(args.receipt),
                pathlib.Path(args.source_archive),
                pathlib.Path(args.toolchain_receipt),
            )
        else:
            result = verify_receipt(
                pathlib.Path(args.repo),
                pathlib.Path(args.receipt),
                pathlib.Path(args.artifact),
            )
    except contract.ManifestContractError as suc:
        print(f"ERROR: {suc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (contract.ManifestContractError, RuntimeError) as suc:
        print(f"ERROR: {suc}", file=sys.stderr)
        raise SystemExit(1)
