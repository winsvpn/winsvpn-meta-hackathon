#!/usr/bin/env python3
"""Fail closed unless an AAB is structurally a Wear companion bundle.

The watch does not host a VPN. Native Winn v3 and Winn v1 AWG/Xray engines
remain on the paired phone form factor. This inspector refuses those payloads
here even if a later allowlist edit tries to bless them.

Release validation uses the exact pinned bundletool CLI to decode the merged
binary manifest. Raw substring matches are not accepted as manifest evidence.
Every ZIP member is also inventoried for native-library paths and ELF magic;
only exact path-plus-SHA-256 entries in the approved allowlist may pass.

The AAB must contain exactly one official R8 mapping member. That member is
bound to the external mapping.txt by SHA-256 of the exact decompressed bytes.
If AGP or bundletool packaging rewrites only a UTF-8 BOM or CR/LF newlines,
the documented canonical form is UTF-8 text with LF newlines and no BOM.
Any other difference, a missing or duplicate proguard.map, or a trivial
placeholder mapping fails closed.

The input is copied through a no-follow descriptor to a private temporary file
before validation. The source path must still identify the same file after the
copy. The tool never extracts bundle members, never downloads bundletool, and
never uploads anything. Java and bundletool come only from authenticated
archive/tree custody. Ambient PATH discovery is refused.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


WEAR_ROOT = Path(__file__).resolve().parents[1]
CANONICAL = WEAR_ROOT / "app/build/outputs/bundle/release/app-release.aab"
PIN_MANIFEST = Path(__file__).resolve().with_name("external_tool_pins.json")
JAVA_HOME_ENV = "WINS_RELEASE_JAVA_HOME"
OWNER_BLOCKED_BUNDLETOOL = (
    "OWNER-BLOCKED: exact latest-stable bundletool archive is absent"
)
OWNER_BLOCKED_JDK = "OWNER-BLOCKED: authenticated JDK is absent"
AMBIENT_BUNDLETOOL = (
    "ambient WINS_BUNDLETOOL_JAR is forbidden; Wear bundletool comes from archive custody"
)


class InspectionError(RuntimeError):
    pass


ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID = f"{{{ANDROID_NS}}}"
EXPECTED_PACKAGE = "org.winsvpn.app"
EXPECTED_VERSION_NAME = "1.0.16"
EXPECTED_VERSION_CODE = 3301
EXPECTED_MIN_SDK = 30
EXPECTED_TARGET_SDK = 37
PHONE_VERSION_CODE = 33
TV_VERSION_CODE = 3302
STALE_TV_PACKAGE = "org.winsvpn.app.tv"
STALE_DEBUG_PACKAGE = "com.example.wins_vpn"
EXPECTED_ACTIVITY = "org.winsvpn.app.wear.MainActivity"
PIN_CONTRACT = "winsvpn-wear-os-external-tools-v1"


def load_external_tool_pins() -> dict[str, Any]:
    try:
        payload = json.loads(PIN_MANIFEST.read_bytes().decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InspectionError(
            "OWNER-BLOCKED: Wear external-tool pin manifest is unreadable"
        ) from error
    if not isinstance(payload, dict) or payload.get("contract") != PIN_CONTRACT:
        raise InspectionError("Wear external-tool pin contract is unsupported")
    if payload.get("latest_stable") is not True:
        raise InspectionError("Wear external-tool pin is not marked latest-stable")
    bundletool = payload.get("bundletool")
    sdk = payload.get("android_sdk")
    if not isinstance(bundletool, dict) or not isinstance(sdk, dict):
        raise InspectionError("Wear external-tool pin is missing bundletool or Android SDK custody")
    version = bundletool.get("version")
    digest = bundletool.get("sha256")
    source_url = bundletool.get("source_url")
    archive_path = bundletool.get("archive_path")
    artifact = bundletool.get("artifact")
    sdk_root = sdk.get("root")
    if (
        not isinstance(version, str)
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not isinstance(source_url, str)
        or not isinstance(archive_path, str)
        or not isinstance(artifact, str)
        or not isinstance(sdk_root, str)
        or not Path(archive_path).is_absolute()
        or not Path(sdk_root).is_absolute()
        or bundletool.get("latest_stable") is not True
    ):
        raise InspectionError("Wear external-tool pin fields are malformed")
    expected_source = (
        "https://github.com/google/bundletool/releases/download/"
        f"{version}/{artifact}"
    )
    if source_url != expected_source or artifact != f"bundletool-all-{version}.jar":
        raise InspectionError(
            "bundletool source URL is not the reviewed latest-stable Google release"
        )
    payload["bundletool"] = bundletool
    payload["android_sdk"] = sdk
    return payload


def _pins() -> dict[str, Any]:
    return load_external_tool_pins()


def bundletool_pin() -> dict[str, Any]:
    return dict(_pins()["bundletool"])


BUNDLETOOL_VERSION = bundletool_pin()["version"]
BUNDLETOOL_ALL_SHA256 = bundletool_pin()["sha256"]

FORBIDDEN_VPN_ENGINE_BASENAMES = frozenset(
    {
        "amneziawg.aar",
        "libwinnengine.so",
        "libam-go.so",
        "libam.so",
        "libam-quick.so",
        "libxray.so",
    }
)
PHONE_PRIMARY_PROTOCOL = "winn-v3"
PHONE_FALLBACK_PROTOCOLS = ("awg", "xray")


def companion_protocol_contract() -> dict[str, object]:
    return {
        "executed_on": "paired-phone",
        "local_wear_inclusion": False,
        "local_tunnel": False,
        "primary": PHONE_PRIMARY_PROTOCOL,
        "fallback": list(PHONE_FALLBACK_PROTOCOLS),
        "forbidden_local_engines": sorted(FORBIDDEN_VPN_ENGINE_BASENAMES),
    }


# The Compose graphics dependency contributes only this reviewed path helper.
# Any dependency or toolchain change must reproduce these exact path-plus-hash
# entries or fail closed. Phone VPN engines are refused by basename before the
# allowlist is consulted, including libwinnengine.so, libam-go.so, libxray.so,
# and amneziawg.aar.
APPROVED_NATIVE_LIBRARIES: dict[str, str] = {
    "base/lib/arm64-v8a/libandroidx.graphics.path.so":
        "41e9a793c43a0f4fddb19e33f346bace464f30f888ba7b9eaf96294ea115bfb6",
    "base/lib/armeabi-v7a/libandroidx.graphics.path.so":
        "41399eba6fc2a60f6f14642375c1824f3cf25eb8fec7397d753730a3ceda3e2b",
    "base/lib/x86/libandroidx.graphics.path.so":
        "eb0570b41fd3bff25d8204a967c03bd7550719e768b791f680cc40cbe35f29af",
    "base/lib/x86_64/libandroidx.graphics.path.so":
        "4e56c996f13670e70082658de7880c4020eabf4f25e43387f88ed78a713fc9f0",
}


OFFICIAL_PROGUARD_MAP = "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map"
MIN_R8_MAPPING_BYTES = 2048
MIN_R8_CLASS_MAPPINGS = 32
R8_CLASS_MAPPING_RE = re.compile(r"^[^\s#].* -> .+:\s*$", re.MULTILINE)
CANONICALIZATION_IDENTITY = "identity"
CANONICALIZATION_UTF8_LF = "utf-8-lf"


def canonicalize_r8_mapping_bytes(data: bytes) -> bytes:
    """Return the documented UTF-8 LF canonical form of an R8 mapping.

    AGP copies mapping.txt into BUNDLE-METADATA as proguard.map. The compared
    payload is the ZIP member's decompressed bytes. Those bytes are matched
    exactly when possible. If packaging rewrites only a UTF-8 BOM or CR/LF
    newlines, this canonical form is UTF-8 text with LF newlines and no BOM.
    Any other difference is a binding failure.
    """
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    text = data.decode("utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _r8_mapping_body(canonical_text: str) -> tuple[str, str]:
    line_end = -1
    compiler_r8 = False
    while True:
        line_start = line_end + 1
        line_end = canonical_text.find("\n", line_start)
        if line_end < 0:
            raise InspectionError("R8 mapping is missing pg_map_hash")
        line = canonical_text[line_start:line_end].strip()
        if not line:
            continue
        if not line.startswith("#"):
            raise InspectionError("R8 mapping header is missing pg_map_hash")
        header_line = line[1:].strip()
        if header_line == "compiler: R8":
            compiler_r8 = True
        if not header_line.startswith("pg_map_hash"):
            continue
        sha_index = header_line.find("SHA-256 ", len("pg_map_hash"))
        if sha_index < 0:
            raise InspectionError("R8 mapping uses an unknown map hash function")
        header_hash = header_line[sha_index + len("SHA-256") :].strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", header_hash):
            raise InspectionError("R8 mapping pg_map_hash is malformed")
        body = canonical_text[line_end + 1 :]
        computed = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if computed != header_hash:
            raise InspectionError("R8 mapping pg_map_hash does not match mapping bytes")
        if not compiler_r8:
            raise InspectionError("R8 mapping header is missing compiler: R8")
        return header_hash, body


def validate_r8_mapping_bytes(data: bytes, label: str) -> dict[str, object]:
    if len(data) < MIN_R8_MAPPING_BYTES:
        raise InspectionError(f"{label} is too small to be Wear release custody")
    try:
        canonical = canonicalize_r8_mapping_bytes(data)
    except UnicodeDecodeError as error:
        raise InspectionError(f"{label} is not UTF-8") from error
    if len(canonical) < MIN_R8_MAPPING_BYTES:
        raise InspectionError(f"{label} is too small to be Wear release custody")
    header_hash, body = _r8_mapping_body(canonical.decode("utf-8"))
    class_count = len(R8_CLASS_MAPPING_RE.findall(body))
    if class_count < MIN_R8_CLASS_MAPPINGS:
        raise InspectionError(f"{label} is too trivial to be Wear release custody")
    return {
        "pg_map_hash": header_hash,
        "class_mapping_count": class_count,
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def bind_r8_mapping_bytes(external: bytes, embedded: bytes) -> dict[str, object]:
    external_info = validate_r8_mapping_bytes(external, "external R8 mapping")
    embedded_info = validate_r8_mapping_bytes(embedded, "embedded AAB proguard.map")
    external_canonical = canonicalize_r8_mapping_bytes(external)
    embedded_canonical = canonicalize_r8_mapping_bytes(embedded)
    if external_canonical != embedded_canonical:
        raise InspectionError(
            "external R8 mapping is not bound to the embedded AAB proguard.map"
        )
    exact = external == embedded
    return {
        "external_sha256": str(external_info["sha256"]),
        "external_size_bytes": int(external_info["size_bytes"]),
        "embedded_sha256": str(embedded_info["sha256"]),
        "embedded_size_bytes": int(embedded_info["size_bytes"]),
        "embedded_path": OFFICIAL_PROGUARD_MAP,
        "exact_bytes": exact,
        "canonicalization": CANONICALIZATION_IDENTITY if exact else CANONICALIZATION_UTF8_LF,
        "canonical_sha256": hashlib.sha256(external_canonical).hexdigest(),
        "bound": True,
    }


def _zip_member_basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def _forbidden_vpn_engine_names() -> set[str]:
    return {item.casefold() for item in FORBIDDEN_VPN_ENGINE_BASENAMES}


def _reject_phone_vpn_engine_members(names: list[str]) -> None:
    forbidden = _forbidden_vpn_engine_names()
    for name in names:
        basename = _zip_member_basename(name)
        if basename.casefold() in forbidden:
            raise InspectionError(
                f"Wear AAB must not include phone VPN engine {basename}"
            )


def _proguard_map_members(names: list[str]) -> list[str]:
    return [name for name in names if _zip_member_basename(name).casefold() == "proguard.map"]


def _require_official_proguard_map(archive: zipfile.ZipFile, names: list[str]) -> bytes:
    members = _proguard_map_members(names)
    if not members:
        raise InspectionError("missing release proguard.map")
    if OFFICIAL_PROGUARD_MAP not in members:
        raise InspectionError("missing release proguard.map")
    extras = [name for name in members if name != OFFICIAL_PROGUARD_MAP]
    if extras or names.count(OFFICIAL_PROGUARD_MAP) != 1:
        extra = extras[0] if extras else OFFICIAL_PROGUARD_MAP
        raise InspectionError(f"duplicate proguard.map members: {extra}")
    data = archive.read(OFFICIAL_PROGUARD_MAP)
    validate_r8_mapping_bytes(data, "embedded AAB proguard.map")
    return data


def read_embedded_proguard_map(path: Path) -> bytes:
    try:
        with zipfile.ZipFile(path) as archive:
            bad_member = archive.testzip()
            if bad_member is not None:
                raise InspectionError(f"ZIP CRC failure: {bad_member}")
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise InspectionError("AAB contains duplicate ZIP member names")
            return _require_official_proguard_map(archive, names)
    except zipfile.BadZipFile as error:
        raise InspectionError(f"not a valid ZIP archive: {error}") from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _same_identity(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )


def _copy_open_file(source_fd: int, destination_fd: int) -> None:
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            view = view[written:]


@contextmanager
def _private_staged_copy(path: Path) -> Iterator[Path]:
    source = path.expanduser()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
    except OSError as error:
        raise InspectionError(f"AAB must be a readable regular non-symlink file: {source}") from error
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise InspectionError(f"AAB must be a regular file: {source}")
        with tempfile.TemporaryDirectory(prefix="winsvpn-wear-aab-") as directory:
            stage = Path(directory) / "candidate.aab"
            destination_fd = os.open(
                stage,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                _copy_open_file(source_fd, destination_fd)
                os.fsync(destination_fd)
            finally:
                os.close(destination_fd)
            try:
                after = os.lstat(source)
            except OSError as error:
                raise InspectionError("AAB source path disappeared during private staging") from error
            if not _same_identity(before, after):
                raise InspectionError("AAB source path changed during private staging")
            yield stage
    finally:
        os.close(source_fd)


def _safe_tool_environment(java_home: str) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "JAVA_HOME": java_home,
    }


def _open_regular_executable(path: Path, label: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise InspectionError(f"{label} must be a readable regular non-symlink executable") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not (stat.S_IMODE(info.st_mode) & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
            raise InspectionError(f"{label} must be a regular executable")
    finally:
        os.close(descriptor)


def authenticated_java() -> tuple[str, str]:
    if os.environ.get("WINS_BUNDLETOOL_JAR", "").strip():
        raise InspectionError(AMBIENT_BUNDLETOOL)
    java_home = os.environ.get(JAVA_HOME_ENV, "").strip()
    if not java_home:
        raise InspectionError(OWNER_BLOCKED_JDK)
    home = Path(java_home)
    if not home.is_absolute() or home.is_symlink() or not home.is_dir():
        raise InspectionError(OWNER_BLOCKED_JDK)
    java = home / "bin" / "java"
    if java.is_symlink() or not java.is_file():
        raise InspectionError(OWNER_BLOCKED_JDK)
    _open_regular_executable(java, "authenticated JDK java")
    return str(java.resolve(strict=True)), str(home)


def _bundletool_jar() -> Path:
    if os.environ.get("WINS_BUNDLETOOL_JAR", "").strip():
        raise InspectionError(AMBIENT_BUNDLETOOL)
    pin = bundletool_pin()
    jar = Path(str(pin["archive_path"]))
    if jar.is_symlink() or not jar.is_file():
        raise InspectionError(OWNER_BLOCKED_BUNDLETOOL)
    jar = jar.resolve(strict=True)
    observed = _sha256_file(jar)
    if observed != pin["sha256"]:
        raise InspectionError(
            f"bundletool-all-{pin['version']}.jar SHA-256 does not match the reviewed pin"
        )
    return jar


def _decoded_manifest_xml(aab: Path) -> tuple[bytes, dict[str, str]]:
    java, java_home = authenticated_java()
    jar = _bundletool_jar()
    pin = bundletool_pin()
    version = subprocess.run(
        [java, "-jar", str(jar), "version"],
        capture_output=True,
        check=False,
        timeout=30,
        env=_safe_tool_environment(java_home),
    )
    if version.returncode != 0 or version.stdout.decode("ascii", errors="replace").strip() != pin["version"]:
        raise InspectionError("pinned bundletool did not report the required version")
    completed = subprocess.run(
        [
            java,
            "-jar",
            str(jar),
            "dump",
            "manifest",
            f"--bundle={aab}",
            "--module=base",
        ],
        capture_output=True,
        check=False,
        timeout=60,
        env=_safe_tool_environment(java_home),
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise InspectionError("bundletool could not decode the base merged manifest")
    return completed.stdout, {
        "decoder": "bundletool",
        "version": str(pin["version"]),
        "jar_sha256": str(pin["sha256"]),
        "source_url": str(pin["source_url"]),
    }


def _direct_children(parent: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(parent) if child.tag == name]


def _sdk_int(raw: str | None, label: str) -> int:
    if raw is None or not re.fullmatch(r"[0-9]+", raw):
        raise InspectionError(f"Wear AAB {label} is not the ruled API identity")
    value = int(raw)
    if str(value) != raw or isinstance(value, bool):
        raise InspectionError(f"Wear AAB {label} is not the ruled API identity")
    return value


def _validate_manifest(raw: bytes) -> dict[str, object]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise InspectionError(f"bundletool returned malformed manifest XML: {error}") from error
    if root.tag != "manifest":
        raise InspectionError("decoded manifest root is not <manifest>")
    package = root.get("package")
    if package == STALE_TV_PACKAGE:
        raise InspectionError("Wear AAB package belongs to a contaminated TV identity")
    if package == STALE_DEBUG_PACKAGE:
        raise InspectionError("Wear AAB package is the stale debug application ID")
    if package != EXPECTED_PACKAGE:
        raise InspectionError("decoded manifest package is not org.winsvpn.app")
    version_name = root.get(ANDROID + "versionName")
    version_code_text = root.get(ANDROID + "versionCode")
    if version_name != EXPECTED_VERSION_NAME or version_code_text is None:
        raise InspectionError(
            "Wear AAB version identity is not the canonical 1.0.16+33 watch identity"
        )
    try:
        version_code = int(version_code_text)
    except ValueError as error:
        raise InspectionError(
            "Wear AAB versionCode is not the canonical 1.0.16+33 watch identity"
        ) from error
    if str(version_code) != version_code_text or isinstance(version_code, bool):
        raise InspectionError("Wear AAB versionCode is not the canonical 1.0.16+33 watch identity")
    if version_code == PHONE_VERSION_CODE:
        raise InspectionError("Wear AAB version identity belongs to the phone target")
    if version_code == TV_VERSION_CODE:
        raise InspectionError("Wear AAB version identity belongs to the Android TV target")
    if version_code != EXPECTED_VERSION_CODE:
        raise InspectionError(
            "Wear AAB versionCode is not the canonical 1.0.16+33 watch identity"
        )

    sdk_nodes = _direct_children(root, "uses-sdk")
    if len(sdk_nodes) != 1:
        raise InspectionError("decoded manifest must declare exactly one uses-sdk")
    min_sdk = _sdk_int(sdk_nodes[0].get(ANDROID + "minSdkVersion"), "minSdkVersion")
    target_sdk = _sdk_int(
        sdk_nodes[0].get(ANDROID + "targetSdkVersion"), "targetSdkVersion"
    )
    if min_sdk != EXPECTED_MIN_SDK:
        raise InspectionError("Wear AAB minSdkVersion is not 30")
    if target_sdk != EXPECTED_TARGET_SDK:
        raise InspectionError(
            "Wear AAB targetSdkVersion is not the ruled API 37 identity"
        )

    watch_features = [
        item
        for item in _direct_children(root, "uses-feature")
        if item.get(ANDROID + "name") == "android.hardware.type.watch"
    ]
    if len(watch_features) != 1:
        raise InspectionError("decoded manifest must have one direct watch uses-feature")
    required = watch_features[0].get(ANDROID + "required", "true").casefold()
    if required not in {"true", "1", "0xffffffff"}:
        raise InspectionError("watch uses-feature must be required")

    applications = _direct_children(root, "application")
    if len(applications) != 1:
        raise InspectionError("decoded manifest must have exactly one application")
    application = applications[0]
    for attribute in ("debuggable", "testOnly"):
        value = application.get(ANDROID + attribute, "false").casefold()
        if value not in {"false", "0", "0x0"}:
            raise InspectionError(f"decoded Wear manifest sets android:{attribute}")
    standalone = [
        item
        for item in _direct_children(application, "meta-data")
        if item.get(ANDROID + "name") == "com.google.android.wearable.standalone"
    ]
    if len(standalone) != 1 or standalone[0].get(ANDROID + "value", "").casefold() != "false":
        raise InspectionError("decoded manifest must declare one non-standalone Wear companion")

    activities = [
        item
        for item in _direct_children(application, "activity")
        if item.get(ANDROID + "name") == EXPECTED_ACTIVITY
    ]
    if len(activities) != 1 or activities[0].get(ANDROID + "exported", "").casefold() != "true":
        raise InspectionError("decoded manifest must expose the reviewed Wear MainActivity")
    launcher = False
    for intent in _direct_children(activities[0], "intent-filter"):
        actions = {item.get(ANDROID + "name") for item in _direct_children(intent, "action")}
        categories = {item.get(ANDROID + "name") for item in _direct_children(intent, "category")}
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
            launcher = True
            break
    if not launcher:
        raise InspectionError("decoded Wear MainActivity lacks a MAIN/LAUNCHER intent filter")
    leanback = False
    for activity in _direct_children(application, "activity"):
        for intent in _direct_children(activity, "intent-filter"):
            categories = {
                item.get(ANDROID + "name") for item in _direct_children(intent, "category")
            }
            if "android.intent.category.LEANBACK_LAUNCHER" in categories:
                leanback = True
                break
    if leanback:
        raise InspectionError("Wear AAB must not declare LEANBACK_LAUNCHER")

    permissions = {
        item.get(ANDROID + "name") for item in _direct_children(root, "uses-permission")
    }
    if "android.permission.INTERNET" in permissions:
        raise InspectionError("decoded Wear manifest unexpectedly requests INTERNET")
    if "android.permission.QUERY_ALL_PACKAGES" in permissions:
        raise InspectionError("decoded Wear manifest unexpectedly requests QUERY_ALL_PACKAGES")
    vpn_services = [
        service
        for service in _direct_children(application, "service")
        if service.get(ANDROID + "permission") == "android.permission.BIND_VPN_SERVICE"
    ]
    if vpn_services:
        raise InspectionError("decoded Wear manifest contains a VPN service")
    return {
        "package": EXPECTED_PACKAGE,
        "version_name": EXPECTED_VERSION_NAME,
        "version_code": EXPECTED_VERSION_CODE,
        "min_sdk": EXPECTED_MIN_SDK,
        "target_sdk": EXPECTED_TARGET_SDK,
        "watch_feature_required": True,
        "standalone": False,
        "main_activity": EXPECTED_ACTIVITY,
        "launcher": True,
        "internet_permission": False,
        "vpn_service": False,
        "companion_protocol": companion_protocol_contract(),
    }


def _unsafe_member_name(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    return name.startswith(("/", "\\")) or "\\" in name or any(part in {"", ".", ".."} for part in parts)


def _native_inventory(archive: zipfile.ZipFile, names: list[str]) -> list[dict[str, str]]:
    inventory: list[dict[str, str]] = []
    for name in names:
        if name.endswith("/"):
            continue
        parts = name.split("/")
        native_path = len(parts) >= 4 and parts[-3] in {"lib", "jni"}
        with archive.open(name) as stream:
            prefix = stream.read(4)
        is_elf = prefix == b"\x7fELF"
        if not (native_path or name.casefold().endswith(".so") or is_elf):
            continue
        data = archive.read(name)
        digest = hashlib.sha256(data).hexdigest()
        inventory.append(
            {
                "path": name,
                "sha256": digest,
                "format": "ELF" if is_elf else "native-looking-non-ELF",
            }
        )
        basename = _zip_member_basename(name)
        if basename.casefold() in _forbidden_vpn_engine_names():
            raise InspectionError(
                f"Wear AAB must not include phone VPN engine {basename}"
            )
        if not is_elf:
            raise InspectionError(f"native library member is not an ELF object: {name}")
        if APPROVED_NATIVE_LIBRARIES.get(name) != digest:
            raise InspectionError(f"unapproved native or ELF payload in Wear AAB: {name}")
    observed = {item["path"] for item in inventory}
    missing = sorted(set(APPROVED_NATIVE_LIBRARIES) - observed)
    if missing:
        raise InspectionError(f"reviewed Wear native library is missing: {missing[0]}")
    return inventory


def _inspect_staged(path: Path) -> dict[str, object]:
    result: dict[str, object] = {
        "ok": False,
        "failures": [],
        "size_bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
        "has_BundleConfig.pb": False,
        "has_proguard.map": False,
        "proguard_map": None,
        "manifest": None,
        "manifest_decoder": None,
        "native_libraries": [],
        "approved_native_library_count": len(APPROVED_NATIVE_LIBRARIES),
    }
    if result["size_bytes"] < 64:
        raise InspectionError(f"too small to be an Android App Bundle: {result['size_bytes']} bytes")
    try:
        with zipfile.ZipFile(path) as archive:
            bad_member = archive.testzip()
            if bad_member is not None:
                raise InspectionError(f"ZIP CRC failure: {bad_member}")
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise InspectionError("AAB contains duplicate ZIP member names")
            folded = [name.casefold() for name in names]
            if len(folded) != len(set(folded)):
                raise InspectionError("AAB contains case-colliding ZIP member names")
            unsafe = next((name for name in names if _unsafe_member_name(name)), None)
            if unsafe is not None:
                raise InspectionError(f"AAB contains an unsafe ZIP member name: {unsafe}")
            result["has_BundleConfig.pb"] = "BundleConfig.pb" in names
            if not result["has_BundleConfig.pb"]:
                raise InspectionError("missing BundleConfig.pb")
            mapping_bytes = _require_official_proguard_map(archive, names)
            result["has_proguard.map"] = True
            result["proguard_map"] = {
                "path": OFFICIAL_PROGUARD_MAP,
                "size_bytes": len(mapping_bytes),
                "sha256": hashlib.sha256(mapping_bytes).hexdigest(),
            }
            _reject_phone_vpn_engine_members(names)
            result["native_libraries"] = _native_inventory(archive, names)
            if "base/manifest/AndroidManifest.xml" not in names:
                raise InspectionError("missing base merged manifest")
    except zipfile.BadZipFile as error:
        raise InspectionError(f"not a valid ZIP archive: {error}") from error

    decoded, decoder = _decoded_manifest_xml(path)
    manifest = _validate_manifest(decoded)
    manifest["minify_enabled"] = True
    result["manifest"] = manifest
    result["manifest_decoder"] = decoder
    result["companion_protocol"] = companion_protocol_contract()
    result["ok"] = True
    return result


def inspect(path: Path) -> dict[str, object]:
    result: dict[str, object] = {
        "path": str(path),
        "ok": False,
        "failures": [],
        "size_bytes": None,
        "sha256": None,
        "has_BundleConfig.pb": False,
        "has_proguard.map": False,
        "proguard_map": None,
        "manifest": None,
        "manifest_decoder": None,
        "native_libraries": [],
        "approved_native_library_count": len(APPROVED_NATIVE_LIBRARIES),
    }
    try:
        with _private_staged_copy(path) as staged:
            inspected = _inspect_staged(staged)
        inspected["path"] = str(path)
        return inspected
    except (InspectionError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        result["failures"].append(str(error))
        return result


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else CANONICAL
    result = inspect(path)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
