#!/usr/bin/env python3
"""Read-only scanner for duplicate, conflicting, and floating toolchain pins.

This module never writes, never opens a network socket, and never invokes a
build, packager, signer, or deployer. It only reads files and classifies pin
hits against tools/toolchain-pins.json plus the reviewed engine pins that
manifest does not yet record (NDK, AWG, Xray).
"""

from __future__ import annotations

import ast
import json
import pathlib
import re
from dataclasses import dataclass

INDIRECT_VALUE = re.compile(r"[{}$]")

SCAN_ROOTS = (
    "tools",
    "installer",
    "linux/packaging",
    "android",
    "wear_os",
    "server",
    "router",
    "extension",
    "deploy",
    ".github/workflows",
)

SCAN_EXTENSIONS = {
    ".sh",
    ".ps1",
    ".py",
    ".yml",
    ".yaml",
    ".kts",
    ".properties",
    ".pin",
    ".iss",
    ".jsonc",
    ".linux-desktop",
}

SKIP_DIR_NAMES = {
    ".git",
    "__pycache__",
    ".staging",
    "node_modules",
    ".dart_tool",
    "jniLibs",
    "Pods",
    "build",
    ".artifacts",
    ".gradle",
    "tests",
    "test",
    "__tests__",
    "androidTest",
}

SKIP_PATH_PREFIXES = (
    "docs/",
    "winn_protocol_experimental/",
    "staging-hub/",
    "website/",
    "brand/",
    "deploy/audit/",
)

SKIP_FILE_NAMES = {
    "toolchain-pins.json",
    "toolchain_pin_scan.py",
    "test_toolchain_pin_consistency.py",
}

# Reviewed engine pins that are not fields of tools/toolchain-pins.json.
# Producers must agree with these exact values until the manifest grows them.
ENGINE_PINS = {
    "ndk": {"version": "30.0.16248370"},
    "awg": {
        "engine_version": "v3.1.20260828",
        # The amneziawg-go commit that engine_version names.
        "engine_commit": "b5928efb6ca19f0153958460c3d141f04abc5c2e",
        "tools_version": "v3.1.20260812",
        # Official amneziawg-android wrapper tag. It no longer shares a tag
        # string with the amneziawg-go engine.
        "android_wrapper_tag": "v3.1.20260814",
    },
    "xray": {
        "version": "26.9.30",
        "tag": "v26.9.30",
        "commit": "b26a91de4f3294e26a0ad0a970b81a386a41f789",
    },
}

GO_SYMBOLS = (
    "GO_VERSION",
    "REQUIRED_GO_VERSION",
    "REVIEWED_GO_VERSION",
    "EXPECTED_GO_VERSION",
    "APPLE_AWG_EXPECTED_GO_VERSION",
    "WINDOWS_REVIEWED_GO_VERSION",
    "XRAY_ENGINE_REVIEWED_GO_VERSION",
    "AMNEZIAWG_ANDROID_ENGINE_REVIEWED_GO_VERSION",
    "RequiredGoVersion",
    "ExpectedGoVersion",
    "goVersion",
)

PYTHON_SYMBOLS = (
    "PYTHON_VERSION",
    "REQUIRED_PYTHON_VERSION",
    "REVIEWED_PYTHON_VERSION",
    "RequiredPythonVersion",
)

FLUTTER_VERSION_SYMBOLS = (
    "REQUIRED_FLUTTER_VERSION",
    "REVIEWED_FLUTTER_VERSION",
    "FLUTTER_VERSION",
    "RequiredFlutterVersion",
    "ExpectedFlutterVersion",
)

FLUTTER_REVISION_SYMBOLS = (
    "REQUIRED_FLUTTER_REVISION",
    "REVIEWED_FLUTTER_REVISION",
    "FLUTTER_REVISION",
    "RequiredFlutterRevision",
    "ExpectedFlutterRevision",
)

DART_SYMBOLS = (
    "REQUIRED_DART_VERSION",
    "REVIEWED_DART_VERSION",
    "DART_VERSION",
    "RequiredDartVersion",
)

NODE_SYMBOLS = (
    "NODE_VERSION",
    "REQUIRED_NODE_VERSION",
    "REVIEWED_NODE_VERSION",
    "RequiredNodeVersion",
)

OPENSSL_SYMBOLS = (
    "OPENSSL_VERSION",
    "REQUIRED_OPENSSL_VERSION",
    "REVIEWED_OPENSSL_VERSION",
)

BROWSER_SYMBOLS = (
    "CHROME_VERSION",
    "BROWSER_VERSION",
    "REQUIRED_BROWSER_VERSION",
    "REVIEWED_BROWSER_VERSION",
    "WINS_RELEASE_BROWSER_VERSION",
)

JAVA_SYMBOLS = (
    "JAVA_VERSION",
    "JDK_VERSION",
    "REQUIRED_JAVA_VERSION",
    "REVIEWED_JAVA_VERSION",
    "RequiredJavaVersion",
)

NDK_SYMBOLS = (
    "REVIEWED_NDK_VERSION",
    "REQUIRED_NDK_VERSION",
    "NDK_VERSION",
    "RequiredNdkVersion",
)

AWG_ENGINE_SYMBOLS = (
    "AWG_GO_VERSION",
    "AWG_GO_TAG",
    "APPLE_AWG_EXPECTED_TAG",
)

AWG_ENGINE_COMMIT_SYMBOLS = (
    "AWG_GO_COMMIT",
    "APPLE_AWG_EXPECTED_COMMIT",
)

AWG_ANDROID_WRAPPER_SYMBOLS = ("AWG_ANDROID_TAG",)

AWG_TOOLS_SYMBOLS = ("AWG_TOOLS_VERSION",)

XRAY_VERSION_SYMBOLS = (
    "XRAY_VERSION",
    "XRAY_VERSION_DEFAULT",
    "REVIEWED_XRAY_VERSION",
)

XRAY_TAG_SYMBOLS = ("XRAY_TAG",)

XRAY_COMMIT_SYMBOLS = ("XRAY_COMMIT",)

PLUGIN_TO_PIN = {
    "com.android.application": ("android_gradle_plugin", "version"),
    "org.jetbrains.kotlin.android": ("kotlin", "version"),
    "org.jetbrains.kotlin.plugin.compose": ("kotlin", "version"),
}

# Exact generated or provenance mirrors. Unmapped JSON pin copies are defects.
MIRROR_MAPPINGS = (
    {
        "path": "tools/android-toolchain-custody.json",
        "tool": "flutter",
        "field": "version",
        "kind": "json",
        "pointer": "platforms.darwin_arm64.flutter.version",
    },
    {
        "path": "tools/android-toolchain-custody.json",
        "tool": "flutter",
        "field": "revision",
        "kind": "json",
        "pointer": "platforms.darwin_arm64.flutter.revision",
    },
    {
        "path": "tools/android-toolchain-custody.json",
        "tool": "flutter",
        "field": "dart_version",
        "kind": "json",
        "pointer": "platforms.darwin_arm64.flutter.dart_version",
    },
    {
        "path": "tools/android-toolchain-custody.json",
        "tool": "java",
        "field": "version",
        "kind": "json",
        "pointer": "platforms.darwin_arm64.java.version",
    },
    {
        "path": "apple/EngineArtifacts/apple_awg_31_engine_provenance.json",
        "tool": "go",
        "field": "version",
        "kind": "json",
        "pointer": "go_toolchain.version",
    },
    {
        "path": "apple/EngineArtifacts/apple_awg_31_engine_provenance.json",
        "tool": "go",
        "field": "archive_sha256.darwin_arm64",
        "kind": "json",
        "pointer": "go_toolchain.darwin_arm64_archive_sha256",
    },
    {
        "path": "apple/EngineArtifacts/apple_awg_31_engine_provenance.json",
        "tool": "awg",
        "field": "engine_version",
        "kind": "json",
        "pointer": "source.tag",
    },
    {
        "path": "installer/windows/dependencies/amneziawg.exe.provenance.json",
        "tool": "go",
        "field": "version",
        "kind": "json",
        "pointer": "go_version",
    },
    {
        "path": "installer/windows/dependencies/amneziawg.exe.provenance.json",
        "tool": "awg",
        "field": "engine_version",
        "kind": "json",
        "pointer": "engine_version",
    },
    {
        "path": "installer/windows/dependencies/amneziawg.exe.provenance.json",
        "tool": "go",
        "field": "archive_sha256.windows_amd64",
        "kind": "json",
        "pointer": "go_archive_sha256",
    },
    {
        "path": "android/gradle/wrapper/gradle-wrapper.properties",
        "tool": "gradle",
        "field": "distribution_version",
        "kind": "gradle_wrapper",
        "pointer": "version",
    },
    {
        "path": "android/devicecheck/gradle/wrapper/gradle-wrapper.properties",
        "tool": "gradle",
        "field": "distribution_version",
        "kind": "gradle_wrapper",
        "pointer": "version",
    },
    {
        "path": "wear_os/gradle/wrapper/gradle-wrapper.properties",
        "tool": "gradle",
        "field": "distribution_version",
        "kind": "gradle_wrapper",
        "pointer": "version",
    },
    {
        "path": "router/base-image.pin",
        "tool": "python",
        "field": "version",
        "kind": "python_image",
        "pointer": "",
    },
    {
        "path": "router/Dockerfile",
        "tool": "python",
        "field": "version",
        "kind": "python_image",
        "pointer": "",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "version",
        "kind": "python_const",
        "pointer": "OFFICIAL_VERSION",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "source_archive_name",
        "kind": "python_const",
        "pointer": "OFFICIAL_SOURCE_NAME",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "source_archive_sha256",
        "kind": "python_const",
        "pointer": "OFFICIAL_SOURCE_SHA256",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "build_configuration",
        "kind": "python_const",
        "pointer": "OFFICIAL_CONFIGURATION",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "build_transaction",
        "kind": "python_const",
        "pointer": "OFFICIAL_BUILD_TRANSACTION",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "build_receipt_env",
        "kind": "python_const",
        "pointer": "RECEIPT_ENV",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "compiler_identity.name",
        "kind": "python_const",
        "pointer": "FROZEN_COMPILER_IDENTITY.name",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "compiler_identity.path",
        "kind": "python_const",
        "pointer": "FROZEN_COMPILER_IDENTITY.path",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "compiler_identity.sha256",
        "kind": "python_const",
        "pointer": "FROZEN_COMPILER_IDENTITY.sha256",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "compiler_identity.target",
        "kind": "python_const",
        "pointer": "FROZEN_COMPILER_IDENTITY.target",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "compiler_identity.version",
        "kind": "python_const",
        "pointer": "FROZEN_COMPILER_IDENTITY.version",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "compiler_identity.version_line",
        "kind": "python_const",
        "pointer": "FROZEN_COMPILER_IDENTITY.version_line",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "compiler_identity.xcode_build",
        "kind": "python_const",
        "pointer": "FROZEN_COMPILER_IDENTITY.xcode_build",
    },
    {
        "path": "tools/release_openssl_archive_custody.py",
        "tool": "openssl",
        "field": "compiler_identity.xcode_version",
        "kind": "python_const",
        "pointer": "FROZEN_COMPILER_IDENTITY.xcode_version",
    },
)

_FLOATING_TAG = re.compile(
    r"(?i)\A(?:latest|stable|current|lts|nightly|tip|\d+\.x)\Z"
)
_FLOATING_ASSIGN = re.compile(
    r"(?i)(?<![A-Z])(?:GO|PYTHON|FLUTTER|DART|NODE|JAVA|JDK|OPENSSL|CHROME|"
    r"BROWSER|GRADLE|NDK|XRAY)_VERSION\s*=\s*[\"']?"
    r"(latest|stable|current|lts|\d+\.x)\b"
)
_FLOATING_YAML = re.compile(
    r"(?i)^\s*(?:go|python|flutter|node|java|jdk)-version:\s*[\"']?"
    r"(latest|stable|\d+\.x)",
    re.MULTILINE,
)
_FLOATING_GO_GET = re.compile(
    r"(?i)\b(?:go install|go get)\s+\S+@latest\b"
)
_FLOATING_DOCKER = re.compile(
    r"(?im)^\s*(?:FROM|image:)\s+(?:[^\s/]+/)?"
    r"(python|golang|node|eclipse-temurin|openjdk|gradle)"
    r":([^\s@]+)"
)
_RANGE_ASSIGN = re.compile(
    r"(?i)(?<![A-Z])(?:GO|PYTHON|FLUTTER|DART|NODE|JAVA|JDK|OPENSSL|CHROME|"
    r"BROWSER|GRADLE|NDK|XRAY)_VERSION\s*=\s*[\"']?(>=|<=|~=|\^|~>)"
)

_PLUGIN_RE = re.compile(r'id\("([^"]+)"\)\s+version\s+"([^"]+)"')
_NDK_GRADLE_RE = re.compile(r'\bndkVersion\s*=\s*"([^"]+)"')
_WRAPPER_URL_RE = re.compile(
    r"distributionUrl=.*?gradle-(?P<version>[\d.]+)-(?P<flavour>all|bin)\.zip"
)
_WRAPPER_HASH_RE = re.compile(
    r"distributionSha256Sum=(?P<sha256>[0-9a-f]{64})"
)
_PYTHON_IMAGE_RE = re.compile(r"(?i)(?:^|\s)(?:FROM\s+)?python:(\d+\.\d+\.\d+)")
_DOCKER_PYTHON_RE = re.compile(
    r"(?i)(?:^|\s)(?:FROM|image:)\s+(?:[^\s/]+/)?python:(\d+\.\d+(?:\.\d+)?)"
)
_DOCKER_GOLANG_RE = re.compile(
    r"(?i)(?:^|\s)(?:FROM|image:)\s+(?:[^\s/]+/)?golang:(\d+\.\d+(?:\.\d+)?)"
)
_DOCKER_NODE_RE = re.compile(
    r"(?i)(?:^|\s)(?:FROM|image:)\s+(?:[^\s/]+/)?node:v?(\d+(?:\.\d+){0,2})"
)
_GO_ARCHIVE_RE = re.compile(r"go(\d+\.\d+\.\d+)\.(?:linux|windows|darwin)-")
_FLUTTER_ARCHIVE_RE = re.compile(
    r"flutter_(?:macos|linux|windows)_[^\"'\s]*_(\d+\.\d+\.\d+)-"
)
_FLUTTER_EXTRACT_RE = re.compile(r"flutter-(\d+\.\d+\.\d+)-extract")
_PYTHON_ARCHIVE_RE = re.compile(r"python-(\d+\.\d+\.\d+)-")
_NODE_ARCHIVE_RE = re.compile(r"node-v(\d+\.\d+\.\d+)-")
_OPENSSL_ARCHIVE_RE = re.compile(r"openssl-(\d+\.\d+\.\d+)")
_GRADLE_ZIP_RE = re.compile(r"gradle-(\d+\.\d+\.\d+)-(?:all|bin)\.zip")
_CHROME_ARCHIVE_RE = re.compile(r"chrome-[^\"'\s]*-(\d+\.\d+\.\d+\.\d+)")
_JDK_ARCHIVE_RE = re.compile(
    r"OpenJDK\d+U-jdk_[^\"'\s]*_(\d+\.\d+\.\d+(?:\.\d+)?)_"
)
_YAML_FLUTTER_RE = re.compile(
    r'^\s*flutter-version:\s*"([^"]+)"', re.MULTILINE
)
_REJECTED_PIN_LINE = re.compile(
    r"(?i)\bold(?:go|pin|version|archive)|retired|superseded|previous.?pin"
)


def _symbol_assign_re(symbols: tuple[str, ...]) -> re.Pattern[str]:
    alt = "|".join(sorted((re.escape(s) for s in symbols), key=len, reverse=True))
    return re.compile(
        rf"(?:^|[\s;])(?:export\s+|local\s+|readonly\s+|ARG\s+)?\$?({alt})\s*=\s*[\"']([^\"']*)[\"']",
        re.MULTILINE,
    )


_ASSIGN_SPECS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("go", "version", _symbol_assign_re(GO_SYMBOLS)),
    ("python", "version", _symbol_assign_re(PYTHON_SYMBOLS)),
    ("flutter", "version", _symbol_assign_re(FLUTTER_VERSION_SYMBOLS)),
    ("flutter", "revision", _symbol_assign_re(FLUTTER_REVISION_SYMBOLS)),
    ("flutter", "dart_version", _symbol_assign_re(DART_SYMBOLS)),
    ("node", "version", _symbol_assign_re(NODE_SYMBOLS)),
    ("openssl", "version", _symbol_assign_re(OPENSSL_SYMBOLS)),
    ("browser", "version", _symbol_assign_re(BROWSER_SYMBOLS)),
    ("java", "version", _symbol_assign_re(JAVA_SYMBOLS)),
    ("ndk", "version", _symbol_assign_re(NDK_SYMBOLS)),
    ("awg", "engine_version", _symbol_assign_re(AWG_ENGINE_SYMBOLS)),
    ("awg", "engine_commit", _symbol_assign_re(AWG_ENGINE_COMMIT_SYMBOLS)),
    ("awg", "tools_version", _symbol_assign_re(AWG_TOOLS_SYMBOLS)),
    ("awg", "android_wrapper_tag", _symbol_assign_re(AWG_ANDROID_WRAPPER_SYMBOLS)),
    ("xray", "version", _symbol_assign_re(XRAY_VERSION_SYMBOLS)),
    ("xray", "tag", _symbol_assign_re(XRAY_TAG_SYMBOLS)),
    ("xray", "commit", _symbol_assign_re(XRAY_COMMIT_SYMBOLS)),
)


@dataclass(frozen=True)
class PinHit:
    path: str
    tool: str
    field: str
    value: str
    kind: str
    symbol: str
    mapped: bool
    canonical: str
    conflict: bool

    def describe(self) -> str:
        state = "conflict" if self.conflict else "match"
        mapped = "mapped" if self.mapped else "unmapped"
        return (
            f"{self.path} :: {self.tool}.{self.field} {self.kind} "
            f"{self.symbol}={self.value!r} canonical={self.canonical!r} "
            f"{state} {mapped}"
        )


@dataclass(frozen=True)
class FloatingHit:
    path: str
    selector: str
    snippet: str

    def describe(self) -> str:
        return f"{self.path} :: floating {self.selector!r} ({self.snippet})"


@dataclass(frozen=True)
class ScanReport:
    hits: tuple[PinHit, ...]
    floating: tuple[FloatingHit, ...]
    unmapped_mirrors: tuple[str, ...]
    missing_mappings: tuple[str, ...]

    @property
    def conflicts(self) -> tuple[PinHit, ...]:
        return tuple(hit for hit in self.hits if hit.conflict)


def canonical_pins(manifest: dict) -> dict[str, dict[str, str]]:
    """Flatten toolchain-pins.json plus reviewed engine pins into comparables."""
    tools = manifest["tools"]
    openssl = tools["openssl"]
    openssl_compiler = openssl["compiler_identity"]
    pins: dict[str, dict[str, str]] = {
        "go": {
            "version": str(tools["go"]["version"]),
            "archive_sha256.darwin_arm64": str(
                tools["go"]["archive_sha256"]["darwin_arm64"]
            ),
            "archive_sha256.windows_amd64": str(
                tools["go"]["archive_sha256"]["windows_amd64"]
            ),
        },
        "python": {"version": str(tools["python"]["version"])},
        "flutter": {
            "version": str(tools["flutter"]["version"]),
            "revision": str(tools["flutter"]["revision"]),
            "dart_version": str(tools["flutter"]["dart_version"]),
        },
        "node": {"version": str(tools["node"]["version"])},
        "openssl": {
            "version": str(openssl["version"]),
            "source_archive_name": str(openssl["source_archive_name"]),
            "source_archive_sha256": str(openssl["source_archive_sha256"]),
            "build_configuration": str(openssl["build_configuration"]),
            "build_transaction": str(openssl["build_transaction"]),
            "build_receipt_env": str(openssl["build_receipt_env"]),
            "compiler_identity.name": str(openssl_compiler["name"]),
            "compiler_identity.path": str(openssl_compiler["path"]),
            "compiler_identity.sha256": str(openssl_compiler["sha256"]),
            "compiler_identity.target": str(openssl_compiler["target"]),
            "compiler_identity.version": str(openssl_compiler["version"]),
            "compiler_identity.version_line": str(openssl_compiler["version_line"]),
            "compiler_identity.xcode_build": str(openssl_compiler["xcode_build"]),
            "compiler_identity.xcode_version": str(openssl_compiler["xcode_version"]),
        },
        "browser": {"version": str(tools["browser"]["version"])},
        "java": {"version": str(tools["java"]["version"])},
        "gradle": {
            "distribution_version": str(tools["gradle"]["distribution_version"]),
            "sha256.all": str(
                tools["gradle"]["distribution_sha256_by_flavour"]["all"]
            ),
            "sha256.bin": str(
                tools["gradle"]["distribution_sha256_by_flavour"]["bin"]
            ),
        },
        "android_gradle_plugin": {
            "version": str(tools["android_gradle_plugin"]["version"])
        },
        "kotlin": {"version": str(tools["kotlin"]["version"])},
        "ndk": dict(ENGINE_PINS["ndk"]),
        "awg": dict(ENGINE_PINS["awg"]),
        "xray": dict(ENGINE_PINS["xray"]),
    }
    return pins


def normalize_pin(tool: str, field: str, value: str) -> str:
    text = value.strip()
    if not text or INDIRECT_VALUE.search(text):
        return ""
    if tool == "go" and field == "version":
        if text.startswith("go") and text[2:3].isdigit():
            text = text[2:]
        return text
    if tool == "node" and field == "version":
        return text[1:] if text.startswith("v") and text[1:2].isdigit() else text
    if tool == "xray" and field in {"version", "tag"}:
        return text[1:] if text.startswith("v") else text
    if tool == "awg" and field == "engine_version" and text[:1].isdigit():
        return "v" + text
    return text


def pins_equal(tool: str, field: str, actual: str, canonical: str) -> bool:
    left = normalize_pin(tool, field, actual)
    right = normalize_pin(tool, field, canonical)
    if not left or not right:
        return True
    return left == right


def path_role(relative: str) -> str:
    rel = relative.replace("\\", "/")
    if rel.startswith("/") or rel.startswith("../") or "/../" in rel:
        return "skip"
    name = pathlib.PurePosixPath(rel).name
    if name in SKIP_FILE_NAMES:
        return "skip"
    if rel == "tools/toolchain-pins.json":
        return "skip"
    lowered = rel.lower()
    for prefix in SKIP_PATH_PREFIXES:
        if rel.startswith(prefix):
            return "docs" if prefix == "docs/" else "skip"
    parts = pathlib.PurePosixPath(rel).parts
    if any(part in SKIP_DIR_NAMES for part in parts):
        return "test" if any(part in {"tests", "test", "__tests__", "androidTest"} for part in parts) else "skip"
    if name.startswith("test_") or name.endswith("_test.py") or name.endswith("_test.go"):
        return "test"
    if name.endswith("Tests.swift") or name.endswith("Test.kt") or name.endswith("Tests.kt"):
        return "test"
    if "/docs/" in f"/{rel}/" or rel.startswith("docs/"):
        return "docs"
    return "authoritative"


def is_authoritative_path(relative: str) -> bool:
    return path_role(relative) == "authoritative"


def _mapping_key(path: str, tool: str, field: str) -> tuple[str, str, str]:
    return (path.replace("\\", "/"), tool, field)


_MAPPED_KEYS = frozenset(
    _mapping_key(str(item["path"]), str(item["tool"]), str(item["field"]))
    for item in MIRROR_MAPPINGS
)
_MAPPED_PATHS = frozenset(str(item["path"]) for item in MIRROR_MAPPINGS)


def _json_pointer(document: object, pointer: str) -> object:
    current: object = document
    for part in pointer.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _python_const_value(text: str, pointer: str) -> str | None:
    """Read one frozen Python assignment used as an exact pin mirror."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    binds: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        try:
            binds[target.id] = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            continue
    name, _, key = pointer.partition(".")
    current = binds.get(name)
    if key:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    if not isinstance(current, str) or not current:
        return None
    return current


def _strip_full_line_comments(relative: str, text: str) -> str:
    suffix = pathlib.PurePosixPath(relative).suffix.lower()
    prefixes = {
        ".py": "#",
        ".sh": "#",
        ".ps1": "#",
        ".yml": "#",
        ".yaml": "#",
        ".pin": "#",
        ".properties": "#",
        ".kts": "//",
    }
    mark = prefixes.get(suffix)
    if not mark:
        return text
    kept: list[str] = []
    for line in text.splitlines():
        if line.lstrip().startswith(mark):
            continue
        kept.append(line)
    return "\n".join(kept)


def _containing_line(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    prev = text.rfind("\n", 0, start - 1) + 1 if start > 0 else 0
    end = text.find("\n", index)
    if end < 0:
        end = len(text)
    return text[prev:end]


def _hit(
    *,
    path: str,
    tool: str,
    field: str,
    value: str,
    kind: str,
    symbol: str,
    canonical: dict[str, dict[str, str]],
) -> PinHit | None:
    wanted = canonical.get(tool, {}).get(field, "")
    normalized = normalize_pin(tool, field, value)
    if not normalized:
        return None
    mapped = _mapping_key(path, tool, field) in _MAPPED_KEYS
    conflict = bool(wanted) and not pins_equal(tool, field, value, wanted)
    return PinHit(
        path=path,
        tool=tool,
        field=field,
        value=normalized,
        kind=kind,
        symbol=symbol,
        mapped=mapped,
        canonical=wanted,
        conflict=conflict,
    )


def scan_text(
    relative: str,
    text: str,
    canonical: dict[str, dict[str, str]],
) -> list[PinHit]:
    """Classify pin literals in one file. Docs and tests return no hits."""
    if path_role(relative) != "authoritative":
        return []
    rel = relative.replace("\\", "/")
    body = _strip_full_line_comments(rel, text)
    found: list[PinHit] = []

    def add(hit: PinHit | None) -> None:
        if hit is not None:
            found.append(hit)

    for tool, field, pattern in _ASSIGN_SPECS:
        for match in pattern.finditer(body):
            add(
                _hit(
                    path=rel,
                    tool=tool,
                    field=field,
                    value=match.group(2),
                    kind="assignment",
                    symbol=match.group(1),
                    canonical=canonical,
                )
            )

    for match in _YAML_FLUTTER_RE.finditer(body):
        add(
            _hit(
                path=rel,
                tool="flutter",
                field="version",
                value=match.group(1),
                kind="yaml_key",
                symbol="flutter-version",
                canonical=canonical,
            )
        )

    for match in _NDK_GRADLE_RE.finditer(body):
        add(
            _hit(
                path=rel,
                tool="ndk",
                field="version",
                value=match.group(1),
                kind="ndk_gradle",
                symbol="ndkVersion",
                canonical=canonical,
            )
        )

    for match in _PLUGIN_RE.finditer(body):
        plugin = match.group(1)
        mapped_pin = PLUGIN_TO_PIN.get(plugin)
        if mapped_pin is None:
            continue
        tool, field = mapped_pin
        add(
            _hit(
                path=rel,
                tool=tool,
                field=field,
                value=match.group(2),
                kind="gradle_plugin",
                symbol=plugin,
                canonical=canonical,
            )
        )

    wrapper_url = _WRAPPER_URL_RE.search(body)
    if wrapper_url is not None:
        add(
            _hit(
                path=rel,
                tool="gradle",
                field="distribution_version",
                value=wrapper_url.group("version"),
                kind="gradle_wrapper",
                symbol="distributionUrl",
                canonical=canonical,
            )
        )
        flavour = wrapper_url.group("flavour")
        hash_match = _WRAPPER_HASH_RE.search(body)
        if hash_match is not None:
            add(
                _hit(
                    path=rel,
                    tool="gradle",
                    field=f"sha256.{flavour}",
                    value=hash_match.group("sha256"),
                    kind="gradle_wrapper",
                    symbol="distributionSha256Sum",
                    canonical=canonical,
                )
            )

    for match in _PYTHON_IMAGE_RE.finditer(body):
        add(
            _hit(
                path=rel,
                tool="python",
                field="version",
                value=match.group(1),
                kind="python_image",
                symbol="python",
                canonical=canonical,
            )
        )
    for match in _DOCKER_PYTHON_RE.finditer(body):
        add(
            _hit(
                path=rel,
                tool="python",
                field="version",
                value=match.group(1),
                kind="docker_from",
                symbol="python",
                canonical=canonical,
            )
        )
    for match in _DOCKER_GOLANG_RE.finditer(body):
        add(
            _hit(
                path=rel,
                tool="go",
                field="version",
                value=match.group(1),
                kind="docker_from",
                symbol="golang",
                canonical=canonical,
            )
        )
    for match in _DOCKER_NODE_RE.finditer(body):
        add(
            _hit(
                path=rel,
                tool="node",
                field="version",
                value=match.group(1),
                kind="docker_from",
                symbol="node",
                canonical=canonical,
            )
        )

    hidden = (
        ("go", "version", "url_token", "go-archive", _GO_ARCHIVE_RE),
        ("flutter", "version", "url_token", "flutter-archive", _FLUTTER_ARCHIVE_RE),
        ("flutter", "version", "path_token", "flutter-extract-dir", _FLUTTER_EXTRACT_RE),
        ("python", "version", "url_token", "python-archive", _PYTHON_ARCHIVE_RE),
        ("node", "version", "url_token", "node-archive", _NODE_ARCHIVE_RE),
        ("openssl", "version", "url_token", "openssl-archive", _OPENSSL_ARCHIVE_RE),
        ("browser", "version", "url_token", "chrome-archive", _CHROME_ARCHIVE_RE),
        ("java", "version", "url_token", "jdk-archive", _JDK_ARCHIVE_RE),
    )
    if rel.endswith("gradle-wrapper.properties"):
        hidden = hidden + (
            ("gradle", "distribution_version", "url_token", "gradle-zip", _GRADLE_ZIP_RE),
        )
    for tool, field, kind, symbol, pattern in hidden:
        for match in pattern.finditer(body):
            line = _containing_line(body, match.start())
            if _REJECTED_PIN_LINE.search(line):
                continue
            add(
                _hit(
                    path=rel,
                    tool=tool,
                    field=field,
                    value=match.group(1),
                    kind=kind,
                    symbol=symbol,
                    canonical=canonical,
                )
            )
    return found


def scan_floating(relative: str, text: str) -> list[FloatingHit]:
    if path_role(relative) != "authoritative":
        return []
    rel = relative.replace("\\", "/")
    body = _strip_full_line_comments(rel, text)
    hits: list[FloatingHit] = []

    def add(selector: str, snippet: str) -> None:
        hits.append(FloatingHit(path=rel, selector=selector, snippet=snippet.strip()[:120]))

    for match in _FLOATING_ASSIGN.finditer(body):
        add(match.group(1), match.group(0))
    for match in _FLOATING_YAML.finditer(body):
        add(match.group(1), match.group(0))
    for match in _FLOATING_GO_GET.finditer(body):
        add("@latest", match.group(0))
    for match in _RANGE_ASSIGN.finditer(body):
        add(match.group(1), match.group(0))
    for match in _FLOATING_DOCKER.finditer(body):
        image = match.group(1).lower()
        tag = match.group(2) or "latest"
        version = tag.split("-", 1)[0]
        if _FLOATING_TAG.match(version) or version.count(".") < 2:
            add(f"{image}:{tag}", match.group(0).strip())
    return hits


def _is_provenance_json(relative: str) -> bool:
    name = pathlib.PurePosixPath(relative).name.lower()
    if not name.endswith(".json"):
        return False
    if "trust" in name:
        return False
    return "provenance" in name or "custody" in name


def _unmapped_json_fields(relative: str, document: object) -> list[str]:
    """Return pin-shaped JSON fields that are not on the explicit allowlist."""
    if not isinstance(document, dict):
        return []
    found: list[str] = []

    def walk(node: object, prefix: str) -> None:
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            pointer = f"{prefix}.{key}" if prefix else str(key)
            if key in {"go_version", "version"} and isinstance(value, str):
                parent = prefix.rsplit(".", 1)[-1] if prefix else ""
                if key == "go_version" or parent in {
                    "go_toolchain",
                    "go",
                    "flutter",
                    "java",
                    "python",
                    "node",
                    "openssl",
                    "browser",
                    "gradle",
                    "ndk",
                    "xray",
                }:
                    found.append(pointer)
            if key in {"engine_version", "ndk_version", "dart_version"} and isinstance(value, str):
                found.append(pointer)
            if isinstance(value, dict):
                walk(value, pointer)

    walk(document, "")
    mapped_pointers = {
        str(item["pointer"])
        for item in MIRROR_MAPPINGS
        if item["path"] == relative and item["kind"] == "json"
    }
    return [pointer for pointer in found if pointer not in mapped_pointers]


def _iter_files(root: pathlib.Path) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for scan_root in SCAN_ROOTS:
        base = root / scan_root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if path_role(rel) != "authoritative":
                continue
            name = path.name
            suffix = path.suffix.lower()
            if suffix not in SCAN_EXTENSIONS and name != "Dockerfile" and not name.startswith("Dockerfile"):
                if not (suffix == ".json" and _is_provenance_json(rel)):
                    continue
            files.append(path)
    for mapping in MIRROR_MAPPINGS:
        mapped_path = root / str(mapping["path"])
        if mapped_path.is_file() and mapped_path not in files:
            files.append(mapped_path)
    return files


def _read_text(path: pathlib.Path) -> str | None:
    try:
        if path.stat().st_size > 32 * 1024 * 1024:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _mirror_hits(
    root: pathlib.Path,
    canonical: dict[str, dict[str, str]],
) -> tuple[list[PinHit], list[str]]:
    hits: list[PinHit] = []
    missing: list[str] = []
    for mapping in MIRROR_MAPPINGS:
        rel = str(mapping["path"])
        path = root / rel
        if not path.is_file():
            missing.append(rel)
            continue
        text = _read_text(path)
        if text is None:
            missing.append(rel)
            continue
        kind = str(mapping["kind"])
        tool = str(mapping["tool"])
        field = str(mapping["field"])
        value = ""
        if kind == "json":
            try:
                document = json.loads(text)
            except json.JSONDecodeError:
                missing.append(rel)
                continue
            extracted = _json_pointer(document, str(mapping["pointer"]))
            if extracted is None:
                missing.append(f"{rel}#{mapping['pointer']}")
                continue
            value = str(extracted)
        elif kind == "gradle_wrapper":
            match = _WRAPPER_URL_RE.search(text)
            if match is None:
                missing.append(rel)
                continue
            value = match.group("version")
        elif kind == "python_image":
            match = _PYTHON_IMAGE_RE.search(text)
            if match is None:
                missing.append(rel)
                continue
            value = match.group(1)
        elif kind == "python_const":
            extracted_const = _python_const_value(text, str(mapping["pointer"]))
            if extracted_const is None:
                missing.append(f"{rel}#{mapping['pointer']}")
                continue
            value = extracted_const
        else:
            missing.append(rel)
            continue
        hit = _hit(
            path=rel,
            tool=tool,
            field=field,
            value=value,
            kind="mirror",
            symbol=str(mapping["pointer"] or kind),
            canonical=canonical,
        )
        if hit is not None:
            hits.append(hit)
    return hits, missing


def scan_repository(
    root: pathlib.Path,
    *,
    manifest: dict | None = None,
) -> ScanReport:
    """Scan production build, packaging, installer, and deployment scripts."""
    root = root.resolve()
    if manifest is None:
        manifest_path = root / "tools" / "toolchain-pins.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    canonical = canonical_pins(manifest)
    hits: list[PinHit] = []
    floating: list[FloatingHit] = []
    unmapped: list[str] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()

    for path in _iter_files(root):
        rel = path.relative_to(root).as_posix()
        text = _read_text(path)
        if text is None:
            continue
        if path.suffix.lower() == ".json" and _is_provenance_json(rel):
            try:
                document = json.loads(text)
            except json.JSONDecodeError:
                document = None
            if document is not None:
                extra = _unmapped_json_fields(rel, document)
                if extra and rel not in _MAPPED_PATHS:
                    unmapped.append(f"{rel} :: {', '.join(extra)}")
        for hit in scan_text(rel, text, canonical):
            # The symbol is part of the identity: two symbols in one file can carry
            # the same value for different components (a wrapper and its embedded
            # engine), and dropping one hides which assignment is wrong.
            key = (hit.path, hit.tool, hit.field, hit.kind, hit.symbol, hit.value)
            if key in seen:
                continue
            seen.add(key)
            hits.append(hit)
        for item in scan_floating(rel, text):
            floating.append(item)

    mirror_hits, missing = _mirror_hits(root, canonical)
    for hit in mirror_hits:
        key = (hit.path, hit.tool, hit.field, hit.kind, hit.symbol, hit.value)
        if key in seen:
            continue
        seen.add(key)
        hits.append(hit)

    wrappers = sorted(root.rglob("gradle/wrapper/gradle-wrapper.properties"))
    for wrapper in wrappers:
        try:
            rel = wrapper.relative_to(root).as_posix()
        except ValueError:
            continue
        if path_role(rel) != "authoritative" and rel not in _MAPPED_PATHS:
            continue
        if rel not in _MAPPED_PATHS:
            unmapped.append(rel)

    hits.sort(key=lambda hit: (hit.path, hit.tool, hit.field, hit.kind, hit.symbol))
    floating.sort(key=lambda item: (item.path, item.selector, item.snippet))
    return ScanReport(
        hits=tuple(hits),
        floating=tuple(floating),
        unmapped_mirrors=tuple(sorted(set(unmapped))),
        missing_mappings=tuple(sorted(set(missing))),
    )


def load_manifest(root: pathlib.Path) -> dict:
    path = root / "tools" / "toolchain-pins.json"
    return json.loads(path.read_text(encoding="utf-8"))
