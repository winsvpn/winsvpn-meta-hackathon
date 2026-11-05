#!/usr/bin/env python3
"""Release-blocking latest AmneziaWG identity audit.

Live-discovers official latest version tags and GitHub Releases, freezes
the exact tag/commit/hash identities, then compares this repo's platform
sources. Stability is taken only from GitHub Releases: a non-draft,
non-prerelease Release is stable. A tag with no Releases has stability
designation unavailable and is not reported as a latest stable release.
Old 1.x, 2.x, v0.2.x, archived forks, untagged source, unidentified
server containers, and mixed protocol generations fail the gate.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import pathlib
import re
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol


USER_AGENT = "wins-vpn-awg-latest-audit/1.0"
OFFICIAL_OWNER = "amnezia-vpn"
RELEASE_CA_BUNDLE_PATH = pathlib.Path(
    "/Library/WinsVPN/ReleasePython/3.14.7/vendor/certifi/cacert.pem"
)
RELEASE_CA_BUNDLE_SHA256 = (
    "9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f"
)
RELEASE_CA_BUNDLE_BYTES = 240216
REJECTED_GENERATIONS = {
    "0.2": "old_v0_2",
    "1": "old_1x",
    "2": "old_2x",
}
UNSTABLE_MARKERS = (
    "nightly",
    "alpha",
    "beta",
    "rc",
    "preview",
    "snapshot",
    "dev",
    "canary",
    "draft",
)
TAG_RE = re.compile(
    r"^v?(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?(?:-(?P<suffix>\d+))?$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DEFAULT_UNWRAP_RE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]+)\}$")
GITHUB_REPOSITORY_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
GITHUB_API_ORIGIN = "https://api.github.com"
GITHUB_API_MAX_BODY_BYTES = 16 * 1024 * 1024
GITHUB_API_MAX_ERROR_BYTES = 64 * 1024
GITHUB_API_MAX_HEADERS = 128
GITHUB_API_MAX_HEADER_BYTES = 64 * 1024
GITHUB_API_MAX_PAGES = 20
GITHUB_API_MAX_ITEMS = 2_000
CONTAINER_RE = re.compile(
    r"(?P<image>amneziavpn/amneziawg-go)"
    r"(?::(?P<tag>[^\s@\"']+))?"
    r"(?:@sha256:(?P<digest>[0-9a-f]{64}))?"
)
WINDOWS_INSTALLER_ARCHITECTURE_ASSETS = {
    "x64": "amneziawg-amd64-{tag}.msi",
    "arm64": "amneziawg-arm64-{tag}.msi",
}
WINDOWS_INSTALLER_DIGEST_MAP_RE = re.compile(
    r"\$AmneziaWgSha256\s*=\s*@\{(?P<body>.*?)\}\s*\[\s*\$TargetArchitecture\s*\]",
    re.DOTALL,
)
WINDOWS_INSTALLER_DIGEST_ASSIGNMENT_RE = re.compile(
    r"\$AmneziaWgSha256\s*="
)
WINDOWS_INSTALLER_DIGEST_ENTRY_RE = re.compile(
    r"'(?P<architecture>[A-Za-z0-9]+)'\s*=\s*'(?P<digest>[0-9a-f]{64})'"
)

COMPONENTS = {
    "amneziawg-tools": "amnezia-vpn/amneziawg-tools",
    "amneziawg-go": "amnezia-vpn/amneziawg-go",
    "amneziawg-android": "amnezia-vpn/amneziawg-android",
    "amneziawg-apple": "amnezia-vpn/amneziawg-apple",
    "amneziawg-windows": "amnezia-vpn/amneziawg-windows",
    "amneziawg-windows-client": "amnezia-vpn/amneziawg-windows-client",
}
ORIGIN_RELEASE = "release"
ORIGIN_TAG = "tag"
STABILITY_STABLE = "stable"
STABILITY_UNAVAILABLE = "unavailable"
DESIGNATION_STABLE_RELEASE = "latest stable GitHub Release"
DESIGNATION_TAG_UNAVAILABLE = (
    "latest upstream tag; stability designation unavailable"
)


class ReleaseClient(Protocol):
    def repo_metadata(self, slug: str) -> dict[str, Any]: ...

    def list_releases(self, slug: str) -> list[dict[str, Any]]: ...

    def list_tags(self, slug: str) -> list[dict[str, Any]]: ...

    def tag_commit(self, slug: str, tag: str) -> str: ...


@dataclass(frozen=True)
class FrozenRelease:
    component: str
    slug: str
    tag: str
    commit: str
    generation: str
    origin: str
    stability: str
    hashes: dict[str, str] = field(default_factory=dict)

    @property
    def designation(self) -> str:
        return designation_label(self.origin, self.stability)


@dataclass(frozen=True)
class RepoSource:
    component: str
    platform: str
    path: str
    kind: str
    repository: str
    tag: str
    commit: str
    digest: str
    generation: str
    digests: dict[str, str] = field(default_factory=dict)
    compare_release_hash: bool = False
    release_asset_name: str = ""


@dataclass(frozen=True)
class Finding:
    code: str
    source: str
    detail: str


@dataclass(frozen=True)
class AuditReport:
    frozen: dict[str, FrozenRelease]
    sources: tuple[RepoSource, ...]
    findings: tuple[Finding, ...]

    @property
    def ok(self) -> bool:
        return not self.findings

    @property
    def frozen_generation(self) -> str | None:
        generations = {item.generation for item in self.frozen.values()}
        if len(generations) == 1:
            return next(iter(generations))
        return None


@dataclass(frozen=True)
class SourceSpec:
    component: str
    platform: str
    relative_path: str
    kind: str
    tag_patterns: tuple[str, ...] = ()
    commit_patterns: tuple[str, ...] = ()
    hash_patterns: tuple[str, ...] = ()
    digest_map_kind: str = ""
    repo_patterns: tuple[str, ...] = ()
    default_repository: str = ""
    compare_release_hash: bool = False
    release_asset_name: str = ""


SOURCE_SPECS: tuple[SourceSpec, ...] = (
    SourceSpec(
        component="amneziawg-tools",
        platform="linux",
        relative_path="tools/build_linux_release.sh",
        kind="git",
        tag_patterns=(r'AWG_TOOLS_VERSION="([^"]+)"',),
        commit_patterns=(r'AWG_TOOLS_COMMIT="([0-9a-f]{40})"',),
        hash_patterns=(r'AWG_TOOLS_ARCHIVE_SHA256="([0-9a-f]{64})"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-tools.git",
        compare_release_hash=True,
        release_asset_name="ubuntu-22.04-amneziawg-tools.zip",
    ),
    SourceSpec(
        component="amneziawg-tools",
        platform="linux-arm64",
        relative_path="tools/build_linux_arm64_awg.sh",
        kind="git",
        tag_patterns=(r'AWG_TOOLS_VERSION="([^"]+)"',),
        commit_patterns=(r'AWG_TOOLS_COMMIT="([0-9a-f]{40})"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-tools.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="linux",
        relative_path="tools/build_linux_release.sh",
        kind="git",
        tag_patterns=(r'AWG_GO_TAG="([^"]+)"',),
        commit_patterns=(r'AWG_GO_COMMIT="([0-9a-f]{40})"',),
        hash_patterns=(r'AWG_GO_SOURCE_SHA256="([0-9a-f]{64})"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="linux-arm64-companion",
        relative_path="tools/build_linux_arm64_awg.sh",
        kind="git",
        tag_patterns=(r'AWG_GO_TAG="([^"]+)"',),
        commit_patterns=(r'AWG_GO_COMMIT="([0-9a-f]{40})"',),
        hash_patterns=(r'AWG_GO_SOURCE_SHA256="([0-9a-f]{64})"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="windows",
        relative_path="tools/build_windows_awg_engine.ps1",
        kind="git",
        tag_patterns=(r"\$engineVersion\s*=\s*'([^']+)'",),
        commit_patterns=(r"\$engineCommit\s*=\s*'([0-9a-f]{40})'",),
        repo_patterns=(r"\$engineRepository\s*=\s*'([^']+)'",),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-android",
        platform="android",
        relative_path="tools/build_amneziawg_android_engine.sh",
        kind="git",
        tag_patterns=(r'AWG_ANDROID_TAG="([^"]+)"',),
        commit_patterns=(r'AWG_ANDROID_COMMIT="([0-9a-f]{40})"',),
        repo_patterns=(r'AWG_ANDROID_REPO="([^"]+)"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-android.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="android-companion",
        relative_path="tools/build_amneziawg_android_engine.sh",
        kind="git",
        tag_patterns=(r'AWG_GO_TAG="([^"]+)"',),
        commit_patterns=(r'AWG_GO_COMMIT="([0-9a-f]{40})"',),
        hash_patterns=(r'AWG_GO_SOURCE_SHA256="([0-9a-f]{64})"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-apple",
        platform="apple",
        relative_path="tools/build_apple_wg_go_bridge.sh",
        kind="git",
        tag_patterns=(
            r'AMNEZIAWG_APPLE_TAG="([^"]+)"',
            r'AMNEZIAWG_APPLE_REF="([^"]+)"',
        ),
        commit_patterns=(
            r'AMNEZIAWG_APPLE_COMMIT="([0-9a-f]{40})"',
            r'AMNEZIAWG_APPLE_REF="([^"]+)"',
        ),
        repo_patterns=(r'AMNEZIAWG_APPLE_REPO="([^"]+)"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-apple.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="apple-companion",
        relative_path="tools/build_apple_wg_go_bridge.sh",
        kind="git",
        tag_patterns=(r'AMNEZIAWG_GO_TAG="([^"]+)"',),
        commit_patterns=(r'AMNEZIAWG_GO_COMMIT="([0-9a-f]{40})"',),
        hash_patterns=(r'AMNEZIAWG_GO_SOURCE_SHA256="([0-9a-f]{64})"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="winn-v3",
        relative_path="winn_protocol_experimental/scripts/build_winn_awg_engine.sh",
        kind="git",
        tag_patterns=(r'upstream_tag=(\S+)',),
        commit_patterns=(r'upstream_commit=([0-9a-f]{40})',),
        hash_patterns=(r'upstream_github_archive_sha256=([0-9a-f]{64})',),
        repo_patterns=(r'upstream_repository=(\S+)',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="server-image",
        relative_path="server/build_amneziawg_go_server_image.sh",
        kind="git",
        tag_patterns=(r'AWG_GO_TAG="([^"]+)"',),
        commit_patterns=(r'AWG_GO_COMMIT="([0-9a-f]{40})"',),
        hash_patterns=(r'AWG_GO_SOURCE_SHA256="([0-9a-f]{64})"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-tools",
        platform="server-image",
        relative_path="server/build_amneziawg_go_server_image.sh",
        kind="git",
        tag_patterns=(r'AWG_TOOLS_TAG="([^"]+)"',),
        commit_patterns=(r'AWG_TOOLS_COMMIT="([0-9a-f]{40})"',),
        hash_patterns=(r'AWG_TOOLS_SOURCE_SHA256="([0-9a-f]{64})"',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-tools.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="windows-module",
        relative_path="windows/awg_engine/go.mod",
        kind="git",
        tag_patterns=(
            r'github\.com/amnezia-vpn/amneziawg-go/v3\s+(v[0-9][\w.-]+)',
        ),
        commit_patterns=(
            r'//\s*([0-9a-f]{40})\. GitHub archive SHA-256',
        ),
        hash_patterns=(
            r'//\s*([0-9a-f]{64})\. That is',
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-windows",
        platform="windows",
        relative_path="tools/build_windows_amneziawg_client.ps1",
        kind="git",
        tag_patterns=(r"\$windowsLibraryVersion\s*=\s*'([^']+)'",),
        commit_patterns=(r"\$windowsLibraryCommit\s*=\s*'([0-9a-f]{40})'",),
        repo_patterns=(r"\$windowsLibraryRepository\s*=\s*'([^']+)'",),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows.git",
    ),
    SourceSpec(
        component="amneziawg-windows-client",
        platform="windows",
        relative_path="tools/build_windows_amneziawg_client.ps1",
        kind="git",
        tag_patterns=(r"\$sourceVersion\s*=\s*'([^']+)'",),
        commit_patterns=(r"\$sourceCommit\s*=\s*'([0-9a-f]{40})'",),
        repo_patterns=(r"\$sourceRepository\s*=\s*'([^']+)'",),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows-client.git",
    ),
    SourceSpec(
        component="amneziawg-windows-client",
        platform="windows-installer",
        relative_path="installer/windows/build_installer.ps1",
        kind="git",
        tag_patterns=(r'\$AmneziaWgVersion\s*=\s*"([^"]+)"',),
        commit_patterns=(r'\$AmneziaWgSourceCommit\s*=\s*"([0-9a-f]{40})"',),
        digest_map_kind="windows-installer",
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows-client.git",
        compare_release_hash=True,
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="android-devicecheck-builder",
        relative_path="android/devicecheck/build_devicecheck.sh",
        kind="git",
        tag_patterns=(r'(?m)^AWG_GO_VERSION="([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^AWG_GO_COMMIT="([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="android-devicecheck-module",
        relative_path="android/devicecheck/awgresponder/go.mod",
        kind="git",
        tag_patterns=(
            r'(?m)^require\s+github\.com/amnezia-vpn/amneziawg-go/v3\s+(v[0-9][\w.-]+)\s*$',
        ),
        commit_patterns=(
            r'(?m)^//\s*AWG_GO_COMMIT=([0-9a-f]{40})\s*$',
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-apple",
        platform="apple-wrapper-consumer",
        relative_path="tools/build_apple_engine_wrappers.sh",
        kind="git",
        tag_patterns=(r'(?m)^APPLE_AWG_EXPECTED_TAG="([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^APPLE_AWG_EXPECTED_COMMIT="([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-apple.git",
    ),
    SourceSpec(
        component="amneziawg-apple",
        platform="apple-stage-consumer",
        relative_path="tools/stage_apple_engine_artifacts.sh",
        kind="git",
        tag_patterns=(r'(?m)^APPLE_AWG_EXPECTED_TAG="([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^APPLE_AWG_EXPECTED_COMMIT="([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-apple.git",
    ),
    SourceSpec(
        component="amneziawg-apple",
        platform="apple-cross-store-consumer",
        relative_path="tools/apple_cross_store_artifact_gate.py",
        kind="git",
        tag_patterns=(
            r'(?ms)^REVIEWED_AWG_SOURCE\s*=\s*\{.*?"tag"\s*:\s*"([^"]+)".*?^\}',
        ),
        commit_patterns=(
            r'(?ms)^REVIEWED_AWG_SOURCE\s*=\s*\{.*?"commit"\s*:\s*"([0-9a-f]{40})".*?^\}',
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-apple.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="gcp-deployment-inputs",
        relative_path="tools/gcp_deployment_inputs.py",
        kind="git",
        tag_patterns=(r'(?m)^REVIEWED_AWG_GO_TAG\s*=\s*"([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^REVIEWED_AWG_GO_COMMIT\s*=\s*"([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-tools",
        platform="gcp-deployment-inputs",
        relative_path="tools/gcp_deployment_inputs.py",
        kind="git",
        tag_patterns=(r'(?m)^REVIEWED_AWG_TOOLS_TAG\s*=\s*"([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^REVIEWED_AWG_TOOLS_COMMIT\s*=\s*"([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-tools.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="windows-cross-store-consumer",
        relative_path="tools/windows_cross_store_artifact_gate.py",
        kind="git",
        tag_patterns=(r'(?m)^AWG_GO_VERSION\s*=\s*"([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^AWG_GO_COMMIT\s*=\s*"([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-windows-client",
        platform="windows-msix",
        relative_path="installer/windows/build_store_msix.ps1",
        kind="git",
        tag_patterns=(r"(?m)^\$AmneziaWgVersion\s*=\s*'([^']+)'\s*$",),
        commit_patterns=(r"(?m)^\$AmneziaWgSourceCommit\s*=\s*'([0-9a-f]{40})'\s*$",),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows-client.git",
    ),
    SourceSpec(
        component="amneziawg-windows",
        platform="windows-msix-library",
        relative_path="installer/windows/build_store_msix.ps1",
        kind="git",
        tag_patterns=(r"(?m)^\$AmneziaWgWindowsLibraryVersion\s*=\s*'([^']+)'\s*$",),
        commit_patterns=(r"(?m)^\$AmneziaWgWindowsLibraryCommit\s*=\s*'([0-9a-f]{40})'\s*$",),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="windows-msix-engine",
        relative_path="installer/windows/build_store_msix.ps1",
        kind="git",
        tag_patterns=(r"(?m)^\$AmneziaWgEngineVersion\s*=\s*'([^']+)'\s*$",),
        commit_patterns=(r"(?m)^\$AmneziaWgEngineCommit\s*=\s*'([0-9a-f]{40})'\s*$",),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-windows-client",
        platform="windows-zip-x64",
        relative_path="installer/windows/build_zip_installer.ps1",
        kind="git",
        tag_patterns=(
            r"(?ms)^\$ZipX64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_client_version\s*=\s*'([^']+)'",
        ),
        commit_patterns=(
            r"(?ms)^\$ZipX64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_source_commit\s*=\s*'([0-9a-f]{40})'",
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows-client.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="windows-zip-x64-engine",
        relative_path="installer/windows/build_zip_installer.ps1",
        kind="git",
        tag_patterns=(
            r"(?ms)^\$ZipX64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_engine_version\s*=\s*'([^']+)'",
        ),
        commit_patterns=(
            r"(?ms)^\$ZipX64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_engine_commit\s*=\s*'([0-9a-f]{40})'",
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-windows-client",
        platform="windows-zip-arm64",
        relative_path="installer/windows/build_zip_installer.ps1",
        kind="git",
        tag_patterns=(
            r"(?ms)^\$ZipArm64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_client_version\s*=\s*'([^']+)'",
        ),
        commit_patterns=(
            r"(?ms)^\$ZipArm64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_source_commit\s*=\s*'([0-9a-f]{40})'",
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows-client.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="windows-zip-arm64-engine",
        relative_path="installer/windows/build_zip_installer.ps1",
        kind="git",
        tag_patterns=(
            r"(?ms)^\$ZipArm64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_engine_version\s*=\s*'([^']+)'",
        ),
        commit_patterns=(
            r"(?ms)^\$ZipArm64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_engine_commit\s*=\s*'([0-9a-f]{40})'",
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-windows-client",
        platform="windows-zip-install-x64",
        relative_path="installer/windows/install_winsvpn_zip.ps1",
        kind="git",
        tag_patterns=(
            r"(?ms)^\$ExpectedDependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_client_version\s*=\s*'([^']+)'",
        ),
        commit_patterns=(
            r"(?ms)^\$ExpectedDependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_source_commit\s*=\s*'([0-9a-f]{40})'",
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows-client.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="windows-zip-install-x64-engine",
        relative_path="installer/windows/install_winsvpn_zip.ps1",
        kind="git",
        tag_patterns=(
            r"(?ms)^\$ExpectedDependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_engine_version\s*=\s*'([^']+)'",
        ),
        commit_patterns=(
            r"(?ms)^\$ExpectedDependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_engine_commit\s*=\s*'([0-9a-f]{40})'",
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-windows-client",
        platform="windows-zip-install-arm64",
        relative_path="installer/windows/install_winsvpn_zip.ps1",
        kind="git",
        tag_patterns=(
            r"(?ms)^\$ExpectedArm64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_client_version\s*=\s*'([^']+)'",
        ),
        commit_patterns=(
            r"(?ms)^\$ExpectedArm64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_source_commit\s*=\s*'([0-9a-f]{40})'",
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows-client.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="windows-zip-install-arm64-engine",
        relative_path="installer/windows/install_winsvpn_zip.ps1",
        kind="git",
        tag_patterns=(
            r"(?ms)^\$ExpectedArm64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_engine_version\s*=\s*'([^']+)'",
        ),
        commit_patterns=(
            r"(?ms)^\$ExpectedArm64DependencyContract\s*=\s*\[ordered\]@\{.*?^\s*amneziawg_engine_commit\s*=\s*'([0-9a-f]{40})'",
        ),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-android",
        platform="deployment-supply-chain-android",
        relative_path="tools/verify_deployment_supply_chain.py",
        kind="git",
        tag_patterns=(r'(?m)^AMNEZIAWG_ANDROID_ENGINE_TAG\s*=\s*"([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^AMNEZIAWG_ANDROID_ENGINE_COMMIT\s*=\s*"([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-android.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="deployment-supply-chain-windows-engine",
        relative_path="tools/verify_deployment_supply_chain.py",
        kind="git",
        tag_patterns=(r'(?m)^WINDOWS_AMNEZIAWG_ENGINE_VERSION\s*=\s*"([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^WINDOWS_AMNEZIAWG_ENGINE_COMMIT\s*=\s*"([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-go.git",
    ),
    SourceSpec(
        component="amneziawg-windows",
        platform="deployment-supply-chain-windows-library",
        relative_path="tools/verify_deployment_supply_chain.py",
        kind="git",
        tag_patterns=(r'(?m)^WINDOWS_AMNEZIAWG_LIBRARY_VERSION\s*=\s*"([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^WINDOWS_AMNEZIAWG_LIBRARY_COMMIT\s*=\s*"([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows.git",
    ),
    SourceSpec(
        component="amneziawg-windows-client",
        platform="deployment-supply-chain-windows-client",
        relative_path="tools/verify_deployment_supply_chain.py",
        kind="git",
        tag_patterns=(r'(?m)^WINDOWS_AMNEZIAWG_SOURCE_VERSION\s*=\s*"([^"]+)"\s*$',),
        commit_patterns=(r'(?m)^WINDOWS_AMNEZIAWG_SOURCE_COMMIT\s*=\s*"([0-9a-f]{40})"\s*$',),
        default_repository="https://github.com/amnezia-vpn/amneziawg-windows-client.git",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="server-data-plane",
        relative_path="server/wins_data_plane_setup_ONETOUCH.sh",
        kind="container",
    ),
    SourceSpec(
        component="amneziawg-go",
        platform="server-core",
        relative_path="server/wins_core_server_setup_ONETOUCH.sh",
        kind="container",
    ),
)

AWG_PIN_DISCOVERY_ROOTS = (
    "tools",
    "server",
    "installer/windows",
    "android/devicecheck",
    "windows/awg_engine",
    "winn_protocol_experimental/scripts",
)
AWG_PIN_DISCOVERY_SUFFIXES = frozenset(
    {
        ".bash",
        ".bat",
        ".cmd",
        ".fish",
        ".mod",
        ".ps1",
        ".psm1",
        ".py",
        ".sh",
        ".zsh",
    }
)
AWG_PIN_DISCOVERY_MAX_FILES = 4_096
AWG_PIN_DISCOVERY_MAX_BYTES = 8 * 1024 * 1024
PRODUCTION_AWG_SOURCE_PATHS = frozenset(
    {
        "android/devicecheck/awgresponder/go.mod",
        "android/devicecheck/build_devicecheck.sh",
        "installer/windows/build_installer.ps1",
        "installer/windows/build_store_msix.ps1",
        "installer/windows/build_zip_installer.ps1",
        "installer/windows/install_winsvpn_zip.ps1",
        "server/build_amneziawg_go_server_image.sh",
        "server/wins_core_server_setup_ONETOUCH.sh",
        "server/wins_data_plane_setup_ONETOUCH.sh",
        "tools/apple_cross_store_artifact_gate.py",
        "tools/build_amneziawg_android_engine.sh",
        "tools/build_apple_engine_wrappers.sh",
        "tools/build_apple_wg_go_bridge.sh",
        "tools/build_linux_arm64_awg.sh",
        "tools/build_linux_release.sh",
        "tools/build_windows_amneziawg_client.ps1",
        "tools/build_windows_awg_engine.ps1",
        "tools/gcp_deployment_inputs.py",
        "tools/stage_apple_engine_artifacts.sh",
        "tools/verify_deployment_supply_chain.py",
        "tools/windows_cross_store_artifact_gate.py",
        "windows/awg_engine/go.mod",
        "winn_protocol_experimental/scripts/build_winn_awg_engine.sh",
    }
)
AWG_PIN_DISCOVERY_RE = re.compile(
    r"(?mx)"
    r"^(?:"
    r"\s*(?:AWG_GO_(?:TAG|VERSION)|AMNEZIAWG_GO_TAG|"
    r"AWG_TOOLS_(?:TAG|VERSION)|AMNEZIAWG_APPLE_TAG|"
    r"APPLE_AWG_EXPECTED_TAG|REVIEWED_AWG_(?:GO|TOOLS)_TAG|"
    r"AMNEZIAWG_ANDROID_ENGINE_TAG|WINDOWS_AMNEZIAWG_(?:SOURCE|LIBRARY|ENGINE)_VERSION)\s*="
    r"|\s*\$(?:engineVersion|sourceVersion|windowsLibraryVersion|"
    r"AmneziaWgVersion|AmneziaWgEngineVersion|AmneziaWgWindowsLibraryVersion)\s*="
    r"|\s*upstream_tag="
    r"|\s*require\s+github\.com/amnezia-vpn/amneziawg-go/v3\s+v"
    r"|\s*REVIEWED_AWG_SOURCE\s*="
    r"|\s*amneziawg_(?:client|engine)_version\s*="
    r")"
)


class LatestAwgError(RuntimeError):
    pass


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def _reject(self, request, fp, code, message, headers):
        raise urllib.error.HTTPError(
            request.full_url, code, message, headers, fp
        )

    http_error_301 = _reject
    http_error_302 = _reject
    http_error_303 = _reject
    http_error_307 = _reject
    http_error_308 = _reject


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LatestAwgError(f"GitHub JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise LatestAwgError(f"GitHub JSON contains non-finite value {value}")


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise LatestAwgError(f"GitHub JSON contains non-finite value {value}")
    return parsed


def _strict_json_loads(payload: bytes) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_strict_json_float,
        )
    except LatestAwgError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LatestAwgError("GitHub response was not strict UTF-8 JSON") from exc


def _validate_github_api_url(url: str) -> urllib.parse.SplitResult:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise LatestAwgError("GitHub API URL is malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or not parsed.path.startswith("/repos/")
        or "//" in parsed.path
        or any(item in {".", ".."} for item in parsed.path.split("/"))
    ):
        raise LatestAwgError(f"GitHub API URL is outside the reviewed origin: {url}")
    try:
        url.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LatestAwgError("GitHub API URL must be ASCII") from exc
    return parsed


def _bounded_read(stream: Any, limit: int, label: str) -> bytes:
    payload = bytearray()
    while len(payload) <= limit:
        chunk = stream.read(min(65536, limit + 1 - len(payload)))
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise LatestAwgError(f"{label} returned non-byte response data")
        payload.extend(chunk)
    if len(payload) > limit:
        raise LatestAwgError(f"{label} exceeded the response byte ceiling")
    return bytes(payload)


def _validate_response_headers(response: Any) -> None:
    headers = getattr(response, "headers", None)
    if headers is None or not callable(getattr(headers, "items", None)):
        raise LatestAwgError("GitHub response headers are unavailable")
    items = list(headers.items())
    if len(items) > GITHUB_API_MAX_HEADERS:
        raise LatestAwgError("GitHub response contains too many headers")
    total = 0
    for name, value in items:
        if not isinstance(name, str) or not isinstance(value, str):
            raise LatestAwgError("GitHub response header is malformed")
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise LatestAwgError("GitHub response header contains a line break")
        total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
    if total > GITHUB_API_MAX_HEADER_BYTES:
        raise LatestAwgError("GitHub response headers exceed the byte ceiling")
    content_type = str(headers.get("Content-Type", "")).split(";", 1)[0].strip().lower()
    if content_type not in {"application/json", "application/vnd.github+json"}:
        raise LatestAwgError("GitHub response content type is not JSON")
    content_encoding = str(headers.get("Content-Encoding", "")).strip().lower()
    if content_encoding not in {"", "identity"}:
        raise LatestAwgError("GitHub response content encoding is unsupported")


def _next_link(headers: Any, current_url: str, first_url: str) -> str | None:
    get_all = getattr(headers, "get_all", None)
    raw_values = get_all("Link", []) if callable(get_all) else []
    if len(raw_values) > 1:
        raise LatestAwgError("GitHub pagination has multiple Link headers")
    raw = raw_values[0] if raw_values else headers.get("Link", "")
    if raw in {None, ""}:
        return None
    if not isinstance(raw, str):
        raise LatestAwgError("GitHub pagination Link header is malformed")
    links: list[tuple[str, frozenset[str]]] = []
    for item in raw.split(","):
        match = re.fullmatch(
            r'\s*<([^<>]+)>\s*;\s*rel="([A-Za-z ]+)"\s*', item
        )
        if match is None:
            raise LatestAwgError("GitHub pagination Link header is malformed")
        links.append((match.group(1), frozenset(match.group(2).split())))
    next_urls = [url for url, relations in links if "next" in relations]
    if len(next_urls) > 1:
        raise LatestAwgError("GitHub pagination has multiple next links")
    if not next_urls:
        return None
    next_url = next_urls[0]
    first = _validate_github_api_url(first_url)
    current = _validate_github_api_url(current_url)
    following = _validate_github_api_url(next_url)
    if (
        (following.scheme, following.netloc, following.path)
        != (first.scheme, first.netloc, first.path)
        or (current.scheme, current.netloc, current.path)
        != (first.scheme, first.netloc, first.path)
    ):
        raise LatestAwgError("GitHub pagination left the exact reviewed endpoint")
    try:
        first_query = urllib.parse.parse_qs(first.query, strict_parsing=True)
        current_query = urllib.parse.parse_qs(current.query, strict_parsing=True)
        next_query = urllib.parse.parse_qs(following.query, strict_parsing=True)
    except ValueError as exc:
        raise LatestAwgError("GitHub pagination query is malformed") from exc
    if first_query != {"per_page": ["100"]}:
        raise LatestAwgError("GitHub pagination first-page query is not exact")
    if set(current_query) - {"page", "per_page"} or set(next_query) != {
        "page",
        "per_page",
    }:
        raise LatestAwgError("GitHub pagination query is not exact")
    if (
        current_query.get("per_page") != ["100"]
        or next_query["per_page"] != ["100"]
        or len(current_query.get("page", ["1"])) != 1
        or len(next_query["page"]) != 1
    ):
        raise LatestAwgError("GitHub pagination page size changed")
    try:
        current_page = int(current_query.get("page", ["1"])[0])
        next_page = int(next_query["page"][0])
    except (ValueError, IndexError) as exc:
        raise LatestAwgError("GitHub pagination page number is malformed") from exc
    if current_page < 1 or next_page != current_page + 1:
        raise LatestAwgError("GitHub pagination page sequence is not contiguous")
    return next_url


def _validate_error_headers(error: urllib.error.HTTPError) -> None:
    headers = error.headers
    if headers is None or not callable(getattr(headers, "items", None)):
        raise LatestAwgError("GitHub error headers are unavailable")
    items = list(headers.items())
    if len(items) > GITHUB_API_MAX_HEADERS:
        raise LatestAwgError("GitHub error contains too many headers")
    total = 0
    for name, value in items:
        if not isinstance(name, str) or not isinstance(value, str):
            raise LatestAwgError("GitHub error header is malformed")
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise LatestAwgError("GitHub error header contains a line break")
        total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
    if total > GITHUB_API_MAX_HEADER_BYTES:
        raise LatestAwgError("GitHub error headers exceed the byte ceiling")


class LiveGitHubClient:
    def __init__(self) -> None:
        self._ssl_context = verified_ssl_context()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self._ssl_context),
            _NoRedirectHandler(),
        )

    def repo_metadata(self, slug: str) -> dict[str, Any]:
        payload = self._get(f"https://api.github.com/repos/{slug}")
        if not isinstance(payload, dict):
            raise LatestAwgError(f"{slug} repo metadata was not an object")
        return payload

    def list_releases(self, slug: str) -> list[dict[str, Any]]:
        return self._paginate(
            f"https://api.github.com/repos/{slug}/releases?per_page=100"
        )

    def list_tags(self, slug: str) -> list[dict[str, Any]]:
        return self._paginate(
            f"https://api.github.com/repos/{slug}/tags?per_page=100"
        )

    def _paginate(self, first_url: str) -> list[dict[str, Any]]:
        url: str | None = first_url
        visited: set[str] = set()
        collected: list[dict[str, Any]] = []
        for _page in range(GITHUB_API_MAX_PAGES):
            if url is None:
                return collected
            if url in visited:
                raise LatestAwgError("GitHub pagination contains a cycle")
            visited.add(url)
            payload, next_url = self._get_page(url, first_url)
            if not isinstance(payload, list):
                raise LatestAwgError("GitHub paginated API did not return a list")
            if len(collected) + len(payload) > GITHUB_API_MAX_ITEMS:
                raise LatestAwgError("GitHub pagination exceeded the item ceiling")
            if any(not isinstance(item, dict) for item in payload):
                raise LatestAwgError("GitHub paginated API returned a non-object item")
            collected.extend(payload)
            url = next_url
        if url is not None:
            raise LatestAwgError("GitHub pagination exceeded the page ceiling")
        return collected

    def tag_commit(self, slug: str, tag: str) -> str:
        encoded = urllib.parse.quote(tag, safe="")
        payload = self._get(
            f"https://api.github.com/repos/{slug}/git/ref/tags/{encoded}"
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("object"), dict):
            raise LatestAwgError(f"{slug} tag {tag} reference was malformed")
        obj = payload["object"]
        visited: set[str] = set()
        for _depth in range(8):
            sha = obj.get("sha")
            kind = obj.get("type")
            if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
                raise LatestAwgError(f"{slug} tag {tag} object SHA was malformed")
            if kind == "commit":
                return sha
            if kind != "tag":
                raise LatestAwgError(
                    f"{slug} tag {tag} resolved to forbidden object type {kind!r}"
                )
            if sha in visited:
                raise LatestAwgError(f"{slug} tag {tag} contains a tag-object cycle")
            visited.add(sha)
            tag_obj = self._get(f"https://api.github.com/repos/{slug}/git/tags/{sha}")
            if not isinstance(tag_obj, dict) or not isinstance(tag_obj.get("object"), dict):
                raise LatestAwgError(f"{slug} annotated tag object was malformed")
            obj = tag_obj["object"]
        raise LatestAwgError(f"{slug} tag {tag} exceeds the tag-object depth limit")

    def _get(self, url: str) -> Any:
        return self._request(url, first_url=None)[0]

    def _get_page(self, url: str, first_url: str) -> tuple[Any, str | None]:
        return self._request(url, first_url=first_url)

    def _request(self, url: str, *, first_url: str | None) -> tuple[Any, str | None]:
        _validate_github_api_url(url)
        request_value = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/vnd.github+json",
            },
        )
        last_error: Exception | None = None
        for attempt in range(4):
            try:
                with self._opener.open(request_value, timeout=45) as response:
                    response_url = response.geturl()
                    if response_url != url:
                        raise LatestAwgError(
                            "GitHub response URL does not match the intended request"
                        )
                    _validate_github_api_url(response_url)
                    status = response.getcode()
                    if status != 200:
                        raise LatestAwgError(
                            f"GitHub response status is not 200: {status!r}"
                        )
                    _validate_response_headers(response)
                    payload = _bounded_read(
                        response, GITHUB_API_MAX_BODY_BYTES, "GitHub response"
                    )
                    next_url = (
                        _next_link(response.headers, url, first_url)
                        if first_url is not None
                        else None
                    )
                    return _strict_json_loads(payload), next_url
            except urllib.error.HTTPError as exc:
                try:
                    if exc.geturl() != url:
                        raise LatestAwgError(
                            "GitHub error URL does not match the intended request"
                        )
                    _validate_error_headers(exc)
                    _bounded_read(exc, GITHUB_API_MAX_ERROR_BYTES, "GitHub error")
                finally:
                    exc.close()
                if 300 <= exc.code <= 399:
                    raise LatestAwgError(
                        f"GitHub redirect refused: {url} status={exc.code}"
                    ) from exc
                if exc.code == 404:
                    raise LatestAwgError(f"not found: {url}") from exc
                if exc.code not in {408, 425, 429, 500, 502, 503, 504}:
                    raise LatestAwgError(f"GitHub request failed: {url}") from exc
                last_error = exc
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
            if attempt == 3:
                break
            time.sleep(2**attempt)
        raise LatestAwgError(f"GitHub request failed after four attempts: {url}") from last_error


def verified_ssl_context() -> ssl.SSLContext:
    """Return a TLS client context with mandatory certificate verification.

    Python distributions on macOS do not always inherit the operating-system
    trust store. Use it when available, then fall back to Certifi's Mozilla CA
    bundle without ever disabling hostname or certificate validation.
    """
    context = ssl.create_default_context()
    if context.get_ca_certs():
        return context

    for ancestor in (
        pathlib.Path("/Library"),
        pathlib.Path("/Library/WinsVPN"),
        pathlib.Path("/Library/WinsVPN/ReleasePython"),
        pathlib.Path("/Library/WinsVPN/ReleasePython/3.14.7"),
        pathlib.Path("/Library/WinsVPN/ReleasePython/3.14.7/vendor"),
        RELEASE_CA_BUNDLE_PATH.parent,
    ):
        try:
            info = ancestor.lstat()
        except OSError as exc:
            raise LatestAwgError(
                f"trusted ReleasePython CA ancestor is unavailable: {ancestor}"
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise LatestAwgError(
                f"trusted ReleasePython CA ancestor has unsafe custody: {ancestor}"
            )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(RELEASE_CA_BUNDLE_PATH, flags)
    except OSError as exc:
        raise LatestAwgError("trusted ReleasePython CA bundle is unavailable") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or info.st_size != RELEASE_CA_BUNDLE_BYTES
        ):
            raise LatestAwgError("trusted ReleasePython CA bundle has unsafe custody")
        payload = bytearray()
        while len(payload) <= RELEASE_CA_BUNDLE_BYTES:
            chunk = os.read(descriptor, min(65536, RELEASE_CA_BUNDLE_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(payload) != RELEASE_CA_BUNDLE_BYTES
            or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or hashlib.sha256(payload).hexdigest() != RELEASE_CA_BUNDLE_SHA256
        ):
            raise LatestAwgError("trusted ReleasePython CA bundle identity changed")
    finally:
        os.close(descriptor)

    try:
        ca_text = bytes(payload).decode("ascii")
    except UnicodeDecodeError as exc:
        raise LatestAwgError("trusted ReleasePython CA bundle is not ASCII PEM") from exc
    context = ssl.create_default_context(cadata=ca_text)
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise LatestAwgError("TLS certificate verification is not enforced")
    if not context.get_ca_certs():
        raise LatestAwgError("trusted ReleasePython CA bundle contains no certificates")
    return context


def unwrap_assignment(value: str) -> str:
    raw = value.strip()
    match = DEFAULT_UNWRAP_RE.fullmatch(raw)
    return match.group(1) if match else raw


def parse_github_slug(url: str) -> str | None:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    parts = parsed.path.split("/")
    if len(parts) != 3 or parts[0] or not parts[1] or not parts[2]:
        return None
    owner = parts[1]
    repo = parts[2].removesuffix(".git")
    if (
        not owner
        or not repo
        or GITHUB_REPOSITORY_COMPONENT_RE.fullmatch(owner) is None
        or GITHUB_REPOSITORY_COMPONENT_RE.fullmatch(repo) is None
    ):
        return None
    return f"{owner}/{repo}"


def is_unstable_name(tag: str) -> bool:
    lowered = tag.lower()
    return any(marker in lowered for marker in UNSTABLE_MARKERS)


def parse_tag(tag: str) -> tuple[int, int, int, int] | None:
    match = TAG_RE.fullmatch(tag)
    if match is None:
        return None
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch") or 0),
        int(match.group("suffix") or 0),
    )


def generation_of(tag: str) -> str:
    parsed = parse_tag(tag)
    if parsed is None:
        return ""
    major, minor, _, _ = parsed
    if major == 0 and minor == 2:
        return "0.2"
    if major in {1, 2}:
        return str(major)
    return f"{major}.{minor}"


def version_key(tag: str) -> tuple[int, int, int, int]:
    parsed = parse_tag(tag)
    if parsed is None:
        return (-1, -1, -1, -1)
    return parsed


def is_stable_release(release: dict[str, Any]) -> bool:
    """True only for a GitHub Release object with explicit stable flags.

    A tag-shaped dict is not a release. Missing draft/prerelease keys are
    not treated as stable; that would fabricate a designation.
    """
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag or is_unstable_name(tag):
        return False
    if "draft" not in release or "prerelease" not in release:
        return False
    if release.get("draft") is not False or release.get("prerelease") is not False:
        return False
    return parse_tag(tag) is not None


def is_version_tag(tag: str) -> bool:
    """True for a version-shaped tag without an explicit instability marker.

    This is latest-version discovery, not a stability designation.
    """
    return bool(tag) and not is_unstable_name(tag) and parse_tag(tag) is not None


def designation_label(origin: str, stability: str) -> str:
    if origin == ORIGIN_RELEASE and stability == STABILITY_STABLE:
        return DESIGNATION_STABLE_RELEASE
    if origin == ORIGIN_TAG and stability == STABILITY_UNAVAILABLE:
        return DESIGNATION_TAG_UNAVAILABLE
    raise LatestAwgError(
        f"cannot classify stability designation origin={origin} stability={stability}"
    )


def classify_origin_and_stability(releases: list[dict[str, Any]]) -> tuple[str, str]:
    if any(is_stable_release(item) for item in releases):
        return ORIGIN_RELEASE, STABILITY_STABLE
    return ORIGIN_TAG, STABILITY_UNAVAILABLE


def asset_hashes(release: dict[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for asset in release.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        digest = asset.get("digest")
        if not isinstance(name, str) or not isinstance(digest, str):
            continue
        if digest.startswith("sha256:"):
            hashes[name] = digest.split(":", 1)[1].lower()
    return hashes


def first_match(text: str, patterns: tuple[str, ...]) -> str:
    matches: list[tuple[int, int, str]] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            value = unwrap_assignment(match.group(1))
            if value:
                matches.append((match.start(), match.end(), value))
    unique = {(start, end, value) for start, end, value in matches}
    if len(unique) > 1:
        raise LatestAwgError(
            "AWG source contains duplicate, comment-shadowed, or ambiguous assignments"
        )
    if not unique:
        return ""
    return next(iter(unique))[2]


def parse_windows_installer_digest_map(text: str) -> dict[str, str]:
    """Parse the reviewed x64/arm64 MSI digest map from the installer source."""
    if len(WINDOWS_INSTALLER_DIGEST_ASSIGNMENT_RE.findall(text)) != 1:
        raise LatestAwgError(
            "Windows installer must contain exactly one $AmneziaWgSha256 assignment"
        )
    matches = list(WINDOWS_INSTALLER_DIGEST_MAP_RE.finditer(text))
    if len(matches) != 1:
        raise LatestAwgError(
            "Windows installer must contain exactly one architecture-keyed "
            "$AmneziaWgSha256 map"
        )
    values: dict[str, str] = {}
    for raw_line in matches[0].group("body").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        entry = WINDOWS_INSTALLER_DIGEST_ENTRY_RE.fullmatch(line.rstrip(","))
        if entry is None:
            raise LatestAwgError(
                "Windows installer contains a malformed architecture MSI digest entry"
            )
        architecture = entry.group("architecture")
        if architecture not in WINDOWS_INSTALLER_ARCHITECTURE_ASSETS:
            raise LatestAwgError(
                f"Windows installer contains an unreviewed MSI architecture {architecture}"
            )
        if architecture in values:
            raise LatestAwgError(
                f"Windows installer contains duplicate MSI architecture {architecture}"
            )
        values[architecture] = entry.group("digest")
    expected_architectures = set(WINDOWS_INSTALLER_ARCHITECTURE_ASSETS)
    if set(values) != expected_architectures:
        missing = sorted(expected_architectures - set(values))
        extra = sorted(set(values) - expected_architectures)
        raise LatestAwgError(
            "Windows installer MSI digest map must cover exactly x64 and arm64 "
            f"(missing={missing or 'none'} extra={extra or 'none'})"
        )
    return values


UNAVAILABLE_STABILITY_SOURCES = {
    "amneziawg-go": (
        "tools/build_linux_arm64_awg.sh",
        "tools/build_amneziawg_android_engine.sh",
        "tools/build_apple_wg_go_bridge.sh",
        "windows/awg_engine/go.mod",
        "docs/AMNEZIAWG_ENGINE_PROVENANCE.md",
    ),
    "amneziawg-apple": ("tools/build_apple_wg_go_bridge.sh",),
}
MISLEADING_STABILITY_PATTERNS = (
    re.compile(r"latest[- ]stable\s+(?:go|apple|awg|engine)\b", re.IGNORECASE),
    re.compile(r"\b(?:go|apple|awg|engine)[^\n]{0,120}latest[- ]stable\b", re.IGNORECASE),
    re.compile(r"official GitHub tags:\s*latest stable\b", re.IGNORECASE),
    re.compile(r"\btag is latest stable\b", re.IGNORECASE),
    re.compile(r"\blatest[- ]stable identities\b", re.IGNORECASE),
    re.compile(r"\bis not latest stable\b", re.IGNORECASE),
    re.compile(r"\balready match latest stable\b", re.IGNORECASE),
)
GENERIC_UNAVAILABLE_STABILITY_SOURCES = frozenset(
    {
        "tools/build_apple_wg_go_bridge.sh",
        "windows/awg_engine/go.mod",
    }
)


def evaluate_stability_label_text(
    files: dict[str, str],
    frozen: dict[str, FrozenRelease],
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for component, relatives in UNAVAILABLE_STABILITY_SOURCES.items():
        release = frozen.get(component)
        if release is None or release.stability != STABILITY_UNAVAILABLE:
            continue
        for relative in relatives:
            text = files.get(relative)
            if text is None:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                patterns = MISLEADING_STABILITY_PATTERNS
                if relative in GENERIC_UNAVAILABLE_STABILITY_SOURCES:
                    patterns = patterns + (
                        re.compile(r"latest[- ]stable\b", re.IGNORECASE),
                    )
                for pattern in patterns:
                    match = pattern.search(line)
                    if match is None:
                        continue
                    key = (relative, line_number)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            "fabricated_release_status",
                            relative,
                            f"{component} has no release stability designation but line "
                            f"{line_number} says {match.group(0)!r}",
                        )
                    )
    return findings


def evaluate_stability_labels(
    root: pathlib.Path,
    frozen: dict[str, FrozenRelease],
) -> list[Finding]:
    files = {
        relative: (root / relative).read_text(encoding="utf-8")
        for relatives in UNAVAILABLE_STABILITY_SOURCES.values()
        for relative in relatives
        if (root / relative).is_file()
    }
    return evaluate_stability_label_text(files, frozen)


def discover_latest(client: ReleaseClient) -> dict[str, FrozenRelease]:
    frozen: dict[str, FrozenRelease] = {}
    for component, slug in COMPONENTS.items():
        metadata = client.repo_metadata(slug)
        if metadata.get("archived"):
            raise LatestAwgError(f"official repository is archived: {slug}")
        owner = str((metadata.get("owner") or {}).get("login") or slug.split("/", 1)[0])
        if owner != OFFICIAL_OWNER:
            raise LatestAwgError(f"repository is not official amnezia-vpn: {slug}")
        listed_releases = client.list_releases(slug)
        stable_releases = [item for item in listed_releases if is_stable_release(item)]
        origin, stability = classify_origin_and_stability(listed_releases)
        if origin == ORIGIN_RELEASE:
            if not stable_releases:
                raise LatestAwgError(
                    f"{slug} origin=release without a GitHub Release would fabricate status"
                )
            latest = max(stable_releases, key=lambda item: version_key(str(item.get("tag_name"))))
            tag = str(latest.get("tag_name"))
            hashes = asset_hashes(latest)
        else:
            if stable_releases:
                raise LatestAwgError(
                    f"{slug} origin=tag despite a GitHub Release"
                )
            tags = [
                item
                for item in client.list_tags(slug)
                if isinstance(item.get("name"), str) and is_version_tag(str(item.get("name")))
            ]
            if not tags:
                raise LatestAwgError(f"no official version tag or GitHub Release for {slug}")
            latest_tag = max(tags, key=lambda item: version_key(str(item.get("name"))))
            tag = str(latest_tag.get("name"))
            hashes = {}
        designation_label(origin, stability)
        generation = generation_of(tag)
        if not generation or generation in REJECTED_GENERATIONS:
            raise LatestAwgError(
                f"{slug} latest identity {tag} is not an allowed AWG generation"
            )
        commit = client.tag_commit(slug, tag)
        if not SHA_RE.fullmatch(commit):
            raise LatestAwgError(f"{slug} tag {tag} did not freeze to a commit")
        frozen[component] = FrozenRelease(
            component=component,
            slug=slug,
            tag=tag,
            commit=commit.lower(),
            generation=generation,
            origin=origin,
            stability=stability,
            hashes=hashes,
        )
    generations = {item.generation for item in frozen.values()}
    if len(generations) != 1:
        detail = ", ".join(
            f"{item.component}={item.tag}/{item.generation}" for item in frozen.values()
        )
        raise LatestAwgError(f"official latest identities are not one AWG generation: {detail}")
    return frozen


def _classify_ref(value: str) -> tuple[str, str]:
    cleaned = unwrap_assignment(value)
    if SHA_RE.fullmatch(cleaned.lower()):
        return "", cleaned.lower()
    if is_version_tag(cleaned) or parse_tag(cleaned):
        return cleaned, ""
    return cleaned, ""


def collect_repo_sources(root: pathlib.Path) -> list[RepoSource]:
    sources: list[RepoSource] = []
    for spec in SOURCE_SPECS:
        path = root / spec.relative_path
        if not path.is_file():
            sources.append(
                RepoSource(
                    component=spec.component,
                    platform=spec.platform,
                    path=spec.relative_path,
                    kind=spec.kind,
                    repository="",
                    tag="",
                    commit="",
                    digest="",
                    generation="",
                    compare_release_hash=spec.compare_release_hash,
                    release_asset_name=spec.release_asset_name,
                )
            )
            continue
        text = path.read_text(encoding="utf-8")
        if spec.kind == "container":
            match = CONTAINER_RE.search(text)
            tag = ""
            digest = ""
            repository = ""
            if match is not None:
                repository = match.group("image") or ""
                raw_tag = match.group("tag") or ""
                if raw_tag and raw_tag not in {"latest", "stable", "nightly"}:
                    tag = raw_tag
                digest = match.group("digest") or ""
            sources.append(
                RepoSource(
                    component=spec.component,
                    platform=spec.platform,
                    path=spec.relative_path,
                    kind="container",
                    repository=repository,
                    tag=tag,
                    commit="",
                    digest=digest,
                    generation=generation_of(tag) if tag else "",
                )
            )
            continue
        repository = first_match(text, spec.repo_patterns) or spec.default_repository
        raw_tag = first_match(text, spec.tag_patterns)
        raw_commit = first_match(text, spec.commit_patterns)
        tag_from_tag, commit_from_tag = _classify_ref(raw_tag) if raw_tag else ("", "")
        tag_from_commit, commit_from_commit = (
            _classify_ref(raw_commit) if raw_commit else ("", "")
        )
        tag = tag_from_tag or tag_from_commit
        commit = commit_from_commit or commit_from_tag
        if commit and not SHA_RE.fullmatch(commit):
            commit = ""
        digests = {}
        digest = ""
        if spec.digest_map_kind == "windows-installer":
            digests = parse_windows_installer_digest_map(text)
        else:
            digest = first_match(text, spec.hash_patterns).lower()
        sources.append(
            RepoSource(
                component=spec.component,
                platform=spec.platform,
                path=spec.relative_path,
                kind="git",
                repository=repository,
                tag=tag,
                commit=commit,
                digest=digest,
                generation=generation_of(tag) if tag else "",
                digests=digests,
                compare_release_hash=spec.compare_release_hash,
                release_asset_name=spec.release_asset_name,
            )
        )
    return sources


def discover_load_bearing_awg_pin_paths(root: pathlib.Path) -> set[str]:
    discovered: set[str] = set()
    candidates = 0
    for relative_root in AWG_PIN_DISCOVERY_ROOTS:
        base = root / relative_root
        if not base.is_dir() or base.is_symlink():
            continue
        for path in base.rglob("*"):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                info = path.lstat()
                if info.st_size <= 0 or info.st_size > AWG_PIN_DISCOVERY_MAX_BYTES:
                    continue
                with path.open("rb") as handle:
                    prefix = handle.read(2)
                is_script_candidate = (
                    path.suffix.lower() in AWG_PIN_DISCOVERY_SUFFIXES
                    or bool(info.st_mode & 0o111)
                    or prefix == b"#!"
                )
                if not is_script_candidate:
                    continue
                if (
                    path.name.startswith("test_")
                    or path.name.endswith("_test.py")
                    or path.name == "verify_latest_awg_release.py"
                ):
                    continue
                candidates += 1
                if candidates > AWG_PIN_DISCOVERY_MAX_FILES:
                    raise LatestAwgError(
                        "AWG producer discovery exceeded the production file ceiling"
                    )
                text = path.read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeError):
                continue
            if AWG_PIN_DISCOVERY_RE.search(text):
                discovered.add(path.relative_to(root).as_posix())
    return discovered


def evaluate_source_inventory(root: pathlib.Path) -> list[Finding]:
    registered = {spec.relative_path for spec in SOURCE_SPECS}
    findings = [
        Finding(
            "unregistered_awg_pin_source",
            relative,
            "load-bearing AWG identity assignment is absent from production SOURCE_SPECS",
        )
        for relative in sorted(discover_load_bearing_awg_pin_paths(root) - registered)
    ]
    for relative in sorted(PRODUCTION_AWG_SOURCE_PATHS - registered):
        findings.append(
            Finding(
                "missing_awg_inventory_entry",
                relative,
                "explicit production AWG source is absent from SOURCE_SPECS",
            )
        )
    for relative in sorted(registered - PRODUCTION_AWG_SOURCE_PATHS):
        findings.append(
            Finding(
                "unknown_awg_inventory_entry",
                relative,
                "SOURCE_SPECS contains a path outside the explicit production inventory",
            )
        )
    return findings


def _source_label(source: RepoSource) -> str:
    return f"{source.platform}:{source.path}"


def evaluate_sources(
    sources: list[RepoSource],
    frozen: dict[str, FrozenRelease],
) -> list[Finding]:
    findings: list[Finding] = []
    frozen_generation = next(iter({item.generation for item in frozen.values()}))
    identified: set[str] = set()
    for source in sources:
        label = _source_label(source)
        expected = frozen.get(source.component)
        if source.kind == "container":
            if not source.tag or not source.generation:
                findings.append(
                    Finding(
                        "unidentified_container",
                        label,
                        f"{source.repository or 'container'} digest={source.digest or 'none'} has no AWG generation",
                    )
                )
                continue
            identified.add(source.generation)
            rejected = REJECTED_GENERATIONS.get(source.generation)
            if rejected:
                findings.append(
                    Finding(
                        rejected,
                        label,
                        f"server container generation {source.generation} tag={source.tag} is rejected",
                    )
                )
            if expected and source.generation != expected.generation:
                findings.append(
                    Finding(
                        "not_latest",
                        label,
                        f"server container {source.tag} is not frozen {expected.tag}",
                    )
                )
            if expected and source.tag != expected.tag:
                findings.append(
                    Finding(
                        "not_latest",
                        label,
                        f"server container tag {source.tag} is not frozen exact tag {expected.tag}",
                    )
                )
            continue
        if not source.repository and not source.tag and not source.commit:
            findings.append(
                Finding("untagged", label, "platform AWG source pin is missing")
            )
            continue
        slug = parse_github_slug(source.repository) if source.repository else None
        if source.repository and slug is None:
            findings.append(
                Finding(
                    "invalid_repository_origin",
                    label,
                    f"{source.repository} is not an exact reviewed HTTPS github.com origin",
                )
            )
        owner = slug.split("/", 1)[0] if slug else ""
        if owner and owner != OFFICIAL_OWNER:
            findings.append(
                Finding(
                    "archived_fork",
                    label,
                    f"{source.repository} is not official {OFFICIAL_OWNER} (archived/unofficial fork)",
                )
            )
        if not source.tag:
            findings.append(
                Finding(
                    "untagged",
                    label,
                    f"source is untagged commit={source.commit or 'none'}",
                )
            )
        if not source.commit:
            findings.append(
                Finding(
                    "unfrozen_commit",
                    label,
                    "AWG source entry does not bind an exact 40-hex frozen commit",
                )
            )
        if source.generation:
            identified.add(source.generation)
            rejected = REJECTED_GENERATIONS.get(source.generation)
            if rejected:
                findings.append(
                    Finding(
                        rejected,
                        label,
                        f"{source.component} {source.tag} is rejected generation {source.generation}",
                    )
                )
        if expected is None:
            continue
        if source.tag and source.tag != expected.tag:
            findings.append(
                Finding(
                    "not_latest",
                    label,
                    f"{source.component} tag {source.tag} is not frozen latest {expected.tag}",
                )
            )
        if source.commit and source.commit != expected.commit:
            findings.append(
                Finding(
                    "not_latest",
                    label,
                    f"{source.component} commit {source.commit} is not frozen {expected.commit}",
                )
            )
        if source.compare_release_hash and not source.digests:
            if not source.digest:
                findings.append(
                    Finding(
                        "missing_local_hash",
                        label,
                        f"{source.component} local release artifact hash is missing",
                    )
                )
            if not source.release_asset_name:
                findings.append(
                    Finding(
                        "missing_reviewed_hash",
                        label,
                        f"{source.component} compared release asset identity is missing",
                    )
                )
            else:
                expected_digest = expected.hashes.get(source.release_asset_name)
                if expected_digest is None:
                    findings.append(
                        Finding(
                            "missing_reviewed_hash",
                            label,
                            f"{source.component} is missing reviewed asset hash for "
                            f"{source.release_asset_name}",
                        )
                    )
                elif source.digest and source.digest != expected_digest:
                    findings.append(
                        Finding(
                            "not_latest",
                            label,
                            f"{source.component} hash {source.digest} is not the reviewed "
                            f"{source.release_asset_name} digest {expected_digest}",
                        )
                    )
        if source.compare_release_hash and source.digests:
            if not expected.hashes:
                findings.append(
                    Finding(
                        "missing_reviewed_hash",
                        label,
                        f"{source.component} has no reviewed release asset hashes",
                    )
                )
            else:
                for architecture, digest in source.digests.items():
                    asset_template = WINDOWS_INSTALLER_ARCHITECTURE_ASSETS.get(
                        architecture
                    )
                    if asset_template is None:
                        findings.append(
                            Finding(
                                "unreviewed_architecture",
                                label,
                                f"{source.component} has unreviewed architecture {architecture}",
                            )
                        )
                        continue
                    asset_name = asset_template.format(tag=expected.tag)
                    expected_digest = expected.hashes.get(asset_name)
                    if expected_digest is None:
                        findings.append(
                            Finding(
                                "missing_reviewed_hash",
                                label,
                                f"{source.component} is missing reviewed asset hash for {asset_name}",
                            )
                        )
                    elif digest != expected_digest:
                        findings.append(
                            Finding(
                                "not_latest",
                                label,
                                f"{source.component} {architecture} digest {digest} is not "
                                f"the reviewed {asset_name} digest {expected_digest}",
                            )
                        )
    if identified and identified != {frozen_generation}:
        findings.append(
            Finding(
                "incoherent",
                "repo",
                "repo AWG generations "
                + ",".join(sorted(identified))
                + f" are not one coherent latest generation {frozen_generation}",
            )
        )
    return findings


def audit(
    root: pathlib.Path,
    *,
    client: ReleaseClient | None = None,
    frozen: dict[str, FrozenRelease] | None = None,
) -> AuditReport:
    discovered = frozen if frozen is not None else discover_latest(
        client or LiveGitHubClient()
    )
    sources = collect_repo_sources(root)
    findings = evaluate_sources(sources, discovered)
    findings.extend(evaluate_source_inventory(root))
    findings.extend(evaluate_stability_labels(root, discovered))
    return AuditReport(
        frozen=discovered,
        sources=tuple(sources),
        findings=tuple(findings),
    )


def format_frozen(frozen: dict[str, FrozenRelease]) -> str:
    lines = []
    for component in COMPONENTS:
        item = frozen[component]
        hash_note = f" hashes={len(item.hashes)}" if item.hashes else ""
        lines.append(
            f"FROZEN {component} tag={item.tag} commit={item.commit} "
            f"generation={item.generation} origin={item.origin} "
            f"stability={item.stability} ({item.designation}){hash_note}"
        )
    return "\n".join(lines)


def verify_latest_awg_release(
    root: pathlib.Path | None = None,
    *,
    client: ReleaseClient | None = None,
    frozen: dict[str, FrozenRelease] | None = None,
) -> AuditReport:
    report = audit(
        root or pathlib.Path(__file__).resolve().parent.parent,
        client=client,
        frozen=frozen,
    )
    print(format_frozen(report.frozen))
    if report.findings:
        for finding in report.findings:
            print(f"FAIL {finding.code}: {finding.source}: {finding.detail}", file=sys.stderr)
        raise LatestAwgError(
            f"latest AWG audit failed ({len(report.findings)} finding(s)); "
            f"frozen generation={report.frozen_generation}"
        )
    print(f"PASS latest AWG identities: generation={report.frozen_generation}")
    return report


def main() -> int:
    try:
        verify_latest_awg_release()
    except Exception as exc:
        print(f"FAIL latest AWG release: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
