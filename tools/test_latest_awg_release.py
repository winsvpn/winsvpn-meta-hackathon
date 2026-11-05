#!/usr/bin/env python3
"""Offline fixture tests for the latest AWG identity audit gate."""

from __future__ import annotations

import copy
import io
import pathlib
import re
import ssl
import sys
import tempfile
import unittest
import urllib.error
from typing import Any
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_latest_awg_release as latest_awg  # noqa: E402


LATEST_FIXTURES: dict[str, dict[str, Any]] = {
    "amnezia-vpn/amneziawg-tools": {
        "metadata": {
            "archived": False,
            "owner": {"login": "amnezia-vpn"},
        },
        "releases": [
            {
                "tag_name": "v3.2.0-rc1",
                "draft": False,
                "prerelease": True,
                "assets": [],
            },
            {
                "tag_name": "v3.9.0",
                "draft": True,
                "prerelease": False,
                "assets": [],
            },
            {
                "tag_name": "v3.1.20260812",
                "draft": False,
                "prerelease": False,
                "assets": [
                    {
                        "name": "ubuntu-22.04-amneziawg-tools.zip",
                        "digest": "sha256:919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56",
                    }
                ],
            },
            {
                "tag_name": "v1.0.20260618-2",
                "draft": False,
                "prerelease": False,
                "assets": [],
            },
        ],
        "tags": [
            {"name": "v3.2.20260820-nightly", "commit": {"sha": "a" * 40}},
            {"name": "v3.1.20260812", "commit": {"sha": "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"}},
            {"name": "v1.0.20260618-2", "commit": {"sha": "61e741780e8465a67a7d7fb6cffe14a8a15d624a"}},
        ],
        "tag_commits": {
            "v3.1.20260812": "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843",
        },
    },
    "amnezia-vpn/amneziawg-go": {
        "metadata": {
            "archived": False,
            "owner": {"login": "amnezia-vpn"},
        },
        "releases": [],
        "tags": [
            {"name": "v3.1.20260828", "commit": {"sha": "b5928efb6ca19f0153958460c3d141f04abc5c2e"}},
            {"name": "v3.0.20260805", "commit": {"sha": "08d68cdae27762c3e07f36bbb12d2bad32f81926"}},
            {"name": "v0.2.19", "commit": {"sha": "1cc94272ca8e9e223a5fe76382f5880f09d3c12d"}},
            {"name": "v0.2.14-beta-awg-1.5", "commit": {"sha": "b" * 40}},
        ],
        "tag_commits": {
            "v3.1.20260828": "b5928efb6ca19f0153958460c3d141f04abc5c2e",
        },
    },
    "amnezia-vpn/amneziawg-android": {
        "metadata": {
            "archived": False,
            "owner": {"login": "amnezia-vpn"},
        },
        "releases": [
            {
                "tag_name": "v3.1.20260814",
                "draft": False,
                "prerelease": False,
                "assets": [
                    {
                        "name": "AmneziaWG-3.1.202060814.apk",
                        "digest": "sha256:74f109a948f012e8b90b4055e98bb9bee77bbb8e5d0fe7d5a057dd9698009697",
                    }
                ],
            },
            {
                "tag_name": "v2.0.2",
                "draft": False,
                "prerelease": False,
                "assets": [],
            },
        ],
        "tags": [
            {"name": "v3.1.20260814", "commit": {"sha": "5c16489e2cd9ed3a0a7a27c7445bba5238132f86"}},
        ],
        "tag_commits": {
            "v3.1.20260814": "5c16489e2cd9ed3a0a7a27c7445bba5238132f86",
        },
    },
    "amnezia-vpn/amneziawg-apple": {
        "metadata": {
            "archived": False,
            "owner": {"login": "amnezia-vpn"},
        },
        "releases": [],
        "tags": [
            {"name": "v3.1.20260814", "commit": {"sha": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"}},
            {"name": "v2.0.2", "commit": {"sha": "0c4d98d1bd927bbba1c3b23c382c3f8881fd6631"}},
            {"name": "v3.2.0-beta.1", "commit": {"sha": "c" * 40}},
        ],
        "tag_commits": {
            "v3.1.20260814": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
        },
    },
    "amnezia-vpn/amneziawg-windows": {
        "metadata": {
            "archived": False,
            "owner": {"login": "amnezia-vpn"},
        },
        "releases": [],
        "tags": [
            {"name": "v3.1.20260814", "commit": {"sha": "e90531d15802cb976773f3b63443bc281f738ca3"}},
            {"name": "v3.0.2", "commit": {"sha": "575626d8f8aa5b64114cf378a08e54bf852d909b"}},
        ],
        "tag_commits": {
            "v3.1.20260814": "e90531d15802cb976773f3b63443bc281f738ca3",
        },
    },
    "amnezia-vpn/amneziawg-windows-client": {
        "metadata": {
            "archived": False,
            "owner": {"login": "amnezia-vpn"},
        },
        "releases": [
            {
                "tag_name": "3.1.0",
                "draft": False,
                "prerelease": False,
                "assets": [
                    {
                        "name": "amneziawg-amd64-3.1.0.msi",
                        "digest": "sha256:a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b",
                    },
                    {
                        "name": "amneziawg-arm64-3.1.0.msi",
                        "digest": "sha256:3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa",
                    }
                ],
            },
            {
                "tag_name": "2.0.1",
                "draft": False,
                "prerelease": False,
                "assets": [],
            },
        ],
        "tags": [
            {"name": "3.1.0", "commit": {"sha": "ca5dd3b983bd19c335ab095ccd21fc2f804ec968"}},
        ],
        "tag_commits": {
            "3.1.0": "ca5dd3b983bd19c335ab095ccd21fc2f804ec968",
        },
    },
}


class FixtureClient:
    def __init__(self, repos: dict[str, dict[str, Any]]) -> None:
        self.repos = repos
        self.calls: list[tuple[str, str]] = []

    def _repo(self, slug: str) -> dict[str, Any]:
        try:
            return self.repos[slug]
        except KeyError as exc:
            raise latest_awg.LatestAwgError(f"fixture missing {slug}") from exc

    def repo_metadata(self, slug: str) -> dict[str, Any]:
        self.calls.append(("metadata", slug))
        return self._repo(slug)["metadata"]

    def list_releases(self, slug: str) -> list[dict[str, Any]]:
        self.calls.append(("releases", slug))
        return list(self._repo(slug).get("releases") or [])

    def list_tags(self, slug: str) -> list[dict[str, Any]]:
        self.calls.append(("tags", slug))
        return list(self._repo(slug).get("tags") or [])

    def tag_commit(self, slug: str, tag: str) -> str:
        self.calls.append(("commit", f"{slug}@{tag}"))
        mapped = (self._repo(slug).get("tag_commits") or {}).get(tag)
        if isinstance(mapped, str):
            return mapped
        for item in self.list_tags(slug):
            if item.get("name") == tag:
                sha = ((item.get("commit") or {}).get("sha"))
                if isinstance(sha, str):
                    return sha
        raise latest_awg.LatestAwgError(f"fixture tag missing {slug} {tag}")


class FakeGitHubResponse(io.BytesIO):
    def __init__(
        self,
        payload: bytes,
        *,
        url: str,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(payload)
        self._url = url
        self._status = status
        self.headers = headers or {"Content-Type": "application/json"}

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self._status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class FakeGitHubOpener:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, int]] = []

    def open(self, request, *, timeout: int):
        self.calls.append((request.get_method(), request.full_url, timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def _write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_current_like_tree(root: pathlib.Path) -> None:
    _write(
        root / "tools/build_linux_release.sh",
        'AWG_TOOLS_VERSION="v1.0.20260618-2"\n'
        'AWG_TOOLS_ARCHIVE_SHA256="9f645117ba1aa536c8358e2c682a54cc3949e65b9efb86d8495d4343dcee99f9"\n'
        'AWG_GO_COMMIT="c1e9bb3758e71bb1adc402598465565bfc9663fd"\n',
    )
    _write(
        root / "tools/build_linux_arm64_awg.sh",
        'AWG_TOOLS_VERSION="v1.0.20260618-2"\n'
        'AWG_TOOLS_COMMIT="61e741780e8465a67a7d7fb6cffe14a8a15d624a"\n'
        'AWG_TOOLS_SOURCE_SHA256="cbda09c90d0740b6c3d39622da9f96cfdc2b83459d45973aadd7bf77518fdf10"\n'
        'AWG_TOOLS_UBUNTU_ZIP_SHA256="9f645117ba1aa536c8358e2c682a54cc3949e65b9efb86d8495d4343dcee99f9"\n'
        'AWG_GO_TAG="v0.2.19"\n'
        'AWG_GO_COMMIT="1cc94272ca8e9e223a5fe76382f5880f09d3c12d"\n'
        'AWG_GO_SOURCE_SHA256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n',
    )
    _write(
        root / "tools/build_windows_awg_engine.ps1",
        "$engineVersion = 'v0.2.19'\n"
        "$engineCommit = '1cc94272ca8e9e223a5fe76382f5880f09d3c12d'\n"
        "$engineRepository = 'https://github.com/amnezia-vpn/amneziawg-go.git'\n",
    )
    _write(
        root / "tools/build_amneziawg_android_engine.sh",
        'AWG_ANDROID_REPO="https://github.com/zaneschepke/amneziawg-android.git"\n'
        'AWG_ANDROID_TAG="v2.3.7"\n'
        'AWG_ANDROID_COMMIT="ffb71fb3bcd15ac011ad7cfbe05f76d150fc37f9"\n',
    )
    _write(
        root / "tools/build_apple_wg_go_bridge.sh",
        'AMNEZIAWG_APPLE_REPO="${AMNEZIAWG_APPLE_REPO:-https://github.com/amnezia-vpn/amneziawg-apple.git}"\n'
        'AMNEZIAWG_APPLE_REF="${AMNEZIAWG_APPLE_REF:-0c4d98d1bd927bbba1c3b23c382c3f8881fd6631}"\n',
    )
    _write(
        root / "tools/build_windows_amneziawg_client.ps1",
        "$windowsLibraryRepository = 'https://github.com/amnezia-vpn/amneziawg-windows.git'\n"
        "$windowsLibraryVersion = 'v0.1.4'\n"
        "$windowsLibraryCommit = 'b4707875c602ea91725d9fd4c771a7cc469fdacd'\n"
        "$sourceRepository = 'https://github.com/amnezia-vpn/amneziawg-windows-client.git'\n"
        "$sourceVersion = '2.0.1'\n"
        "$sourceCommit = '8e0e3784143cc06de5422d09d9b6cd1d352dfeb4'\n",
    )
    _write(
        root / "installer/windows/build_installer.ps1",
        '$AmneziaWgVersion = "2.0.1"\n'
        '$AmneziaWgSha256 = @{\n'
        "    'x64' = 'a0fa81022a6e0204b67c92f0046aaebac923bf6ffc786f503c5acff483807b4a'\n"
        "    'arm64' = 'a0fa81022a6e0204b67c92f0046aaebac923bf6ffc786f503c5acff483807b4a'\n"
        '}[$TargetArchitecture]\n'
        '$AmneziaWgSourceCommit = "8e0e3784143cc06de5422d09d9b6cd1d352dfeb4"\n',
    )
    image = (
        "amneziavpn/amneziawg-go@sha256:"
        "acef5ae84808a9568448e9d8c7a96f640a5ccc590b0f8dfbc2df9f9dc0e848c9"
    )
    _write(
        root / "server/wins_data_plane_setup_ONETOUCH.sh",
        f'AWG_DOCKER_IMAGES_DEFAULT="${{AWG_DOCKER_IMAGES:-{image}}}"\n',
    )
    _write(
        root / "server/wins_core_server_setup_ONETOUCH.sh",
        f'AWG_DOCKER_IMAGES="${{AWG_DOCKER_IMAGES:-{image}}}"\n',
    )
    _write(
        root / "winn_protocol_experimental/scripts/build_winn_awg_engine.sh",
        "upstream_tag=v0.2.19\n"
        "upstream_commit=c1e9bb3758e71bb1adc402598465565bfc9663fd\n"
        "upstream_github_archive_sha256="
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    _write(
        root / "windows/awg_engine/go.mod",
        "github.com/amnezia-vpn/amneziawg-go v0.2.19\n"
        "1cc94272ca8e9e223a5fe76382f5880f09d3c12d\n",
    )
    _write(
        root / "server/build_amneziawg_go_server_image.sh",
        'AWG_GO_TAG="v0.2.19"\n'
        'AWG_GO_COMMIT="c1e9bb3758e71bb1adc402598465565bfc9663fd"\n'
        'AWG_GO_SOURCE_SHA256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n',
    )


def write_latest_tree(root: pathlib.Path) -> None:
    _write(
        root / "tools/build_linux_release.sh",
        'AWG_TOOLS_VERSION="v3.1.20260812"\n'
        'AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"\n'
        'AWG_TOOLS_ARCHIVE_SHA256="919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56"\n'
        'AWG_GO_TAG="v3.1.20260828"\n'
        'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"\n',
    )
    _write(
        root / "tools/build_linux_arm64_awg.sh",
        'AWG_TOOLS_VERSION="v3.1.20260812"\n'
        'AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"\n'
        'AWG_TOOLS_SOURCE_SHA256="dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493"\n'
        'AWG_TOOLS_UBUNTU_ZIP_SHA256="919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56"\n'
        'AWG_GO_TAG="v3.1.20260828"\n'
        'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"\n'
        'AWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"\n',
    )
    _write(
        root / "tools/build_windows_awg_engine.ps1",
        "$engineVersion = 'v3.1.20260828'\n"
        "$engineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'\n"
        "$engineRepository = 'https://github.com/amnezia-vpn/amneziawg-go.git'\n"
        "$engineSourceArchiveSha256 = "
        "'10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4'\n",
    )
    _write(
        root / "tools/build_amneziawg_android_engine.sh",
        'AWG_ANDROID_REPO="https://github.com/amnezia-vpn/amneziawg-android.git"\n'
        'AWG_ANDROID_TAG="v3.1.20260814"\n'
        'AWG_ANDROID_COMMIT="5c16489e2cd9ed3a0a7a27c7445bba5238132f86"\n'
        'AWG_GO_TAG="v3.1.20260828"\n'
        'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"\n'
        'AWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"\n',
    )
    _write(
        root / "tools/build_apple_wg_go_bridge.sh",
        'AMNEZIAWG_APPLE_REPO="https://github.com/amnezia-vpn/amneziawg-apple.git"\n'
        'AMNEZIAWG_APPLE_TAG="v3.1.20260814"\n'
        'AMNEZIAWG_APPLE_COMMIT="fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"\n'
        'AMNEZIAWG_GO_TAG="v3.1.20260828"\n'
        'AMNEZIAWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"\n'
        'AMNEZIAWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"\n',
    )
    _write(
        root / "tools/build_windows_amneziawg_client.ps1",
        "$windowsLibraryRepository = 'https://github.com/amnezia-vpn/amneziawg-windows.git'\n"
        "$windowsLibraryVersion = 'v3.1.20260814'\n"
        "$windowsLibraryCommit = 'e90531d15802cb976773f3b63443bc281f738ca3'\n"
        "$sourceRepository = 'https://github.com/amnezia-vpn/amneziawg-windows-client.git'\n"
        "$sourceVersion = '3.1.0'\n"
        "$sourceCommit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'\n"
        "$engineVersion = 'v3.1.20260828'\n"
        "$engineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'\n"
        "$engineSourceArchiveSha256 = "
        "'10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4'\n",
    )
    _write(
        root / "installer/windows/build_installer.ps1",
        '$AmneziaWgVersion = "3.1.0"\n'
        '$AmneziaWgSha256 = @{\n'
        "    'x64' = 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b'\n"
        "    'arm64' = '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa'\n"
        '}[$TargetArchitecture]\n'
        '$AmneziaWgSourceCommit = "ca5dd3b983bd19c335ab095ccd21fc2f804ec968"\n',
    )
    image = "amneziavpn/amneziawg-go:v3.1.20260828@sha256:" + ("d" * 64)
    _write(
        root / "server/wins_data_plane_setup_ONETOUCH.sh",
        f"AWG_DOCKER_IMAGES={image}\n",
    )
    _write(
        root / "server/wins_core_server_setup_ONETOUCH.sh",
        f"AWG_DOCKER_IMAGES={image}\n",
    )
    _write(
        root / "winn_protocol_experimental/scripts/build_winn_awg_engine.sh",
        "upstream_tag=v3.1.20260828\n"
        "upstream_commit=b5928efb6ca19f0153958460c3d141f04abc5c2e\n"
        "upstream_github_archive_sha256="
        "10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4\n",
    )
    _write(
        root / "windows/awg_engine/go.mod",
        "require (\n"
        "\tgithub.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828\n"
        ")\n"
        "// b5928efb6ca19f0153958460c3d141f04abc5c2e. GitHub archive SHA-256\n"
        "// 10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4. That is\n",
    )
    _write(
        root / "server/build_amneziawg_go_server_image.sh",
        'AWG_GO_TAG="v3.1.20260828"\n'
        'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"\n'
        'AWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"\n'
        'AWG_TOOLS_TAG="v3.1.20260812"\n'
        'AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"\n'
        'AWG_TOOLS_SOURCE_SHA256="dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493"\n',
    )
    _write(
        root / "android/devicecheck/build_devicecheck.sh",
        'AWG_GO_VERSION="v3.1.20260828"\n'
        'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"\n',
    )
    _write(
        root / "android/devicecheck/awgresponder/go.mod",
        "require github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828\n"
        "// AWG_GO_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e\n",
    )
    _write(
        root / "tools/build_apple_engine_wrappers.sh",
        'APPLE_AWG_EXPECTED_TAG="v3.1.20260814"\n'
        'APPLE_AWG_EXPECTED_COMMIT="fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"\n',
    )
    _write(
        root / "tools/stage_apple_engine_artifacts.sh",
        'APPLE_AWG_EXPECTED_TAG="v3.1.20260814"\n'
        'APPLE_AWG_EXPECTED_COMMIT="fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"\n',
    )
    _write(
        root / "tools/apple_cross_store_artifact_gate.py",
        'REVIEWED_AWG_SOURCE = {\n'
        '    "commit": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",\n'
        '    "tag": "v3.1.20260814",\n'
        '}\n',
    )
    _write(
        root / "tools/gcp_deployment_inputs.py",
        'REVIEWED_AWG_GO_TAG = "v3.1.20260828"\n'
        'REVIEWED_AWG_GO_COMMIT = "b5928efb6ca19f0153958460c3d141f04abc5c2e"\n'
        'REVIEWED_AWG_TOOLS_TAG = "v3.1.20260812"\n'
        'REVIEWED_AWG_TOOLS_COMMIT = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"\n',
    )
    _write(
        root / "tools/windows_cross_store_artifact_gate.py",
        'AWG_GO_VERSION = "v3.1.20260828"\n'
        'AWG_GO_COMMIT = "b5928efb6ca19f0153958460c3d141f04abc5c2e"\n',
    )
    _write(
        root / "installer/windows/build_store_msix.ps1",
        "$AmneziaWgVersion = '3.1.0'\n"
        "$AmneziaWgSourceCommit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'\n"
        "$AmneziaWgWindowsLibraryVersion = 'v3.1.20260814'\n"
        "$AmneziaWgWindowsLibraryCommit = 'e90531d15802cb976773f3b63443bc281f738ca3'\n"
        "$AmneziaWgEngineVersion = 'v3.1.20260828'\n"
        "$AmneziaWgEngineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'\n",
    )
    _write(
        root / "installer/windows/build_zip_installer.ps1",
        "$ZipX64DependencyContract = [ordered]@{\n"
        "    amneziawg_client_version = '3.1.0'\n"
        "    amneziawg_source_commit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'\n"
        "    amneziawg_engine_version = 'v3.1.20260828'\n"
        "    amneziawg_engine_commit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'\n"
        "}\n"
        "$ZipArm64DependencyContract = [ordered]@{\n"
        "    amneziawg_client_version = '3.1.0'\n"
        "    amneziawg_source_commit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'\n"
        "    amneziawg_engine_version = 'v3.1.20260828'\n"
        "    amneziawg_engine_commit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'\n"
        "}\n",
    )
    _write(
        root / "installer/windows/install_winsvpn_zip.ps1",
        "$ExpectedDependencyContract = [ordered]@{\n"
        "    amneziawg_client_version = '3.1.0'\n"
        "    amneziawg_source_commit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'\n"
        "    amneziawg_engine_version = 'v3.1.20260828'\n"
        "    amneziawg_engine_commit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'\n"
        "}\n"
        "$ExpectedArm64DependencyContract = [ordered]@{\n"
        "    amneziawg_client_version = '3.1.0'\n"
        "    amneziawg_source_commit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'\n"
        "    amneziawg_engine_version = 'v3.1.20260828'\n"
        "    amneziawg_engine_commit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'\n"
        "}\n",
    )
    _write(
        root / "tools/verify_deployment_supply_chain.py",
        'WINDOWS_AMNEZIAWG_SOURCE_VERSION = "3.1.0"\n'
        'WINDOWS_AMNEZIAWG_SOURCE_COMMIT = "ca5dd3b983bd19c335ab095ccd21fc2f804ec968"\n'
        'WINDOWS_AMNEZIAWG_LIBRARY_VERSION = "v3.1.20260814"\n'
        'WINDOWS_AMNEZIAWG_LIBRARY_COMMIT = "e90531d15802cb976773f3b63443bc281f738ca3"\n'
        'WINDOWS_AMNEZIAWG_ENGINE_VERSION = "v3.1.20260828"\n'
        'WINDOWS_AMNEZIAWG_ENGINE_COMMIT = "b5928efb6ca19f0153958460c3d141f04abc5c2e"\n'
        'AMNEZIAWG_ANDROID_ENGINE_TAG = "v3.1.20260814"\n'
        'AMNEZIAWG_ANDROID_ENGINE_COMMIT = "5c16489e2cd9ed3a0a7a27c7445bba5238132f86"\n',
    )


class LatestAwgReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FixtureClient(LATEST_FIXTURES)

    def test_discovery_freezes_exact_latest_identities(self) -> None:
        frozen = latest_awg.discover_latest(self.client)
        self.assertEqual(frozen["amneziawg-tools"].tag, "v3.1.20260812")
        self.assertEqual(
            frozen["amneziawg-tools"].commit,
            "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843",
        )
        self.assertEqual(
            frozen["amneziawg-tools"].hashes["ubuntu-22.04-amneziawg-tools.zip"],
            "919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56",
        )
        self.assertEqual(frozen["amneziawg-tools"].origin, "release")
        self.assertEqual(frozen["amneziawg-tools"].stability, "stable")
        self.assertEqual(
            frozen["amneziawg-tools"].designation,
            "latest stable GitHub Release",
        )
        self.assertEqual(frozen["amneziawg-go"].tag, "v3.1.20260828")
        self.assertEqual(
            frozen["amneziawg-go"].commit,
            "b5928efb6ca19f0153958460c3d141f04abc5c2e",
        )
        self.assertEqual(frozen["amneziawg-go"].origin, "tag")
        self.assertEqual(frozen["amneziawg-go"].stability, "unavailable")
        self.assertEqual(frozen["amneziawg-go"].hashes, {})
        self.assertEqual(
            frozen["amneziawg-go"].designation,
            "latest upstream tag; stability designation unavailable",
        )
        self.assertEqual(frozen["amneziawg-android"].tag, "v3.1.20260814")
        self.assertEqual(frozen["amneziawg-android"].origin, "release")
        self.assertEqual(frozen["amneziawg-android"].stability, "stable")
        self.assertEqual(frozen["amneziawg-apple"].tag, "v3.1.20260814")
        self.assertEqual(
            frozen["amneziawg-apple"].commit,
            "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
        )
        self.assertEqual(frozen["amneziawg-apple"].origin, "tag")
        self.assertEqual(frozen["amneziawg-apple"].stability, "unavailable")
        self.assertEqual(frozen["amneziawg-windows"].tag, "v3.1.20260814")
        self.assertEqual(frozen["amneziawg-windows"].origin, "tag")
        self.assertEqual(frozen["amneziawg-windows"].stability, "unavailable")
        self.assertEqual(
            frozen["amneziawg-windows"].commit,
            "e90531d15802cb976773f3b63443bc281f738ca3",
        )
        self.assertEqual(frozen["amneziawg-windows-client"].tag, "3.1.0")
        self.assertEqual(frozen["amneziawg-windows-client"].origin, "release")
        self.assertEqual(frozen["amneziawg-windows-client"].stability, "stable")
        self.assertEqual({item.generation for item in frozen.values()}, {"3.1"})

    def test_discovery_excludes_prerelease_draft_and_nightly(self) -> None:
        frozen = latest_awg.discover_latest(self.client)
        tags = {item.tag for item in frozen.values()}
        self.assertNotIn("v3.2.0-rc1", tags)
        self.assertNotIn("v3.9.0", tags)
        self.assertNotIn("v3.2.20260820-nightly", tags)
        self.assertNotIn("v3.2.0-beta.1", tags)
        self.assertNotIn("v0.2.14-beta-awg-1.5", tags)

    def test_github_repository_origin_is_exact(self) -> None:
        self.assertEqual(
            latest_awg.parse_github_slug(
                "https://github.com/amnezia-vpn/amneziawg-go.git"
            ),
            "amnezia-vpn/amneziawg-go",
        )
        for hostile in (
            "http://github.com/amnezia-vpn/amneziawg-go.git",
            "https://www.github.com/amnezia-vpn/amneziawg-go.git",
            "https://attacker.invalid/cache/github.com/amnezia-vpn/amneziawg-go.git",
            "https://github.com.evil.invalid/amnezia-vpn/amneziawg-go.git",
            "https://user@github.com/amnezia-vpn/amneziawg-go.git",
            "https://github.com:443/amnezia-vpn/amneziawg-go.git",
            "https://github.com/amnezia-vpn/amneziawg-go.git?ref=main",
            "https://github.com/amnezia-vpn/amneziawg-go.git#main",
            "https://github.com/amnezia-vpn/amneziawg-go/extra",
        ):
            with self.subTest(hostile=hostile):
                self.assertIsNone(latest_awg.parse_github_slug(hostile))

    def test_invalid_repository_origin_is_a_release_finding(self) -> None:
        frozen = latest_awg.discover_latest(self.client)
        source = latest_awg.RepoSource(
            component="amneziawg-go",
            platform="hostile-origin",
            path="tools/hostile.sh",
            kind="git",
            repository=(
                "https://attacker.invalid/cache/github.com/"
                "amnezia-vpn/amneziawg-go.git"
            ),
            tag="v3.1.20260828",
            commit="b5928efb6ca19f0153958460c3d141f04abc5c2e",
            digest="",
            generation="3.1",
        )
        findings = latest_awg.evaluate_sources([source], frozen)
        self.assertTrue(
            any(item.code == "invalid_repository_origin" for item in findings)
        )

    def test_live_transport_refuses_redirect_without_second_request(self) -> None:
        url = "https://api.github.com/repos/amnezia-vpn/amneziawg-go"
        redirect = urllib.error.HTTPError(
            url,
            302,
            "Found",
            {"Location": "https://attacker.invalid/collect"},
            io.BytesIO(b"redirect"),
        )
        opener = FakeGitHubOpener([redirect])
        client = object.__new__(latest_awg.LiveGitHubClient)
        client._opener = opener
        with self.assertRaisesRegex(latest_awg.LatestAwgError, "redirect refused"):
            client._get(url)
        self.assertEqual(opener.calls, [("GET", url, 45)])

    def test_live_transport_binds_exact_response_url_and_strict_json(self) -> None:
        url = "https://api.github.com/repos/amnezia-vpn/amneziawg-go"
        hostile = (
            FakeGitHubResponse(
                b"{}",
                url="https://attacker.invalid/response",
            ),
            FakeGitHubResponse(b'{"owner":1,"owner":2}', url=url),
            FakeGitHubResponse(b'{"score":1e400}', url=url),
            FakeGitHubResponse(b'{"score":NaN}', url=url),
        )
        messages = (
            "response URL",
            "duplicate key",
            "non-finite",
            "non-finite",
        )
        for response, message in zip(hostile, messages, strict=True):
            with self.subTest(message=message):
                client = object.__new__(latest_awg.LiveGitHubClient)
                client._opener = FakeGitHubOpener([response])
                with self.assertRaisesRegex(latest_awg.LatestAwgError, message):
                    client._get(url)

        first = (
            "https://api.github.com/repos/amnezia-vpn/amneziawg-go/"
            "tags?per_page=100"
        )
        second = (
            "https://api.github.com/repos/amnezia-vpn/amneziawg-go/"
            "tags?page=2&per_page=100"
        )
        paginated = object.__new__(latest_awg.LiveGitHubClient)
        paginated._opener = FakeGitHubOpener(
            [
                FakeGitHubResponse(
                    b'[{"name":"v3.0.0"}]',
                    url=first,
                    headers={
                        "Content-Type": "application/json",
                        "Link": f'<{second}>; rel="next"',
                    },
                ),
                FakeGitHubResponse(b'[{"name":"v3.1.0"}]', url=second),
            ]
        )
        self.assertEqual(
            [item["name"] for item in paginated.list_tags("amnezia-vpn/amneziawg-go")],
            ["v3.0.0", "v3.1.0"],
        )
        self.assertEqual(len(paginated._opener.calls), 2)

        for hostile_link, message in (
            (
                "https://attacker.invalid/repos/amnezia-vpn/amneziawg-go/"
                "tags?page=2&per_page=100",
                "reviewed origin",
            ),
            (
                "https://api.github.com/repos/attacker/repo/"
                "tags?page=2&per_page=100",
                "exact reviewed endpoint",
            ),
            (
                first,
                "query is not exact",
            ),
        ):
            with self.subTest(hostile_link=hostile_link):
                hostile_client = object.__new__(latest_awg.LiveGitHubClient)
                hostile_client._opener = FakeGitHubOpener(
                    [
                        FakeGitHubResponse(
                            b"[]",
                            url=first,
                            headers={
                                "Content-Type": "application/json",
                                "Link": f'<{hostile_link}>; rel="next"',
                            },
                        )
                    ]
                )
                with self.assertRaisesRegex(latest_awg.LatestAwgError, message):
                    hostile_client.list_tags("amnezia-vpn/amneziawg-go")
                self.assertEqual(len(hostile_client._opener.calls), 1)

        capped = object.__new__(latest_awg.LiveGitHubClient)
        capped._opener = FakeGitHubOpener(
            [
                FakeGitHubResponse(
                    b"[]",
                    url=first,
                    headers={
                        "Content-Type": "application/json",
                        "Link": f'<{second}>; rel="next"',
                    },
                )
            ]
        )
        with (
            mock.patch.object(latest_awg, "GITHUB_API_MAX_PAGES", 1),
            self.assertRaisesRegex(latest_awg.LatestAwgError, "page ceiling"),
        ):
            capped.list_tags("amnezia-vpn/amneziawg-go")

    def test_live_transport_rejects_unreviewed_request_origin(self) -> None:
        client = object.__new__(latest_awg.LiveGitHubClient)
        client._opener = FakeGitHubOpener([])
        with self.assertRaisesRegex(latest_awg.LatestAwgError, "reviewed origin"):
            client._get("https://attacker.invalid/repos/amnezia-vpn/amneziawg-go")
        self.assertEqual(client._opener.calls, [])

    def test_live_transport_bounds_body_headers_and_error_body(self) -> None:
        url = "https://api.github.com/repos/amnezia-vpn/amneziawg-go"
        body_client = object.__new__(latest_awg.LiveGitHubClient)
        body_client._opener = FakeGitHubOpener(
            [FakeGitHubResponse(b'{"long":true}', url=url)]
        )
        with (
            mock.patch.object(latest_awg, "GITHUB_API_MAX_BODY_BYTES", 4),
            self.assertRaisesRegex(latest_awg.LatestAwgError, "byte ceiling"),
        ):
            body_client._get(url)

        header_client = object.__new__(latest_awg.LiveGitHubClient)
        header_client._opener = FakeGitHubOpener(
            [
                FakeGitHubResponse(
                    b"{}",
                    url=url,
                    headers={
                        "Content-Type": "application/json",
                        "X-Extra": "value",
                    },
                )
            ]
        )
        with (
            mock.patch.object(latest_awg, "GITHUB_API_MAX_HEADERS", 1),
            self.assertRaisesRegex(latest_awg.LatestAwgError, "too many headers"),
        ):
            header_client._get(url)

        error = urllib.error.HTTPError(
            url, 500, "Server error", {}, io.BytesIO(b"oversized-error")
        )
        error_client = object.__new__(latest_awg.LiveGitHubClient)
        error_client._opener = FakeGitHubOpener([error])
        with (
            mock.patch.object(latest_awg, "GITHUB_API_MAX_ERROR_BYTES", 4),
            self.assertRaisesRegex(latest_awg.LatestAwgError, "byte ceiling"),
        ):
            error_client._get(url)
        self.assertEqual(len(error_client._opener.calls), 1)

    def test_assignment_parser_rejects_comment_shadow_and_duplicates(self) -> None:
        pattern = (r'(?m)^AWG_GO_TAG="([^"]+)"\s*$',)
        for text in (
            'AWG_GO_TAG="v3.1.20260828"\nAWG_GO_TAG="v0.2.19"\n',
            'AWG_GO_TAG="v3.1.20260828"\nAWG_GO_TAG="v3.1.20260828"\n',
        ):
            with self.subTest(text=text), self.assertRaisesRegex(
                latest_awg.LatestAwgError, "ambiguous assignments"
            ):
                latest_awg.first_match(text, pattern)
        self.assertEqual(
            latest_awg.first_match(
                '# AWG_GO_TAG="v3.1.20260828"\nAWG_GO_TAG="v0.2.19"\n',
                pattern,
            ),
            "v0.2.19",
        )

    def test_annotated_tag_must_end_at_commit(self) -> None:
        client = object.__new__(latest_awg.LiveGitHubClient)
        responses = iter(
            (
                {"object": {"type": "tag", "sha": "a" * 40}},
                {"object": {"type": "blob", "sha": "b" * 40}},
            )
        )
        client._get = lambda _url: next(responses)
        with self.assertRaisesRegex(latest_awg.LatestAwgError, "forbidden object type"):
            client.tag_commit("amnezia-vpn/amneziawg-go", "v3.1.20260828")

    def test_nested_annotated_tag_is_bounded_and_commit_only(self) -> None:
        client = object.__new__(latest_awg.LiveGitHubClient)
        responses = iter(
            (
                {"object": {"type": "tag", "sha": "a" * 40}},
                {"object": {"type": "tag", "sha": "b" * 40}},
                {"object": {"type": "commit", "sha": "c" * 40}},
            )
        )
        client._get = lambda _url: next(responses)
        self.assertEqual(
            client.tag_commit("amnezia-vpn/amneziawg-go", "v3.1.20260828"),
            "c" * 40,
        )

        cycle = object.__new__(latest_awg.LiveGitHubClient)
        cycle._get = lambda _url: {
            "object": {"type": "tag", "sha": "d" * 40}
        }
        with self.assertRaisesRegex(latest_awg.LatestAwgError, "cycle"):
            cycle.tag_commit("amnezia-vpn/amneziawg-go", "v3.1.20260828")

    def test_current_repo_exposes_every_audited_source(self) -> None:
        sources = latest_awg.collect_repo_sources(ROOT)
        labels = {(source.component, source.platform, source.path) for source in sources}
        for spec in latest_awg.SOURCE_SPECS:
            self.assertIn(
                (spec.component, spec.platform, spec.relative_path),
                labels,
            )
            if spec.kind == "git":
                self.assertTrue(spec.commit_patterns, spec.relative_path)
        tag_only = latest_awg.RepoSource(
            component="amneziawg-go",
            platform="hostile-tag-only",
            path="tools/hostile-tag-only.bash",
            kind="git",
            repository="https://github.com/amnezia-vpn/amneziawg-go.git",
            tag="v3.1.20260828",
            commit="",
            digest="",
            generation="3.1",
        )
        frozen = latest_awg.discover_latest(self.client)
        self.assertIn(
            "unfrozen_commit",
            {item.code for item in latest_awg.evaluate_sources([tag_only], frozen)},
        )

    def test_production_inventory_covers_independent_shipping_path_list(self) -> None:
        required = {
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
        registered = {spec.relative_path for spec in latest_awg.SOURCE_SPECS}
        self.assertEqual(required, latest_awg.PRODUCTION_AWG_SOURCE_PATHS)
        self.assertEqual(required, registered)
        self.assertEqual(latest_awg.evaluate_source_inventory(ROOT), [])

    def test_inventory_discovery_rejects_new_unregistered_shipping_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            hostile_paths = (
                tree / "tools/new_shipping_awg_producer.sh",
                tree / "tools/new_shipping_awg_producer.bash",
                tree / "server/new_shipping_awg_producer.custom",
                tree / "installer/windows/new_shipping_awg_producer.odd",
            )
            payload = (
                'AWG_GO_TAG="v3.1.20260828"\n'
                'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"\n'
            )
            _write(hostile_paths[0], payload)
            _write(hostile_paths[1], payload)
            _write(hostile_paths[2], payload)
            hostile_paths[2].chmod(0o700)
            _write(hostile_paths[3], "#!/bin/sh\n" + payload)
            _write(tree / "tools/arbitrary-data.json", payload)
            findings = latest_awg.evaluate_source_inventory(tree)
        self.assertEqual(len(findings), len(hostile_paths))
        self.assertEqual(
            {finding.code for finding in findings}, {"unregistered_awg_pin_source"}
        )
        self.assertEqual(
            {finding.source for finding in findings},
            {path.relative_to(tree).as_posix() for path in hostile_paths},
        )

    def test_current_like_fixture_tree_is_fail_red(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_current_like_tree(tree)
            report = latest_awg.audit(tree, client=self.client)
        self.assertFalse(report.ok)
        codes = {finding.code for finding in report.findings}
        self.assertGreaterEqual(
            codes,
            {
                "old_1x",
                "old_2x",
                "old_v0_2",
                "archived_fork",
                "untagged",
                "unidentified_container",
                "not_latest",
                "incoherent",
            },
        )

    def test_matching_frozen_latest_tree_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            report = latest_awg.audit(tree, client=self.client)
        self.assertEqual(report.findings, ())
        self.assertTrue(report.ok)
        self.assertEqual(report.frozen_generation, "3.1")

    def test_old_generations_are_classified(self) -> None:
        self.assertEqual(latest_awg.generation_of("v1.0.20260618-2"), "1")
        self.assertEqual(latest_awg.generation_of("2.0.1"), "2")
        self.assertEqual(latest_awg.generation_of("v2.3.7"), "2")
        self.assertEqual(latest_awg.generation_of("v0.2.19"), "0.2")
        self.assertEqual(latest_awg.generation_of("v3.1.20260814"), "3.1")
        self.assertEqual(latest_awg.generation_of("3.1.0"), "3.1")

    def test_incoherent_discovered_latests_fail(self) -> None:
        broken = {
            slug: dict(payload) for slug, payload in LATEST_FIXTURES.items()
        }
        broken["amnezia-vpn/amneziawg-windows-client"] = {
            "metadata": {"archived": False, "owner": {"login": "amnezia-vpn"}},
            "releases": [
                {
                    "tag_name": "2.0.2",
                    "draft": False,
                    "prerelease": False,
                    "assets": [],
                }
            ],
            "tags": [],
            "tag_commits": {"2.0.2": "e" * 40},
        }
        with self.assertRaises(latest_awg.LatestAwgError) as raised:
            latest_awg.discover_latest(FixtureClient(broken))
        self.assertIn("not an allowed AWG generation", str(raised.exception))

    def test_mixed_official_latests_are_incoherent(self) -> None:
        broken = {
            slug: dict(payload) for slug, payload in LATEST_FIXTURES.items()
        }
        broken["amnezia-vpn/amneziawg-windows-client"] = {
            "metadata": {"archived": False, "owner": {"login": "amnezia-vpn"}},
            "releases": [
                {
                    "tag_name": "3.0.0",
                    "draft": False,
                    "prerelease": False,
                    "assets": [],
                }
            ],
            "tags": [],
            "tag_commits": {"3.0.0": "f" * 40},
        }
        with self.assertRaises(latest_awg.LatestAwgError) as raised:
            latest_awg.discover_latest(FixtureClient(broken))
        self.assertIn("not one AWG generation", str(raised.exception))

    def test_verify_raises_on_obsolete_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_current_like_tree(tree)
            with self.assertRaises(latest_awg.LatestAwgError):
                latest_awg.verify_latest_awg_release(tree, client=self.client)

    def test_offline_client_never_uses_live_github(self) -> None:
        self.assertFalse(isinstance(self.client, latest_awg.LiveGitHubClient))
        latest_awg.discover_latest(self.client)
        self.assertTrue(self.client.calls)
        self.assertFalse(any("api.github.com" in str(item) for item in self.client.calls))

    def test_go_fixture_has_no_github_releases(self) -> None:
        self.assertEqual(LATEST_FIXTURES["amnezia-vpn/amneziawg-go"]["releases"], [])

    def test_origin_and_stability_match_upstream_release_presence(self) -> None:
        frozen = latest_awg.discover_latest(self.client)
        for component, item in frozen.items():
            slug = latest_awg.COMPONENTS[component]
            listed = self.client.list_releases(slug)
            stable = [row for row in listed if latest_awg.is_stable_release(row)]
            if stable:
                self.assertEqual(item.origin, "release", component)
                self.assertEqual(item.stability, "stable", component)
                self.assertEqual(item.designation, "latest stable GitHub Release")
            else:
                self.assertFalse(stable, component)
                self.assertEqual(item.origin, "tag", component)
                self.assertEqual(item.stability, "unavailable", component)
                self.assertEqual(item.hashes, {}, component)
                self.assertEqual(
                    item.designation,
                    "latest upstream tag; stability designation unavailable",
                )

    def test_tag_shaped_dict_does_not_fabricate_a_stable_release(self) -> None:
        self.assertFalse(
            latest_awg.is_stable_release({"tag_name": "v3.1.20260814"})
        )
        self.assertFalse(
            latest_awg.is_stable_release({"name": "v3.1.20260814"})
        )
        self.assertTrue(latest_awg.is_version_tag("v3.1.20260814"))
        self.assertTrue(
            latest_awg.is_stable_release(
                {
                    "tag_name": "v3.1.20260812",
                    "draft": False,
                    "prerelease": False,
                }
            )
        )
        origin, stability = latest_awg.classify_origin_and_stability([])
        self.assertEqual(origin, "tag")
        self.assertEqual(stability, "unavailable")
        self.assertEqual(
            latest_awg.designation_label(origin, stability),
            "latest upstream tag; stability designation unavailable",
        )

    def test_windows_installer_digest_map_is_architecture_keyed_without_temp_tree(
        self,
    ) -> None:
        text = (
            '$AmneziaWgSha256 = @{\n'
            f"    'x64' = '{'a' * 64}'\n"
            f"    'arm64' = '{'b' * 64}'\n"
            '}[$TargetArchitecture]\n'
        )
        self.assertEqual(
            latest_awg.parse_windows_installer_digest_map(text),
            {"x64": "a" * 64, "arm64": "b" * 64},
        )
        scalar = '$AmneziaWgSha256 = "' + ("a" * 64) + '"\n'
        with self.assertRaisesRegex(latest_awg.LatestAwgError, "architecture-keyed"):
            latest_awg.parse_windows_installer_digest_map(scalar)

    def test_windows_installer_architecture_digest_drift_is_rejected_without_temp_tree(
        self,
    ) -> None:
        frozen = latest_awg.discover_latest(self.client)
        source = latest_awg.RepoSource(
            component="amneziawg-windows-client",
            platform="windows-installer",
            path="installer/windows/build_installer.ps1",
            kind="git",
            repository="https://github.com/amnezia-vpn/amneziawg-windows-client.git",
            tag="3.1.0",
            commit="ca5dd3b983bd19c335ab095ccd21fc2f804ec968",
            digest="",
            generation="3.1",
            digests={
                "x64": "0" * 64,
                "arm64": "3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa",
            },
            compare_release_hash=True,
        )
        findings = latest_awg.evaluate_sources([source], frozen)
        self.assertTrue(any(item.code == "not_latest" for item in findings))
        self.assertTrue(any("reviewed amneziawg-amd64-3.1.0.msi" in item.detail for item in findings))

    def test_compared_release_hash_is_required_on_both_sides(self) -> None:
        frozen = latest_awg.discover_latest(self.client)
        source = latest_awg.RepoSource(
            component="amneziawg-tools",
            platform="linux",
            path="tools/build_linux_release.sh",
            kind="git",
            repository="https://github.com/amnezia-vpn/amneziawg-tools.git",
            tag="v3.1.20260812",
            commit="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843",
            digest="",
            generation="3.1",
            compare_release_hash=True,
            release_asset_name="ubuntu-22.04-amneziawg-tools.zip",
        )
        findings = latest_awg.evaluate_sources([source], frozen)
        self.assertTrue(any(item.code == "missing_local_hash" for item in findings))

        tools_release = frozen["amneziawg-tools"]
        frozen["amneziawg-tools"] = latest_awg.FrozenRelease(
            component=tools_release.component,
            slug=tools_release.slug,
            tag=tools_release.tag,
            commit=tools_release.commit,
            generation=tools_release.generation,
            origin=tools_release.origin,
            stability=tools_release.stability,
            hashes={},
        )
        source = latest_awg.RepoSource(
            component=source.component,
            platform=source.platform,
            path=source.path,
            kind=source.kind,
            repository=source.repository,
            tag=source.tag,
            commit=source.commit,
            digest="919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56",
            generation=source.generation,
            compare_release_hash=True,
            release_asset_name=source.release_asset_name,
        )
        findings = latest_awg.evaluate_sources([source], frozen)
        self.assertTrue(any(item.code == "missing_reviewed_hash" for item in findings))

    def test_same_generation_server_tag_drift_is_rejected_without_temp_tree(self) -> None:
        frozen = latest_awg.discover_latest(self.client)
        source = latest_awg.RepoSource(
            component="amneziawg-go",
            platform="server-core",
            path="server/wins_core_server_setup_ONETOUCH.sh",
            kind="container",
            repository="amneziavpn/amneziawg-go",
            tag="v3.1.20260901",
            commit="",
            digest="",
            generation="3.1",
        )
        findings = latest_awg.evaluate_sources([source], frozen)
        self.assertTrue(any(item.code == "not_latest" for item in findings))
        self.assertTrue(any("exact tag v3.1.20260828" in item.detail for item in findings))

    def test_unavailable_stability_label_is_rejected_without_temp_tree(self) -> None:
        frozen = latest_awg.discover_latest(self.client)
        findings = latest_awg.evaluate_stability_label_text(
            {
                "tools/build_apple_wg_go_bridge.sh": (
                    "# Companion latest-stable Go engine\n"
                ),
                "windows/awg_engine/go.mod": (
                    "// latest stable\n"
                ),
            },
            frozen,
        )
        self.assertEqual(
            {item.code for item in findings},
            {"fabricated_release_status"},
        )
        self.assertEqual(
            {item.source for item in findings},
            {
                "tools/build_apple_wg_go_bridge.sh",
                "windows/awg_engine/go.mod",
            },
        )

    def test_newer_go_tag_is_tag_drift_failure(self) -> None:
        drifted = copy.deepcopy(LATEST_FIXTURES)
        newer_commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        drifted["amnezia-vpn/amneziawg-go"]["tags"].insert(
            0,
            {"name": "v3.1.20260901", "commit": {"sha": newer_commit}},
        )
        drifted["amnezia-vpn/amneziawg-go"]["tag_commits"]["v3.1.20260901"] = (
            newer_commit
        )
        client = FixtureClient(drifted)
        frozen = latest_awg.discover_latest(client)
        self.assertEqual(frozen["amneziawg-go"].tag, "v3.1.20260901")
        self.assertEqual(frozen["amneziawg-go"].commit, newer_commit)
        self.assertEqual(frozen["amneziawg-go"].origin, "tag")
        self.assertEqual(frozen["amneziawg-go"].stability, "unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            report = latest_awg.audit(tree, client=client)
        self.assertFalse(report.ok)
        go_drift = [
            finding
            for finding in report.findings
            if finding.code == "not_latest" and "amneziawg-go" in finding.detail
        ]
        self.assertTrue(go_drift)
        self.assertTrue(
            any("v3.1.20260828" in finding.detail for finding in go_drift)
        )
        self.assertTrue(
            any("v3.1.20260901" in finding.detail for finding in go_drift)
        )

    def test_go_prerelease_github_release_is_not_a_stable_release(self) -> None:
        mutated = copy.deepcopy(LATEST_FIXTURES)
        mutated["amnezia-vpn/amneziawg-go"]["releases"] = [
            {
                "tag_name": "v3.1.20260828",
                "draft": False,
                "prerelease": True,
                "assets": [],
            }
        ]
        frozen = latest_awg.discover_latest(FixtureClient(mutated))
        self.assertEqual(frozen["amneziawg-go"].tag, "v3.1.20260828")
        self.assertEqual(frozen["amneziawg-go"].origin, "tag")
        self.assertEqual(frozen["amneziawg-go"].stability, "unavailable")
        self.assertEqual(frozen["amneziawg-go"].hashes, {})
        self.assertEqual(frozen["amneziawg-tools"].origin, "release")
        self.assertEqual(frozen["amneziawg-tools"].stability, "stable")

    def test_format_frozen_reports_go_designation_unavailable(self) -> None:
        frozen = latest_awg.discover_latest(self.client)
        rendered = latest_awg.format_frozen(frozen)
        go_line = next(
            line for line in rendered.splitlines() if line.startswith("FROZEN amneziawg-go ")
        )
        tools_line = next(
            line
            for line in rendered.splitlines()
            if line.startswith("FROZEN amneziawg-tools ")
        )
        self.assertIn("origin=tag", go_line)
        self.assertIn("stability=unavailable", go_line)
        self.assertIn(
            "latest upstream tag; stability designation unavailable",
            go_line,
        )
        self.assertNotIn("latest stable GitHub Release", go_line)
        self.assertIn("origin=release", tools_line)
        self.assertIn("stability=stable", tools_line)
        self.assertIn("latest stable GitHub Release", tools_line)

    def test_live_client_tls_verification_is_fail_closed(self) -> None:
        client = latest_awg.LiveGitHubClient()
        self.assertTrue(client._ssl_context.check_hostname)
        self.assertEqual(client._ssl_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreater(len(client._ssl_context.get_ca_certs()), 0)
        self.assertTrue(
            any(
                isinstance(handler, latest_awg._NoRedirectHandler)
                for handler in client._opener.handlers
            )
        )
        proxy_handlers = [
            handler
            for handler in client._opener.handlers
            if isinstance(handler, latest_awg.urllib.request.ProxyHandler)
        ]
        # build_opener sees the explicit ProxyHandler({}) and suppresses its
        # environment-backed default.  urllib then omits the empty handler
        # itself because it has no protocol_open methods to install.
        self.assertEqual(proxy_handlers, [])

    def test_supply_chain_hooks_the_gate(self) -> None:
        text = (ROOT / "tools/verify_deployment_supply_chain.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("def verify_latest_awg_release()", text)
        self.assertIn("verify_latest_awg_release()", text.split("def main()")[1])
        self.assertIn("import verify_latest_awg_release", text)


FROZEN_GO_TAG = "v3.1.20260828"
FROZEN_GO_COMMIT = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
FROZEN_GO_ARCHIVE = "10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"
FROZEN_TOOLS_TAG = "v3.1.20260812"
FROZEN_TOOLS_COMMIT = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
FROZEN_TOOLS_SOURCE = "dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493"
FROZEN_TOOLS_UBUNTU_ZIP = (
    "919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56"
)
FROZEN_ANDROID_COMMIT = "5c16489e2cd9ed3a0a7a27c7445bba5238132f86"
FROZEN_APPLE_COMMIT = "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"
FROZEN_WINDOWS_CLIENT_TAG = "3.1.0"
FROZEN_WINDOWS_CLIENT_COMMIT = "ca5dd3b983bd19c335ab095ccd21fc2f804ec968"
REJECTED_PRE_V3_COMMIT = "c1e9bb3758e71bb1adc402598465565bfc9663fd"

GO_ENGINE_FILES = (
    "tools/build_windows_awg_engine.ps1",
    "tools/build_windows_amneziawg_client.ps1",
    "tools/build_amneziawg_android_engine.sh",
    "tools/build_apple_wg_go_bridge.sh",
    "tools/build_linux_arm64_awg.sh",
    "winn_protocol_experimental/scripts/build_winn_awg_engine.sh",
    "server/build_amneziawg_go_server_image.sh",
    "windows/awg_engine/go.mod",
)


def _search(text: str, pattern: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    if not match:
        return ""
    return next((item for item in match.groups() if item), "")


def _first_match(text: str, patterns: tuple[str, ...]) -> str:
    for pattern in patterns:
        value = _search(text, pattern)
        if value:
            return value
    return ""


GO_TAG_PATTERNS = (
    r'(?:AWG_GO_TAG|AMNEZIAWG_GO_TAG)="([^"]+)"',
    r"\$engineVersion\s*=\s*'([^']+)'",
    r"^upstream_tag=(\S+)",
    r"github.com/amnezia-vpn/amneziawg-go/v3 (v[0-9][\w.-]+)",
    r"github.com/amnezia-vpn/amneziawg-go (v?[0-9][\w.-]+)",
)
GO_COMMIT_PATTERNS = (
    r'(?:AWG_GO_COMMIT|AMNEZIAWG_GO_COMMIT)="([0-9a-f]{40})"',
    r"\$engineCommit\s*=\s*'([0-9a-f]{40})'",
    r"^upstream_commit=([0-9a-f]{40})",
)
GO_ARCHIVE_PATTERNS = (
    r'(?:AWG_GO_SOURCE_SHA256|AMNEZIAWG_GO_SOURCE_SHA256)="([0-9a-f]{64})"',
    r"^upstream_github_archive_sha256=([0-9a-f]{64})",
    r"\$engineSourceArchiveSha256\s*=\s*'([0-9a-f]{64})'",
)


def collect_go_engine_pins(root: pathlib.Path) -> dict[str, dict[str, str]]:
    pins: dict[str, dict[str, str]] = {}
    for relative in GO_ENGINE_FILES:
        path = root / relative
        if not path.is_file():
            pins[relative] = {"tag": "", "commit": "", "archive": ""}
            continue
        text = path.read_text(encoding="utf-8")
        tag = _first_match(text, GO_TAG_PATTERNS)
        commit = _first_match(text, GO_COMMIT_PATTERNS)
        archive = _first_match(text, GO_ARCHIVE_PATTERNS)
        if relative.endswith("go.mod"):
            if not commit:
                commit = _search(text, r"\b([0-9a-f]{40})\b")
            if not archive:
                archive = _search(text, r"\b([0-9a-f]{64})\b")
        pins[relative] = {"tag": tag, "commit": commit, "archive": archive}
    return pins


def evaluate_pin_contract(root: pathlib.Path) -> list[latest_awg.Finding]:
    findings: list[latest_awg.Finding] = []
    pins = collect_go_engine_pins(root)
    tags = {item["tag"] for item in pins.values() if item["tag"]}
    commits = {item["commit"] for item in pins.values() if item["commit"]}
    archives = {item["archive"] for item in pins.values() if item["archive"]}
    for relative, item in pins.items():
        if not item["tag"]:
            findings.append(
                latest_awg.Finding(
                    "stale_tag",
                    relative,
                    "Go engine tag pin is missing",
                )
            )
        elif item["tag"] != FROZEN_GO_TAG:
            findings.append(
                latest_awg.Finding(
                    "stale_tag",
                    relative,
                    f"Go engine tag {item['tag']} is not frozen {FROZEN_GO_TAG}",
                )
            )
        if not item["commit"]:
            findings.append(
                latest_awg.Finding(
                    "wrong_commit",
                    relative,
                    "Go engine commit pin is missing",
                )
            )
        elif item["commit"] != FROZEN_GO_COMMIT:
            findings.append(
                latest_awg.Finding(
                    "wrong_commit",
                    relative,
                    f"Go engine commit {item['commit']} is not frozen {FROZEN_GO_COMMIT}",
                )
            )
        if not item["archive"]:
            findings.append(
                latest_awg.Finding(
                    "binary_label",
                    relative,
                    "Go engine archive hash pin is missing",
                )
            )
        elif item["archive"] != FROZEN_GO_ARCHIVE:
            findings.append(
                latest_awg.Finding(
                    "binary_label",
                    relative,
                    f"Go engine archive {item['archive']} is not frozen {FROZEN_GO_ARCHIVE}",
                )
            )
        if item["tag"] == FROZEN_WINDOWS_CLIENT_TAG:
            findings.append(
                latest_awg.Finding(
                    "binary_label",
                    relative,
                    "Windows client 3.1.0 was labeled as the Go engine tag",
                )
            )
        if item["commit"] == REJECTED_PRE_V3_COMMIT:
            findings.append(
                latest_awg.Finding(
                    "wrong_commit",
                    relative,
                    "retired pre-v3 commit is still pinned",
                )
            )
    if len(tags) > 1:
        findings.append(
            latest_awg.Finding(
                "cross_platform_drift",
                "go-engine",
                "Go engine tags drifted across producers: " + ",".join(sorted(tags)),
            )
        )
    if len(commits) > 1:
        findings.append(
            latest_awg.Finding(
                "cross_platform_drift",
                "go-engine",
                "Go engine commits drifted across producers: "
                + ",".join(sorted(commits)),
            )
        )
    if len(archives) > 1:
        findings.append(
            latest_awg.Finding(
                "cross_platform_drift",
                "go-engine",
                "Go engine archive hashes drifted across producers",
            )
        )

    linux = root / "tools/build_linux_arm64_awg.sh"
    if linux.is_file():
        text = linux.read_text(encoding="utf-8")
        tools_source = _search(text, r'AWG_TOOLS_SOURCE_SHA256="([0-9a-f]{64})"')
        tools_zip = _search(text, r'AWG_TOOLS_UBUNTU_ZIP_SHA256="([0-9a-f]{64})"')
        go_archive = _search(text, r'AWG_GO_SOURCE_SHA256="([0-9a-f]{64})"')
        tools_tag = _search(text, r'AWG_TOOLS_VERSION="([^"]+)"')
        if tools_source and tools_source == tools_zip:
            findings.append(
                latest_awg.Finding(
                    "binary_label",
                    "tools/build_linux_arm64_awg.sh",
                    "tools source tarball hash is the Ubuntu zip hash",
                )
            )
        if tools_source and tools_source == go_archive:
            findings.append(
                latest_awg.Finding(
                    "binary_label",
                    "tools/build_linux_arm64_awg.sh",
                    "tools source tarball hash is the Go engine archive hash",
                )
            )
        if tools_tag and tools_tag == FROZEN_GO_TAG:
            findings.append(
                latest_awg.Finding(
                    "binary_label",
                    "tools/build_linux_arm64_awg.sh",
                    "tools tag was copied onto the Go engine tag",
                )
            )

    android = root / "tools/build_amneziawg_android_engine.sh"
    if android.is_file():
        text = android.read_text(encoding="utf-8")
        wrapper = _search(text, r'AWG_ANDROID_COMMIT="([0-9a-f]{40})"')
        engine = _search(text, r'AWG_GO_COMMIT="([0-9a-f]{40})"')
        if wrapper and engine and wrapper == engine:
            findings.append(
                latest_awg.Finding(
                    "binary_label",
                    "tools/build_amneziawg_android_engine.sh",
                    "Android wrapper commit was labeled as the Go engine commit",
                )
            )

    apple = root / "tools/build_apple_wg_go_bridge.sh"
    if apple.is_file():
        text = apple.read_text(encoding="utf-8")
        wrapper = _search(text, r'AMNEZIAWG_APPLE_COMMIT="([0-9a-f]{40})"')
        engine = _search(text, r'AMNEZIAWG_GO_COMMIT="([0-9a-f]{40})"')
        if wrapper and engine and wrapper == engine:
            findings.append(
                latest_awg.Finding(
                    "binary_label",
                    "tools/build_apple_wg_go_bridge.sh",
                    "Apple wrapper commit was labeled as the Go engine commit",
                )
            )

    client = root / "tools/build_windows_amneziawg_client.ps1"
    if client.is_file():
        text = client.read_text(encoding="utf-8")
        source_version = _search(text, r"\$sourceVersion\s*=\s*'([^']+)'")
        engine_version = _search(text, r"\$engineVersion\s*=\s*'([^']+)'")
        if source_version == engine_version and source_version:
            findings.append(
                latest_awg.Finding(
                    "binary_label",
                    "tools/build_windows_amneziawg_client.ps1",
                    "Windows client release tag was copied onto the Go engine tag",
                )
            )
        if source_version and source_version != FROZEN_WINDOWS_CLIENT_TAG:
            findings.append(
                latest_awg.Finding(
                    "stale_tag",
                    "tools/build_windows_amneziawg_client.ps1",
                    f"Windows client tag {source_version} is not {FROZEN_WINDOWS_CLIENT_TAG}",
                )
            )

    fabricated_go_stable_markers = (
        "tag is latest stable",
        "Companion latest-stable Go engine",
        "is not latest stable",
        "latest-stable identities",
        "latest-stable Go engine",
        "already match latest stable",
        "same latest-stable Go engine",
        "Go engine companion tag is not latest stable",
        "Android companion Go engine pin is not latest stable",
        "official GitHub tags: latest stable",
    )
    for relative in (
        "tools/build_linux_arm64_awg.sh",
        "tools/build_amneziawg_android_engine.sh",
        "tools/build_apple_wg_go_bridge.sh",
        "windows/awg_engine/go.mod",
        "docs/AMNEZIAWG_ENGINE_PROVENANCE.md",
    ):
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for marker in fabricated_go_stable_markers:
            if marker in text:
                findings.append(
                    latest_awg.Finding(
                        "fabricated_release_status",
                        relative,
                        f"Go tag described as {marker!r}",
                    )
                )

    provenance = root / "docs/AMNEZIAWG_ENGINE_PROVENANCE.md"
    if provenance.is_file():
        text = provenance.read_text(encoding="utf-8")
        rows = {
            "amneziawg-go": "",
            "amneziawg-tools": "",
            "amneziawg-android": "",
            "amneziawg-apple": "",
            "amneziawg-windows": "",
            "amneziawg-windows-client": "",
        }
        for line in text.splitlines():
            for component in rows:
                prefix = f"| {component} |"
                if line.startswith(prefix):
                    rows[component] = line
        go_row = rows["amneziawg-go"]
        if "stability designation unavailable" not in go_row:
            findings.append(
                latest_awg.Finding(
                    "fabricated_release_status",
                    "docs/AMNEZIAWG_ENGINE_PROVENANCE.md",
                    "Go row does not report stability designation unavailable",
                )
            )
        if "latest stable" in go_row:
            findings.append(
                latest_awg.Finding(
                    "fabricated_release_status",
                    "docs/AMNEZIAWG_ENGINE_PROVENANCE.md",
                    "Go row fabricates a latest stable release",
                )
            )
        if "latest stable GitHub Release" not in rows["amneziawg-tools"]:
            findings.append(
                latest_awg.Finding(
                    "fabricated_release_status",
                    "docs/AMNEZIAWG_ENGINE_PROVENANCE.md",
                    "tools row is not classified as a latest stable GitHub Release",
                )
            )
        if "latest stable GitHub Release" not in rows["amneziawg-android"]:
            findings.append(
                latest_awg.Finding(
                    "fabricated_release_status",
                    "docs/AMNEZIAWG_ENGINE_PROVENANCE.md",
                    "android row is not classified as a latest stable GitHub Release",
                )
            )
        if "latest stable GitHub Release" not in rows["amneziawg-windows-client"]:
            findings.append(
                latest_awg.Finding(
                    "fabricated_release_status",
                    "docs/AMNEZIAWG_ENGINE_PROVENANCE.md",
                    "windows-client row is not classified as a latest stable GitHub Release",
                )
            )
    return findings


class AwgPinContractTests(unittest.TestCase):
    def test_live_allowed_producers_match_frozen_latest(self) -> None:
        findings = evaluate_pin_contract(ROOT)
        self.assertEqual(findings, [])
        pins = collect_go_engine_pins(ROOT)
        for relative, item in pins.items():
            self.assertEqual(item["tag"], FROZEN_GO_TAG, relative)
            self.assertEqual(item["commit"], FROZEN_GO_COMMIT, relative)
            self.assertEqual(item["archive"], FROZEN_GO_ARCHIVE, relative)
        android = (ROOT / "tools/build_amneziawg_android_engine.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(FROZEN_ANDROID_COMMIT, android)
        self.assertNotEqual(FROZEN_ANDROID_COMMIT, FROZEN_GO_COMMIT)
        apple = (ROOT / "tools/build_apple_wg_go_bridge.sh").read_text(encoding="utf-8")
        self.assertIn(FROZEN_APPLE_COMMIT, apple)
        self.assertNotEqual(FROZEN_APPLE_COMMIT, FROZEN_GO_COMMIT)
        winn = (
            ROOT / "winn_protocol_experimental/scripts/build_winn_awg_engine.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn(REJECTED_PRE_V3_COMMIT, winn.split("rejected_pre_v3_commit=", 1)[0])
        self.assertIn(f"rejected_pre_v3_commit={REJECTED_PRE_V3_COMMIT}", winn)
        client = (ROOT / "tools/build_windows_amneziawg_client.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"$sourceVersion = '{FROZEN_WINDOWS_CLIENT_TAG}'", client)
        self.assertIn(FROZEN_WINDOWS_CLIENT_COMMIT, client)
        self.assertIn(FROZEN_TOOLS_TAG, (ROOT / "tools/build_linux_arm64_awg.sh").read_text(encoding="utf-8"))
        self.assertIn(FROZEN_TOOLS_COMMIT, (ROOT / "tools/build_linux_arm64_awg.sh").read_text(encoding="utf-8"))
        self.assertIn(FROZEN_TOOLS_SOURCE, (ROOT / "tools/build_linux_arm64_awg.sh").read_text(encoding="utf-8"))
        self.assertIn(FROZEN_TOOLS_UBUNTU_ZIP, (ROOT / "tools/build_linux_arm64_awg.sh").read_text(encoding="utf-8"))
        provenance = (ROOT / "docs/AMNEZIAWG_ENGINE_PROVENANCE.md").read_text(
            encoding="utf-8"
        )
        for marker in (
            FROZEN_GO_TAG,
            FROZEN_GO_COMMIT,
            FROZEN_GO_ARCHIVE,
            FROZEN_TOOLS_TAG,
            FROZEN_WINDOWS_CLIENT_TAG,
            "Not the Go engine tag",
            "latest upstream tag; stability designation unavailable",
            "latest stable GitHub Release",
        ):
            self.assertIn(marker, provenance)
        go_row = next(
            line
            for line in provenance.splitlines()
            if line.startswith("| amneziawg-go |")
        )
        self.assertIn("stability designation unavailable", go_row)
        self.assertNotIn("latest stable", go_row)
        self.assertNotIn("tag is latest stable", provenance)
        self.assertNotIn("Frozen latest-stable identities", provenance)
        linux = (ROOT / "tools/build_linux_arm64_awg.sh").read_text(encoding="utf-8")
        self.assertIn("stability designation unavailable", linux)
        self.assertIn("latest stable GitHub Release", linux)
        self.assertNotIn("is not latest stable", linux)
        self.assertNotIn("Companion latest-stable Go engine", linux)
        self.assertIn("stability designation unavailable", android)
        self.assertNotIn("is not latest stable", android)
        self.assertNotIn("Companion latest-stable Go engine", android)

    def test_current_like_tree_fails_pin_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_current_like_tree(tree)
            codes = {item.code for item in evaluate_pin_contract(tree)}
        self.assertIn("stale_tag", codes)
        self.assertIn("wrong_commit", codes)
        self.assertIn("cross_platform_drift", codes)

    def test_matching_frozen_latest_tree_satisfies_pin_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            self.assertEqual(evaluate_pin_contract(tree), [])

    def test_stale_tag_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            path = tree / "tools/build_windows_awg_engine.ps1"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    FROZEN_GO_TAG, "v3.1.20260813"
                ),
                encoding="utf-8",
            )
            codes = {item.code for item in evaluate_pin_contract(tree)}
        self.assertIn("stale_tag", codes)
        self.assertIn("cross_platform_drift", codes)

    def test_fabricated_go_stable_language_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            path = tree / "tools/build_linux_arm64_awg.sh"
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\n# Companion latest-stable Go engine\n",
                encoding="utf-8",
            )
            docs = tree / "docs/AMNEZIAWG_ENGINE_PROVENANCE.md"
            docs.parent.mkdir(parents=True, exist_ok=True)
            docs.write_text(
                "| amneziawg-go | amnezia-vpn/amneziawg-go | "
                f"{FROZEN_GO_TAG} | {FROZEN_GO_COMMIT} | "
                "Go engine. No GitHub Releases; tag is latest stable. |\n"
                "| amneziawg-tools | amnezia-vpn/amneziawg-tools | "
                f"{FROZEN_TOOLS_TAG} | {FROZEN_TOOLS_COMMIT} | CLI |\n"
                "| amneziawg-android | amnezia-vpn/amneziawg-android | "
                f"{FROZEN_GO_TAG} | {FROZEN_ANDROID_COMMIT} | wrapper |\n"
                "| amneziawg-windows-client | "
                "amnezia-vpn/amneziawg-windows-client | "
                f"{FROZEN_WINDOWS_CLIENT_TAG} | "
                f"{FROZEN_WINDOWS_CLIENT_COMMIT} | client |\n",
                encoding="utf-8",
            )
            codes = {item.code for item in evaluate_pin_contract(tree)}
        self.assertIn("fabricated_release_status", codes)

    def test_wrong_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            path = tree / "winn_protocol_experimental/scripts/build_winn_awg_engine.sh"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    FROZEN_GO_COMMIT, "75ea550a642a9ebef674411c228bb272213a1c23"
                ),
                encoding="utf-8",
            )
            codes = {item.code for item in evaluate_pin_contract(tree)}
        self.assertIn("wrong_commit", codes)
        self.assertIn("cross_platform_drift", codes)

    def test_binary_label_tools_zip_as_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            path = tree / "tools/build_linux_arm64_awg.sh"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    f'AWG_TOOLS_SOURCE_SHA256="{FROZEN_TOOLS_SOURCE}"',
                    f'AWG_TOOLS_SOURCE_SHA256="{FROZEN_TOOLS_UBUNTU_ZIP}"',
                ),
                encoding="utf-8",
            )
            codes = {item.code for item in evaluate_pin_contract(tree)}
        self.assertIn("binary_label", codes)

    def test_binary_label_client_tag_as_engine_tag_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            path = tree / "tools/build_windows_amneziawg_client.ps1"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "$sourceVersion = '3.1.0'",
                    "$sourceVersion = 'v3.1.20260828'",
                ),
                encoding="utf-8",
            )
            codes = {item.code for item in evaluate_pin_contract(tree)}
        self.assertIn("binary_label", codes)

    def test_binary_label_apple_wrapper_commit_as_go_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            path = tree / "tools/build_apple_wg_go_bridge.sh"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    f'AMNEZIAWG_GO_COMMIT="{FROZEN_GO_COMMIT}"',
                    f'AMNEZIAWG_GO_COMMIT="{FROZEN_APPLE_COMMIT}"',
                ),
                encoding="utf-8",
            )
            codes = {item.code for item in evaluate_pin_contract(tree)}
        self.assertIn("binary_label", codes)

    def test_cross_platform_go_archive_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = pathlib.Path(tmp)
            write_latest_tree(tree)
            path = tree / "tools/build_linux_arm64_awg.sh"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    FROZEN_GO_ARCHIVE, FROZEN_TOOLS_SOURCE
                ),
                encoding="utf-8",
            )
            codes = {item.code for item in evaluate_pin_contract(tree)}
        self.assertIn("binary_label", codes)
        self.assertIn("cross_platform_drift", codes)

    def test_windows_client_tag_stays_distinct_from_go_engine(self) -> None:
        self.assertNotEqual(FROZEN_WINDOWS_CLIENT_TAG, FROZEN_GO_TAG)
        self.assertNotEqual(FROZEN_TOOLS_TAG, FROZEN_GO_TAG)
        self.assertNotEqual(FROZEN_TOOLS_SOURCE, FROZEN_GO_ARCHIVE)
        self.assertNotEqual(FROZEN_TOOLS_SOURCE, FROZEN_TOOLS_UBUNTU_ZIP)
        self.assertNotEqual(FROZEN_ANDROID_COMMIT, FROZEN_GO_COMMIT)
        self.assertNotEqual(FROZEN_APPLE_COMMIT, FROZEN_GO_COMMIT)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
