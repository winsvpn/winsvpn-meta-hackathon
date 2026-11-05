#!/usr/bin/env python3
"""Verify network-fetched deployment inputs without executing them."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import re
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile


USER_AGENT = "wins-vpn-deployment-audit/1.0"
DOWNLOADS = {
    # NOTE: Xray is no longer fetched as a prebuilt release archive for any
    # platform (Android/Linux/Windows) -- M-1 replaced that with an
    # from-source rebuild against a reviewed Go toolchain, because the
    # upstream v26.3.27 release binaries embed an outdated go1.26.1 runtime.
    # See verify_xray_engine_rebuild_pins() below for the live pins on that
    # from-source build, and the go-1.27.1-* entries below for the reviewed
    # toolchain it downloads.
    "amneziawg-tools-v3.1.20260812-ubuntu-22.04": (
        "https://github.com/amnezia-vpn/amneziawg-tools/releases/download/"
        "v3.1.20260812/ubuntu-22.04-amneziawg-tools.zip",
        "919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56",
    ),
    "amneziawg-tools-v3.1.20260812-copying": (
        "https://raw.githubusercontent.com/amnezia-vpn/amneziawg-tools/"
        "v3.1.20260812/COPYING",
        "8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643",
    ),
    "amneziawg-go-v3.1.20260828-source": (
        "https://github.com/amnezia-vpn/amneziawg-go/archive/"
        "b5928efb6ca19f0153958460c3d141f04abc5c2e.tar.gz",
        "10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4",
    ),
    "go-1.27.1-linux-amd64": (
        "https://go.dev/dl/go1.27.1.linux-amd64.tar.gz",
        "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445",
    ),
    "go-1.27.1-linux-arm64": (
        "https://go.dev/dl/go1.27.1.linux-arm64.tar.gz",
        "3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec",
    ),
    "go-1.27.1-darwin-arm64": (
        "https://go.dev/dl/go1.27.1.darwin-arm64.tar.gz",
        "ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12",
    ),
    "go-1.27.1-darwin-amd64": (
        "https://go.dev/dl/go1.27.1.darwin-amd64.tar.gz",
        "8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4",
    ),
    "amneziawg-windows-3.1.0-amd64": (
        "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/"
        "download/3.1.0/amneziawg-amd64-3.1.0.msi",
        "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b",
    ),
    "cowrie-3.0.0-wheel": (
        "https://files.pythonhosted.org/packages/d3/7c/"
        "27a7c9d6e4c24c4d8ed64e2c1d5daf46b6505419495e0ccbdcabe1d8abf5/"
        "cowrie-3.0.0-py3-none-any.whl",
        "17bbc617133c3c541d7a65beab879f3ed520e7390eb4b811d5c0423636558075",
    ),
    "adguard-home-0.107.79-linux-amd64": (
        "https://github.com/AdguardTeam/AdGuardHome/releases/download/"
        "v0.107.79/AdGuardHome_linux_amd64.tar.gz",
        "c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f",
    ),
    "yabs": (
        "https://raw.githubusercontent.com/masonr/yet-another-bench-script/"
        "1d20bd9b058f425a0e3e8ac03fe2f501b0457d7c/yabs.sh",
        "389a0726119e4acd7fc9b20a8d1e271c423d55013f8638c6fb54e92c3443a069",
    ),
    "ollama-installer": (
        "https://ollama.com/install.sh",
        "25f64b810b947145095956533e1bdf56eacea2673c55a7e586be4515fc882c9f",
    ),
}
TPOT_COMMIT = "84637788c76629c449925f2428387fdb61454f0e"
LATEST_GITHUB_RELEASES = {
    "XTLS/Xray-core": "v26.9.30",
    "AdguardTeam/AdGuardHome": "v0.107.79",
    "OISF/suricata": "suricata-8.0.7",
    "ollama/ollama": "v0.40.2",
}
# M-4: pin the Ollama *binary* release every AI setup script installs (not
# just the installer script's own hash, already covered by "ollama-installer"
# in DOWNLOADS above) plus the content digest of every base-model tag those
# scripts can select. `ollama pull` has no CLI flag to pin by digest (only
# mutable name:tag refs -- see upstream ollama/ollama#941), so every script
# pulls by tag and then verifies the digest Ollama stored locally against
# these same values before that content is ever wired into a served model.
# Reviewed release stream: `OLLAMA_VERSION=0.40.2 sh install.sh`; model
# pulls and `/api/tags` results remain cross-checked against the registry's
# own "ollama-content-digest" manifest
# response header for every tag below.
OLLAMA_PINNED_VERSION = "0.40.2"
# Re-pinned 2026-10-06 to the registry's current manifests (tags republished about
# 2026-09-30 with an added draft layer). UNVERIFIED: content equivalence with the
# previous pins (12b 4eb23ef1..., e4b c6eb396d...), and a live pull + /api/tags check.
OLLAMA_MODEL_CONTENT_DIGESTS = {
    "gemma4:12b": "6114515d63c17436a7c0417d82820ac65ad643e2806c5a3c89cb62846436ed0b",
    "gemma4:e4b": "dc35e8d9c6061baa6f0fa870975ab6932e2542b579b13ea0f199fa4bb7300c9c",
}
# Complete deterministic AAR built from the exact official Android v3.1 source
# plus the reviewed in-tree live-peer JNI overlay. No Maven/base AAR is used.
ANDROID_AWG_AAR_SHA256 = (
    "e4cc912ec3f1e63e9d46c47063fefb908837253c888bb771ee11a5115df274d6"
)
ANDROID_XRAY_REQUIRED_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")
ANDROID_XRAY_SOURCE_SETS = ("main", "debug", "profile", "release")
ANDROID_XRAY_BINARY_SHA256 = {
    "arm64-v8a": "30772382fcee4fe18b6c31a3daf9a53878b5bfa775e05ea3f3c8cb0b0ec73b2b",
    "armeabi-v7a": "35e5256bce15bc30bd3dbf7ba82c7ac6b138782eae811e0ae4ab535fbedec1b9",
    "x86_64": "82885af5bc2c89eb10201af08049d865c398025fe89f2b8cd02178fc275876b4",
}
ANDROID_XRAY_GOARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "amd64",
}
# M-1: these are no longer the hashes of upstream's own release archive
# members -- they're a from-source rebuild of the exact same reviewed
# Xray-core commit (see XRAY_ENGINE_PINS below), built with the pinned,
# independently-verified Go 1.27.1 instead of upstream's go1.26.1.
XRAY_ENGINE_COMMIT = "b26a91de4f3294e26a0ad0a970b81a386a41f789"
XRAY_ENGINE_TAG = "v26.9.30"
XRAY_ENGINE_REVIEWED_GO_VERSION = "1.27.1"
XRAY_ENGINE_BUILD_MARKER = "v1.260327.0-277-gb26a91de"
WINDOWS_XRAY_REQUIRED_ARCHITECTURES = ("x64", "arm64")
WINDOWS_XRAY_EXE_NAMES = {
    "x64": "xray.exe",
    "arm64": "xray-arm64.exe",
}
WINDOWS_XRAY_EXE_SHA256 = {
    "x64": "fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224",
    "arm64": "c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af",
}
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_XRAY_EXE_SHA256_ASSIGNMENT = re.compile(r"\$XrayExeSha256\s*=")
_XRAY_EXE_SHA256_TABLE = re.compile(
    r"\$XrayExeSha256\s*=\s*@\{(?P<body>.*?)\}\[\$TargetArchitecture\]",
    re.DOTALL,
)
_XRAY_EXE_SHA256_ENTRY = re.compile(
    r"^'([A-Za-z0-9]+)'\s*=\s*'([0-9a-f]{64})'$"
)
WINDOWS_AMNEZIAWG_SOURCE_VERSION = "3.1.0"
WINDOWS_AMNEZIAWG_SOURCE_COMMIT = "ca5dd3b983bd19c335ab095ccd21fc2f804ec968"
WINDOWS_AMNEZIAWG_GO_MOD_SHA256 = (
    "ad578b6a2107ae4c1bab214c8057e89608ac516d6e381675c3d9441ccc4da70a"
)
WINDOWS_AMNEZIAWG_GO_SUM_SHA256 = (
    "268286d6183ec93c39e5295e73e660d9920481c66ecff8331ab64fa082230723"
)
WINDOWS_AMNEZIAWG_SOURCE_BUILD_BAT_SHA256 = (
    "c501fd947d08a4bfdb29f65a9f06ced004779be7a90a125f703c1c5a5130350b"
)
WINDOWS_AMNEZIAWG_PATCHED_BUILD_BAT_SHA256 = (
    "79bd946166bc6e87d4ff1602889557590703fc8a64737fbfe7f0b64ebda431d7"
)
WINDOWS_AMNEZIAWG_BUILD_PATCH_SHA256 = (
    "a5ad25797aadc29f0e7aa0bf91e6197ce57c48cb845194a18ae7c2dbbebadcbd"
)
WINDOWS_AMNEZIAWG_LIBRARY_VERSION = "v3.1.20260814"
WINDOWS_AMNEZIAWG_LIBRARY_COMMIT = "e90531d15802cb976773f3b63443bc281f738ca3"
WINDOWS_AMNEZIAWG_ENGINE_VERSION = "v3.1.20260828"
WINDOWS_AMNEZIAWG_ENGINE_COMMIT = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
WINDOWS_AMNEZIAWG_GO_ARCHIVE_SHA256 = (
    "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d"
)
WINDOWS_REVIEWED_GO_VERSION = "1.27.1"
WINDOWS_AMNEZIAWG_SOURCE_REPOSITORY = (
    "https://github.com/amnezia-vpn/amneziawg-windows-client.git"
)
WINDOWS_AMNEZIAWG_GO_ARCHIVE = "go1.27.1.windows-amd64.zip"
# Unsigned windows-amd64 product maintenance helper, the producer's own pin
# (tools/build_windows_amneziawg_client.ps1 ProductHelperSha256) mirrored in
# installer/windows/build_installer.ps1 $AmneziaWgHelperUnsignedSha256.
WINDOWS_AMNEZIAWG_HELPER_UNSIGNED_SHA256 = (
    "12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41"
)
# Fields that only described an owner publication transaction. The helper
# contract no longer reads them, and a builder must not assert them again.
WINDOWS_AWG_RETIRED_OWNER_TOKEN_ASSERTS = (
    "Get-RequiredJsonProperty $evidence 'owner_blocked'",
    "Get-RequiredJsonProperty $evidence 'publication_contract'",
    "Get-RequiredJsonProperty $evidence 'publication_transaction_id'",
    "Get-RequiredJsonProperty $evidence 'provenance_is_commit_marker'",
    "Get-RequiredJsonProperty $evidence 'helper_kind'",
    "Get-RequiredJsonProperty $evidence 'signing_boundary'",
    "Get-RequiredJsonProperty $evidence 'authenticode_status'",
    "Get-RequiredJsonProperty $evidence 'release_signing_required'",
    '"owner_blocked"\\s*:\\s*false',
)
AMNEZIAWG_ANDROID_ENGINE_COMMIT = "5c16489e2cd9ed3a0a7a27c7445bba5238132f86"
AMNEZIAWG_ANDROID_ENGINE_TAG = "v3.1.20260814"
AMNEZIAWG_ANDROID_ENGINE_REVIEWED_GO_VERSION = "1.27.1"


def verified_ssl_context() -> ssl.SSLContext:
    """Create a fail-closed TLS context with a usable CA bundle on macOS."""
    context = ssl.create_default_context()
    if not context.get_ca_certs():
        candidates = (
            ("/etc/ssl/cert.pem",)
            if sys.platform == "darwin"
            else (("/etc/ssl/certs/ca-certificates.crt",) if sys.platform.startswith("linux") else ())
        )
        context = None
        for candidate in candidates:
            flags = os.O_RDONLY | os.O_CLOEXEC
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(candidate, flags)
            except OSError:
                continue
            try:
                before = os.fstat(descriptor)
                identity = (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_nlink,
                    before.st_uid,
                    before.st_gid,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != 0
                    or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) & 0o022
                    or not 1 <= before.st_size <= 4 * 1024 * 1024
                ):
                    continue
                loaded = ssl.create_default_context(cafile=f"/dev/fd/{descriptor}")
                after = os.fstat(descriptor)
                if identity != (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_nlink,
                    after.st_uid,
                    after.st_gid,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    continue
                context = loaded
                break
            finally:
                os.close(descriptor)
        if context is None:
            raise RuntimeError("TLS certificate verification is unavailable")
    if (
        not context.check_hostname
        or context.verify_mode != ssl.CERT_REQUIRED
        or not context.get_ca_certs()
    ):
        raise RuntimeError("TLS certificate verification is unavailable")
    return context


TLS_CONTEXT: ssl.SSLContext | None = None


def tls_context() -> ssl.SSLContext:
    global TLS_CONTEXT
    if TLS_CONTEXT is None:
        TLS_CONTEXT = verified_ssl_context()
    return TLS_CONTEXT


def request(url: str, *, headers: dict[str, str] | None = None, method: str = "GET"):
    merged = {"User-Agent": USER_AGENT, **(headers or {})}
    request_value = urllib.request.Request(url, headers=merged, method=method)
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            return urllib.request.urlopen(
                request_value,
                timeout=45,
                context=tls_context(),
            )
        except urllib.error.HTTPError as exc:
            if exc.code not in {408, 425, 429, 500, 502, 503, 504}:
                raise
            last_error = exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
        if attempt == 3:
            break
        time.sleep(2**attempt)
    raise RuntimeError(f"network request failed after four attempts: {url}") from last_error


def verify_downloads() -> None:
    for name, (url, expected) in DOWNLOADS.items():
        with request(url) as response:
            body = response.read()
        actual = hashlib.sha256(body).hexdigest()
        if actual != expected:
            raise RuntimeError(f"{name} SHA-256 drift: expected {expected}, got {actual}")
        print(f"PASS {name}: {len(body)} bytes sha256={actual}")


def verify_tpot_commit() -> None:
    url = f"https://api.github.com/repos/telekom-security/tpotce/commits/{TPOT_COMMIT}"
    with request(url, headers={"Accept": "application/vnd.github+json"}) as response:
        payload = json.load(response)
    if payload.get("sha") != TPOT_COMMIT:
        raise RuntimeError("T-Pot pinned commit did not resolve exactly")
    print(f"PASS tpot commit: {TPOT_COMMIT}")


# OWNER DECISION 2026-10-06
# (.agent/debates/_decisions/owner_decision_bump_xray_latest_20261006.md):
# Xray-core follows the newest upstream TAG even though XTLS marks every tag
# after v26.3.27 as a GitHub pre-release (upstream ships a stream of
# pre-releases and promotes one only occasionally). The generic check in
# verify_latest_release_pins keys on /releases/latest and rejects prereleases,
# so it would report v26.3.27 as "latest stable" and fail the v26.9.30 pin.
# These repositories are therefore verified against the newest non-draft
# release in the /releases listing instead, prereleases included.
OWNER_APPROVED_PRERELEASE_TRACKING = frozenset({"XTLS/Xray-core"})


def verify_newest_release_pin(repository: str, expected_tag: str) -> None:
    url = f"https://api.github.com/repos/{repository}/releases?per_page=30"
    with request(url, headers={"Accept": "application/vnd.github+json"}) as response:
        payload = json.load(response)
    published = [
        release
        for release in payload
        if isinstance(release, dict)
        and not release.get("draft")
        and release.get("published_at")
    ]
    if not published:
        raise RuntimeError(f"{repository} has no published release in the listing")
    newest = max(published, key=lambda release: release["published_at"])
    actual_tag = newest.get("tag_name")
    if actual_tag != expected_tag:
        raise RuntimeError(
            f"{repository} newest release drift (owner decision 2026-10-06 tracks "
            f"the newest tag, prereleases included): expected {expected_tag}, "
            f"got {actual_tag}"
        )
    print(
        f"PASS newest release (owner-approved prerelease tracking): "
        f"{repository} {actual_tag} prerelease={bool(newest.get('prerelease'))}"
    )


def verify_latest_release_pins() -> None:
    for repository, expected_tag in LATEST_GITHUB_RELEASES.items():
        if repository in OWNER_APPROVED_PRERELEASE_TRACKING:
            verify_newest_release_pin(repository, expected_tag)
            continue
        url = f"https://api.github.com/repos/{repository}/releases/latest"
        with request(url, headers={"Accept": "application/vnd.github+json"}) as response:
            payload = json.load(response)
        actual_tag = payload.get("tag_name")
        if payload.get("draft") or payload.get("prerelease") or actual_tag != expected_tag:
            raise RuntimeError(
                f"{repository} latest stable release drift: expected {expected_tag}, "
                f"got {actual_tag}"
            )
        print(f"PASS latest stable release: {repository} {actual_tag}")


def verify_suricata_package_contract() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    for relative in (
        "server/wins_control_plane_setup_ONETOUCH.sh",
        "server/wins_data_plane_setup_ONETOUCH.sh",
    ):
        text = (root / relative).read_text(encoding="utf-8")
        for required in (
            'SURICATA_MIN_VERSION_DEFAULT="${SURICATA_MIN_VERSION:-8.0.7}"',
            "ppa:oisf/suricata-stable",
            "ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu",
            "ExecStart=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0",
        ):
            if required not in text:
                raise RuntimeError(f"{relative} Suricata stable/NFQUEUE contract is missing: {required}")
    print("PASS Suricata 8.0.7 stable PPA minimum and NFQUEUE queue-0 contract")


def verify_ollama_pins() -> None:
    """M-4: live-verify Ollama base-model content digests, and cross-check
    that the version + digest pins baked into every AI setup script still
    match this file's reviewed values (catching drift in either direction).
    """

    accept = ", ".join(
        (
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
        )
    )
    for model_tag, expected in OLLAMA_MODEL_CONTENT_DIGESTS.items():
        name, tag = model_tag.split(":", 1)
        url = f"https://registry.ollama.ai/v2/library/{name}/manifests/{tag}"
        # The registry only sets the "ollama-content-digest" response header
        # on HEAD requests (confirmed empirically); a GET to the same URL
        # returns 200 with the manifest body but omits it.
        with request(url, headers={"Accept": accept}, method="HEAD") as response:
            actual = response.headers.get("ollama-content-digest")
        if actual != expected:
            raise RuntimeError(
                f"Ollama model {model_tag} content digest drift: expected {expected}, got {actual}"
            )
        print(f"PASS ollama model digest: {model_tag} sha256={actual}")

    root = pathlib.Path(__file__).resolve().parent.parent
    non_windows_tags = dict(OLLAMA_MODEL_CONTENT_DIGESTS)
    script_contracts = {
        "server/wins_core_server_setup_ONETOUCH.sh": (
            f'CORE_AI_OLLAMA_PINNED_VERSION="${{CORE_AI_OLLAMA_PINNED_VERSION:-{OLLAMA_PINNED_VERSION}}}"',
            non_windows_tags,
        ),
    }
    for relative, (version_literal, digests) in script_contracts.items():
        text = (root / relative).read_text(encoding="utf-8")
        if version_literal not in text:
            raise RuntimeError(f"{relative} is missing the reviewed Ollama version pin: {version_literal}")
        for model_tag, digest in digests.items():
            if digest not in text:
                raise RuntimeError(f"{relative} is missing the reviewed {model_tag} content digest: {digest}")
    print(f"PASS ollama version pin contract across setup scripts: {OLLAMA_PINNED_VERSION}")


def verify_server_awg_source_build_contract() -> None:
    """Verify servers build AWG 3.1 locally and never trust a registry image."""
    from validate_deployment_scripts import validate_awg_31_server_image_contract

    validate_awg_31_server_image_contract()
    print("PASS server AWG 3.1 local source-build and provenance contract")


def verify_workflow_pins() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    workflow_dir = root / ".github" / "workflows"
    tools_dir = str(root / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    import github_backup_only_policy as github_policy

    problems = github_policy.check_repository(root)
    if problems:
        raise RuntimeError(
            "GitHub backup-only policy failed:\n  - " + "\n  - ".join(problems)
        )
    print("PASS GitHub backup-only workflow sentinels")

    linux = (workflow_dir / "build-linux-release.yml").read_text(encoding="utf-8")
    lowered_linux = linux.lower()
    for required in ("workflow_dispatch:", "contents: read", "exit 64"):
        if required not in lowered_linux:
            raise RuntimeError(f"Linux release policy sentinel is missing: {required}")
    for forbidden in (
        "id-token:",
        "oidc",
        "cosign ",
        "sigstore",
        "upload-artifact",
        "download-artifact",
        "actions/checkout",
        "sign-blob",
        "verify-blob",
        "sign_staged",
    ):
        if forbidden in lowered_linux:
            raise RuntimeError(f"Linux release policy sentinel retained hosted authority: {forbidden}")
    print("PASS Linux local-only release policy sentinel")


def verify_android_runtime_pins() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    aar = root / "android" / "app" / "libs" / "amneziawg.aar"
    actual_aar = hashlib.sha256(aar.read_bytes()).hexdigest()
    if actual_aar != ANDROID_AWG_AAR_SHA256:
        raise RuntimeError(
            f"Android AmneziaWG AAR drift: expected {ANDROID_AWG_AAR_SHA256}, got {actual_aar}"
        )
    with zipfile.ZipFile(aar) as archive:
        names = set(archive.namelist())
        required = {
            "classes.jar",
            "jni/arm64-v8a/libam-go.so",
            "jni/x86_64/libam-go.so",
        }
        if not required.issubset(names):
            raise RuntimeError(
                f"Android AmneziaWG AAR is missing runtime members: {sorted(required - names)}"
            )
        native = archive.read("jni/arm64-v8a/libam-go.so")
        for marker in (
            b"github.com/amnezia-vpn/amneziawg-android",
            b"github.com/amnezia-vpn/amneziawg-go",
        ):
            if marker not in native:
                raise RuntimeError("Android AmneziaWG native module identity is missing")
        # Win's Android carrier requires the reviewed live-peer JNI overlay on
        # top of the complete official v3 tunnel module.
        with zipfile.ZipFile(io.BytesIO(archive.read("classes.jar"))) as classes:
            go_backend = classes.read("org/amnezia/awg/GoBackend.class")
            for marker in (b"awgUpdateTunnelPeers", b"awgTurnOn"):
                if marker not in go_backend:
                    raise RuntimeError(
                        "Android AmneziaWG bridge is missing the required carrier API"
                    )

    prepare = (root / "tools" / "prepare_android_xray_assets.sh").read_text(
        encoding="utf-8"
    )
    required_prepare_literals = {
        "build_xray_engine.sh",
        "android-arm64",
        "android-arm",
        "android-amd64",
    }
    missing = sorted(value for value in required_prepare_literals if value not in prepare)
    if missing or "/releases/latest/" in prepare:
        raise RuntimeError("Android Xray preparation script is not immutably pinned")
    require_exact_architecture_sha256_map(
        ANDROID_XRAY_BINARY_SHA256,
        ANDROID_XRAY_REQUIRED_ABIS,
        "Android Xray",
    )
    if set(ANDROID_XRAY_GOARCH) != set(ANDROID_XRAY_REQUIRED_ABIS):
        raise RuntimeError("Android Xray GOARCH map must match arm64/armv7/x86_64")
    verifier = root / "tools" / "verify_android_xray_binary.py"
    for source_set in ANDROID_XRAY_SOURCE_SETS:
        for abi in ANDROID_XRAY_REQUIRED_ABIS:
            expected = ANDROID_XRAY_BINARY_SHA256[abi]
            binary = (
                root
                / "android"
                / "app"
                / "src"
                / source_set
                / "jniLibs"
                / abi
                / "libxray.so"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(verifier),
                    str(binary),
                    "--goarch",
                    ANDROID_XRAY_GOARCH[abi],
                    "--go-version",
                    XRAY_ENGINE_REVIEWED_GO_VERSION,
                    "--build-marker",
                    XRAY_ENGINE_BUILD_MARKER,
                    "--page-size",
                    "16384",
                    "--expected-sha256",
                    expected,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Android Xray {source_set}/{abi} provenance/ELF verification failed: "
                    f"{result.stderr.strip() or result.stdout.strip()}"
                )

    alignment_verifier = root / "tools" / "verify_android_elf_alignment.py"
    for source_set in ("debug", "profile", "release"):
        for abi in ("arm64-v8a", "x86_64"):
            binary = (
                root
                / "android"
                / "app"
                / "src"
                / source_set
                / "jniLibs"
                / abi
                / "libwinnengine.so"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(alignment_verifier),
                    str(binary),
                    "--abi",
                    abi,
                    "--page-size",
                    "16384",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Android Winn {source_set}/{abi} ELF verification failed: "
                    f"{result.stderr.strip() or result.stdout.strip()}"
                )
    print("PASS Android AmneziaWG bridge and Xray runtime pins")


def require_exact_architecture_sha256_map(
    values: dict[str, str],
    required: tuple[str, ...],
    label: str,
) -> None:
    if type(values) is not dict:
        raise RuntimeError(f"{label} must be an architecture-keyed SHA-256 table")
    actual_keys = set(values)
    required_keys = set(required)
    if actual_keys != required_keys:
        missing = sorted(required_keys - actual_keys)
        extra = sorted(actual_keys - required_keys)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("extra " + ", ".join(extra))
        raise RuntimeError(
            f"{label} architecture keys are invalid: {'; '.join(details)}"
        )
    seen: dict[str, str] = {}
    for key in required:
        digest = values[key]
        if type(digest) is not str or _SHA256_HEX.fullmatch(digest) is None:
            raise RuntimeError(f"{label} {key} hash is malformed")
        owner = seen.get(digest)
        if owner is not None:
            raise RuntimeError(
                f"{label} hashes must be distinct; {key} duplicates {owner}"
            )
        seen[digest] = key


def require_file_sha256(path: pathlib.Path, expected: str, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"{label} is missing: {path}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError(f"{label} drift: expected {expected}, got {actual}")


def parse_powershell_xray_sha256_table(source: str) -> dict[str, str]:
    """Parse the exact architecture-keyed $XrayExeSha256 PowerShell table."""
    if type(source) is not str:
        raise RuntimeError("$XrayExeSha256 table source is malformed")
    for match in _XRAY_EXE_SHA256_ASSIGNMENT.finditer(source):
        rest = source[match.end() :].lstrip()
        if not rest.startswith("@{"):
            raise RuntimeError(
                "scalar legacy $XrayExeSha256 form is rejected; "
                "architecture-keyed table required"
            )
    matches = list(_XRAY_EXE_SHA256_TABLE.finditer(source))
    if len(matches) != 1:
        raise RuntimeError(
            "installer/windows/build_installer.ps1 must contain exactly one "
            "architecture-keyed $XrayExeSha256 table"
        )
    parsed: dict[str, str] = {}
    for raw_line in matches[0].group("body").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        entry = _XRAY_EXE_SHA256_ENTRY.fullmatch(line)
        if entry is None:
            raise RuntimeError(
                f"malformed architecture key in $XrayExeSha256 table: {line}"
            )
        architecture, digest = entry.group(1), entry.group(2)
        if architecture in parsed:
            raise RuntimeError(
                f"duplicate architecture key in $XrayExeSha256 table: {architecture}"
            )
        parsed[architecture] = digest
    require_exact_architecture_sha256_map(
        parsed, WINDOWS_XRAY_REQUIRED_ARCHITECTURES, "$XrayExeSha256"
    )
    return parsed


def verify_windows_xray_binaries(root: pathlib.Path, expected: dict[str, str]) -> None:
    require_exact_architecture_sha256_map(
        expected, WINDOWS_XRAY_REQUIRED_ARCHITECTURES, "Windows Xray"
    )
    dependencies = root / "installer" / "windows" / "dependencies"
    for architecture in WINDOWS_XRAY_REQUIRED_ARCHITECTURES:
        require_file_sha256(
            dependencies / WINDOWS_XRAY_EXE_NAMES[architecture],
            expected[architecture],
            f"Windows Xray {architecture}",
        )


def verify_android_xray_binaries(root: pathlib.Path, expected: dict[str, str]) -> None:
    require_exact_architecture_sha256_map(
        expected, ANDROID_XRAY_REQUIRED_ABIS, "Android Xray"
    )
    if set(ANDROID_XRAY_GOARCH) != set(ANDROID_XRAY_REQUIRED_ABIS):
        raise RuntimeError("Android Xray GOARCH map must match arm64/armv7/x86_64")
    for source_set in ANDROID_XRAY_SOURCE_SETS:
        for abi in ANDROID_XRAY_REQUIRED_ABIS:
            require_file_sha256(
                root
                / "android"
                / "app"
                / "src"
                / source_set
                / "jniLibs"
                / abi
                / "libxray.so",
                expected[abi],
                f"Android Xray {source_set}/{abi}",
            )


def verify_xray_engine_recipe_pins(engine: str) -> None:
    for required in (
        f'XRAY_COMMIT="{XRAY_ENGINE_COMMIT}"',
        f'XRAY_TAG="{XRAY_ENGINE_TAG}"',
        f'REVIEWED_GO_VERSION="{XRAY_ENGINE_REVIEWED_GO_VERSION}"',
        'REVIEWED_NDK_VERSION="30.0.16248370"',
        "verify_android_xray_binary.py",
        "max-page-size=${ANDROID_ELF_PAGE_SIZE}",
        "common-page-size=${ANDROID_ELF_PAGE_SIZE}",
        "go.dev/dl/go${REVIEWED_GO_VERSION}",
        "shasum -a 256",
        "sha256sum",
    ):
        if required not in engine:
            raise RuntimeError(
                f"tools/build_xray_engine.sh is missing a required pin: {required}"
            )


def verify_xray_engine_rebuild_pins() -> None:
    """M-1: Xray is a from-source rebuild of a pinned commit with a pinned,
    reviewed Go toolchain -- verify the rebuild recipe, its two callers, and
    the vendored Windows/Android outputs all agree with each other."""
    root = pathlib.Path(__file__).resolve().parent.parent
    engine = (root / "tools" / "build_xray_engine.sh").read_text(encoding="utf-8")
    verify_xray_engine_recipe_pins(engine)
    if XRAY_ENGINE_TAG != "v26.9.30" or XRAY_ENGINE_COMMIT != (
        "b26a91de4f3294e26a0ad0a970b81a386a41f789"
    ):
        raise RuntimeError("Xray tag/commit pin drifted from v26.9.30")
    if LATEST_GITHUB_RELEASES.get("XTLS/Xray-core") != "v26.9.30":
        raise RuntimeError("XTLS/Xray-core newest-release pin drifted from v26.9.30")

    installer = (root / "installer" / "windows" / "build_installer.ps1").read_text(
        encoding="utf-8"
    )
    table = parse_powershell_xray_sha256_table(installer)
    require_exact_architecture_sha256_map(
        WINDOWS_XRAY_EXE_SHA256,
        WINDOWS_XRAY_REQUIRED_ARCHITECTURES,
        "Windows Xray pin",
    )
    if table != WINDOWS_XRAY_EXE_SHA256:
        raise RuntimeError(
            "installer/windows/build_installer.ps1 $XrayExeSha256 table drifted "
            "from the rebuild"
        )
    if "Get-VerifiedDownload -Uri $XrayArchiveUrl -OutFile $zipPath" in installer:
        raise RuntimeError(
            "build_installer.ps1 must not silently re-download the upstream Xray "
            "archive if the vendored rebuild is missing -- that would resurrect "
            "the outdated Go runtime M-1 fixed."
        )

    verify_windows_xray_binaries(root, WINDOWS_XRAY_EXE_SHA256)
    verify_android_xray_binaries(root, ANDROID_XRAY_BINARY_SHA256)
    print("PASS Xray from-source rebuild pins (engine recipe, Windows, Android)")


def verify_amneziawg_engine_rebuild_pins() -> None:
    """Verify the complete official-source Android AWG 3.1 AAR and recipe."""
    root = pathlib.Path(__file__).resolve().parent.parent
    engine = (root / "tools" / "build_amneziawg_android_engine.sh").read_text(
        encoding="utf-8"
    )
    for required in (
        f'AWG_ANDROID_COMMIT="{AMNEZIAWG_ANDROID_ENGINE_COMMIT}"',
        f'AWG_ANDROID_TAG="{AMNEZIAWG_ANDROID_ENGINE_TAG}"',
        f'REVIEWED_GO_VERSION="{AMNEZIAWG_ANDROID_ENGINE_REVIEWED_GO_VERSION}"',
        'AWG_ANDROID_REPO="https://github.com/amnezia-vpn/amneziawg-android.git"',
        "No prebuilt/base AAR is accepted",
        "canonicalize_complete_aar",
        "verify_complete_aar",
        "gradle-verification-metadata.xml",
        "awgUpdateTunnelPeers",
        "libam-go.so",
        "libam.so",
        "libam-quick.so",
        "arm64-v8a armeabi-v7a x86 x86_64",
    ):
        if required not in engine:
            raise RuntimeError(
                f"tools/build_amneziawg_android_engine.sh is missing a required pin: {required}"
            )

    aar = root / "android" / "app" / "libs" / "amneziawg.aar"
    actual_aar = hashlib.sha256(aar.read_bytes()).hexdigest()
    if actual_aar != ANDROID_AWG_AAR_SHA256:
        raise RuntimeError(
            f"Android AmneziaWG AAR drift: expected {ANDROID_AWG_AAR_SHA256}, got {actual_aar}"
        )
    expected_marker = f"go{AMNEZIAWG_ANDROID_ENGINE_REVIEWED_GO_VERSION}".encode()
    with zipfile.ZipFile(aar) as archive:
        go_members = [
            name
            for name in archive.namelist()
            if name.startswith("jni/") and name.endswith("libam-go.so")
        ]
        if len(go_members) < 4:
            raise RuntimeError(
                f"Android AmneziaWG AAR only has {len(go_members)} libam-go.so "
                "members; expected all four ABIs (arm64-v8a, armeabi-v7a, x86, x86_64)."
            )
        for member in go_members:
            native = archive.read(member)
            if expected_marker not in native:
                raise RuntimeError(
                    f"Android AmneziaWG {member} does not embed the reviewed "
                    f"{expected_marker.decode()} runtime -- it may still carry "
                    "the vulnerable go1.24.x build M-1 was supposed to replace."
                )
            if b"github.com/amnezia-vpn/amneziawg-go/v3" not in native:
                raise RuntimeError(f"Android AmneziaWG {member} lacks official AWG v3 identity")
            if b"github.com/wgtunnel/amneziawg-go" in native:
                raise RuntimeError(f"Android AmneziaWG {member} retains retired fork identity")
        names = set(archive.namelist())
        for abi in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64"):
            for library in ("libam-go.so", "libam.so", "libam-quick.so"):
                name = f"jni/{abi}/{library}"
                if name not in names:
                    raise RuntimeError(f"complete Android AAR is missing {name}")
        with zipfile.ZipFile(io.BytesIO(archive.read("classes.jar"))) as classes:
            class_names = set(classes.namelist())
            if "org/amnezia/awg/backend/AwgQuickBackend.class" not in class_names:
                raise RuntimeError("Android classes.jar is not the official v3 tunnel module")
            backend = classes.read("org/amnezia/awg/GoBackend.class")
            for marker in (b"awgTurnOn", b"awgUpdateTunnelPeers"):
                if marker not in backend:
                    raise RuntimeError(f"Android classes.jar lacks {marker.decode()}")
    print("PASS complete official-source AmneziaWG Android AWG 3.1 AAR")


def _reject_duplicate_json_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise RuntimeError(
                f"Windows AWG provenance repeats JSON key {key}"
            )
        seen[key] = value
    return seen


def load_unique_json_object(path: pathlib.Path) -> dict:
    payload = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
    )
    if type(payload) is not dict:
        raise RuntimeError("Windows AWG provenance is not a JSON object")
    return payload


def require_windows_awg_schema2_evidence(
    evidence: dict,
    actual_digest: str,
    expected_target: str = "windows-amd64",
) -> None:
    if type(evidence) is not dict:
        raise RuntimeError("Windows AWG provenance is not a JSON object")
    if type(actual_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", actual_digest) is None:
        raise RuntimeError("Windows AWG helper digest is not lowercase SHA-256")
    expected_evidence = {
        "schema_version": 2,
        "source_repository": WINDOWS_AMNEZIAWG_SOURCE_REPOSITORY,
        "source_version": WINDOWS_AMNEZIAWG_SOURCE_VERSION,
        "source_commit": WINDOWS_AMNEZIAWG_SOURCE_COMMIT,
        "source_go_mod_sha256": WINDOWS_AMNEZIAWG_GO_MOD_SHA256,
        "source_go_sum_sha256": WINDOWS_AMNEZIAWG_GO_SUM_SHA256,
        "source_build_bat_sha256": WINDOWS_AMNEZIAWG_SOURCE_BUILD_BAT_SHA256,
        "patched_build_bat_sha256": WINDOWS_AMNEZIAWG_PATCHED_BUILD_BAT_SHA256,
        "build_patch_sha256": WINDOWS_AMNEZIAWG_BUILD_PATCH_SHA256,
        "windows_library_repository": (
            "https://github.com/amnezia-vpn/amneziawg-windows.git"
        ),
        "windows_library_version": WINDOWS_AMNEZIAWG_LIBRARY_VERSION,
        "windows_library_commit": WINDOWS_AMNEZIAWG_LIBRARY_COMMIT,
        "engine_module": "github.com/amnezia-vpn/amneziawg-go/v3",
        "engine_version": WINDOWS_AMNEZIAWG_ENGINE_VERSION,
        "engine_commit": WINDOWS_AMNEZIAWG_ENGINE_COMMIT,
        "go_version": WINDOWS_REVIEWED_GO_VERSION,
        "go_archive": WINDOWS_AMNEZIAWG_GO_ARCHIVE,
        "go_archive_sha256": WINDOWS_AMNEZIAWG_GO_ARCHIVE_SHA256,
        "go_toolchain_policy": "verified_archive_only",
        "go_module_policy": "readonly",
        "go_checksum_database": "sum.golang.org",
        "target": expected_target,
        "unsigned_artifact_sha256": actual_digest,
        "expected_unsigned_artifact_sha256": actual_digest,
    }
    mismatches = []
    for name, expected in expected_evidence.items():
        if name not in evidence:
            mismatches.append(name)
            continue
        actual = evidence[name]
        if type(actual) is not type(expected) or actual != expected:
            mismatches.append(name)
    if mismatches:
        raise RuntimeError(
            "Windows AmneziaWG helper provenance is not the reviewed "
            "schema-2 contract: " + ", ".join(mismatches)
        )
    module_info = evidence.get("module_build_info")
    if (
        type(module_info) is not list
        or not module_info
        or any(type(item) is not str for item in module_info)
    ):
        raise RuntimeError(
            "Windows AWG module_build_info must be a JSON array of strings"
        )
    module_text = "\n".join(module_info)
    if (
        re.search(
            r"(?m)^\s*dep\s+github\.com/amnezia-vpn/amneziawg-go/v3\s+v3\.1\.20260828\s+",
            module_text,
        )
        is None
        or re.search(
            r"(?m)^\s*dep\s+github\.com/amnezia-vpn/amneziawg-windows/v3\s+v3\.1\.20260814\s+",
            module_text,
        )
        is None
    ):
        raise RuntimeError(
            "Windows AWG module_build_info lacks the exact AWG 3.1 module identities"
        )
    if expected_target == "windows-arm64":
        if (
            type(evidence.get("reproducibility_builds")) is not int
            or evidence.get("reproducibility_builds") != 2
            or type(evidence.get("reproducibility_status")) is not str
            or evidence.get("reproducibility_status")
            != "two_clean_builds_byte_identical"
        ):
            raise RuntimeError(
                "Windows AWG arm64 schema-2 provenance lacks exact reproducibility evidence"
            )


def verify_windows_amneziawg_client_rebuild_pins() -> None:
    """M-11: verify the source-built Windows maintenance helper, provenance,
    and release-only Authenticode path remain bound to the same reviewed
    source/toolchain/artifact."""
    root = pathlib.Path(__file__).resolve().parent.parent
    builder = (
        root / "tools" / "build_windows_amneziawg_client.ps1"
    ).read_text(encoding="utf-8")
    required_builder = (
        f"$sourceVersion = '{WINDOWS_AMNEZIAWG_SOURCE_VERSION}'",
        f"$sourceCommit = '{WINDOWS_AMNEZIAWG_SOURCE_COMMIT}'",
        WINDOWS_AMNEZIAWG_GO_MOD_SHA256,
        WINDOWS_AMNEZIAWG_GO_SUM_SHA256,
        WINDOWS_AMNEZIAWG_SOURCE_BUILD_BAT_SHA256,
        WINDOWS_AMNEZIAWG_PATCHED_BUILD_BAT_SHA256,
        WINDOWS_AMNEZIAWG_BUILD_PATCH_SHA256,
        f"$windowsLibraryVersion = '{WINDOWS_AMNEZIAWG_LIBRARY_VERSION}'",
        f"$windowsLibraryCommit = '{WINDOWS_AMNEZIAWG_LIBRARY_COMMIT}'",
        f"$engineVersion = '{WINDOWS_AMNEZIAWG_ENGINE_VERSION}'",
        f"$engineCommit = '{WINDOWS_AMNEZIAWG_ENGINE_COMMIT}'",
        f"$goVersion = '{WINDOWS_REVIEWED_GO_VERSION}'",
        WINDOWS_AMNEZIAWG_GO_ARCHIVE_SHA256,
        "GOTOOLCHAIN = 'local'",
        "GOENV = 'off'",
        "GOWORK = 'off'",
        "GOFLAGS = '-mod=readonly -buildvcs=false'",
        "GOSUMDB = 'sum.golang.org'",
        "GOMODCACHE = $goModuleCache",
        "GOTMPDIR = $goTemporary",
        "GOAMD64 = 'v1'",
        "CGO_CFLAGS = ''",
        "SigningProvider = ''",
        "Assert-TargetPe -Path $builtExe",
        "authenticode_status = 'pending_release_signing'",
        "release_signing_required = $true",
        f"ProductHelperSha256 = '{WINDOWS_AMNEZIAWG_HELPER_UNSIGNED_SHA256}'",
    )
    for required in required_builder:
        if required not in builder:
            raise RuntimeError(
                "tools/build_windows_amneziawg_client.ps1 is missing a "
                f"required source/toolchain control: {required}"
            )

    zip_builder = (
        root / "installer" / "windows" / "build_zip_installer.ps1"
    ).read_text(encoding="utf-8")
    required_zip = (
        "function Assert-WindowsAwgSchema2OwnerPublicationContract",
        "Assert-JsonIntegerEquals -Value (Get-RequiredJsonProperty $evidence 'schema_version') -Expected 2 -Name 'schema_version'",
        f"-Expected '{WINDOWS_REVIEWED_GO_VERSION}' -Name 'go_version'",
        f"-Expected '{WINDOWS_AMNEZIAWG_GO_ARCHIVE_SHA256}' -Name 'go_archive_sha256'",
        "expected_unsigned_artifact_sha256",
        WINDOWS_AMNEZIAWG_SOURCE_REPOSITORY,
        WINDOWS_AMNEZIAWG_GO_ARCHIVE,
        "module_build_info",
        f"-Expected '{WINDOWS_AMNEZIAWG_SOURCE_VERSION}' -Name 'source_version'",
        f"-Expected '{WINDOWS_AMNEZIAWG_SOURCE_COMMIT}' -Name 'source_commit'",
        f"-Expected '{WINDOWS_AMNEZIAWG_LIBRARY_VERSION}' -Name 'windows_library_version'",
        f"-Expected '{WINDOWS_AMNEZIAWG_LIBRARY_COMMIT}' -Name 'windows_library_commit'",
        f"-Expected '{WINDOWS_AMNEZIAWG_ENGINE_VERSION}' -Name 'engine_version'",
        f"-Expected '{WINDOWS_AMNEZIAWG_ENGINE_COMMIT}' -Name 'engine_commit'",
        "Re-verifying staged dependency bytes against reviewed pins after copy",
        "bytes that changed after the pre-copy pin check",
    )
    for required in required_zip:
        if required not in zip_builder:
            raise RuntimeError(
                "installer/windows/build_zip_installer.ps1 is missing a "
                f"required schema-2 provenance control: {required}"
            )
    if "[int]$evidence.schema_version -ne 2" in zip_builder:
        raise RuntimeError(
            "installer/windows/build_zip_installer.ps1 still coerces schema_version"
        )
    if "-not [bool]$evidence.provenance_is_commit_marker" in zip_builder:
        raise RuntimeError(
            "installer/windows/build_zip_installer.ps1 still coerces provenance_is_commit_marker"
        )

    binary = root / "installer" / "windows" / "dependencies" / "amneziawg.exe"
    provenance = pathlib.Path(f"{binary}.provenance.json")
    # The expected digest is the producer's pin, never the hash of the file
    # being checked.
    require_file_sha256(
        binary,
        WINDOWS_AMNEZIAWG_HELPER_UNSIGNED_SHA256,
        "Windows AmneziaWG maintenance helper",
    )
    evidence = load_unique_json_object(provenance)
    require_windows_awg_schema2_evidence(
        evidence, WINDOWS_AMNEZIAWG_HELPER_UNSIGNED_SHA256, "windows-amd64"
    )

    installer = (
        root / "installer" / "windows" / "build_installer.ps1"
    ).read_text(encoding="utf-8")
    required_installer = (
        "function Assert-WindowsAwgSchema2OwnerPublicationContract",
        "Assert-JsonIntegerEquals -Value (Get-RequiredJsonProperty $evidence 'schema_version') -Expected 2 -Name 'schema_version'",
        f"-Expected '{WINDOWS_REVIEWED_GO_VERSION}' -Name 'go_version'",
        f"-Expected '{WINDOWS_AMNEZIAWG_GO_ARCHIVE_SHA256}' -Name 'go_archive_sha256'",
        f"'x64' = '{WINDOWS_AMNEZIAWG_HELPER_UNSIGNED_SHA256}'",
        "$expectedUnsigned = $AmneziaWgHelperUnsignedSha256",
        "$stagedPinMap['amneziawg.exe'] = $script:AmneziaWgHelperReviewedSha256",
        f'$AmneziaWgSourceCommit = "{WINDOWS_AMNEZIAWG_SOURCE_COMMIT}"',
        "unsigned_artifact_sha256",
        "Assert-RebuiltAmneziaWgHelper",
        "if ($destinations.ContainsKey($name))",
        "Invoke-ProductSigning -Path $stagedAmneziaWg",
        "/DAmneziaWgExeSha256=$stagedAmneziaWgSha256",
        "/DUpstreamAmneziaWgExeSha256=$UpstreamAmneziaWgExeSha256",
        "Re-verifying staged dependency bytes against reviewed pins after copy",
        "bytes that changed after the pre-copy pin check",
    )
    for required in required_installer:
        if required not in installer:
            raise RuntimeError(
                "Windows installer lost the M-11 helper pin/signing contract: "
                f"{required}"
            )
    if "[int]$evidence.schema_version -ne 2" in installer.split(
        "function Assert-RebuiltAmneziaWgHelper", 1
    )[-1].split("function Assert-AmneziaWgPayloadSignatures", 1)[0]:
        raise RuntimeError(
            "installer/windows/build_installer.ps1 still coerces helper schema_version"
        )
    zip_contract = zip_builder[
        zip_builder.index("# BEGIN-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT")
        : zip_builder.index("# END-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT")
        + len("# END-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT")
    ]
    installer_contract = installer[
        installer.index("# BEGIN-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT")
        : installer.index("# END-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT")
        + len("# END-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT")
    ]
    if zip_contract != installer_contract:
        raise RuntimeError(
            "ZIP and Inno Windows AWG schema-2 owner publication contracts are not identical"
        )
    for retired in WINDOWS_AWG_RETIRED_OWNER_TOKEN_ASSERTS:
        if retired in installer_contract or retired in zip_contract:
            raise RuntimeError(
                "Windows AWG helper contract still asserts an owner publication "
                f"token: {retired}"
            )
    msi_audit = installer[
        installer.index("function Assert-AmneziaWgPayloadSignatures")
        : installer.index("function Ensure-AmneziaWgMsi")
    ]
    if "'amneziawg.exe' = $AmneziaWgExe" in msi_audit:
        raise RuntimeError(
            "The upstream MSI extraction map can overwrite the source-built "
            "Windows AmneziaWG helper."
        )
    backend = (
        root / "windows" / "runner" / "windows_tunnel_backend.cpp"
    ).read_text(encoding="utf-8")
    if 'L"AmneziaWG\\\\amneziawg.exe"' in backend:
        raise RuntimeError(
            "The Windows runtime can fall back to the MSI-installed Go 1.24.4 "
            "maintenance helper instead of failing closed."
        )
    store_builder = (
        root / "installer" / "windows" / "build_store_msix.ps1"
    ).read_text(encoding="utf-8")
    for required in (
        "$amneziaHelper = Assert-PinnedFile 'amneziawg.exe'",
        "foreach ($name in 'awg.exe','wintun.dll')",
        "Copy-Item -LiteralPath $amneziaHelper",
    ):
        if required not in store_builder:
            raise RuntimeError(
                "The non-production MSIX lane can resurrect the upstream "
                f"Go 1.24.4 helper: {required}"
            )
    print("PASS Windows AmneziaWG client source/toolchain/provenance/signing pins")


def verify_linux_runtime_pins() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    builder = (root / "tools" / "build_linux_release.sh").read_text(encoding="utf-8")
    backend = (root / "linux" / "runner" / "linux_tunnel_backend.cc").read_text(
        encoding="utf-8"
    )
    installer = (root / "linux" / "packaging" / "install.sh").read_text(
        encoding="utf-8"
    )
    bpf_helper = (
        root / "linux" / "runner" / "winsvpn_bypass_bpf.cc"
    ).read_text(encoding="utf-8")
    required_hashes = {
        "23d29323258166183eeeb288c1f9f08b879f3707e54591b1bfb2402413f6d8d8",
        "89dca7788242e542cec249af5d062764fbcb3a6a3ef66999c400d5bbe2f446db",
        "5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f",
        "bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d",
        "9083c92dbd16422cd590df8fcf2ebae2c604b43539bdd58dddaede74efd0642a",
    }
    for expected in required_hashes:
        if expected not in builder or expected not in backend or expected not in installer:
            raise RuntimeError(f"Linux AmneziaWG runtime pin is not end-to-end: {expected}")
    if (
        'AWG_QUICK_SOURCE_SHA256="f4bb0f5d63665ade87f0cb9f2185c43515cff09868637eb311f98f65a318722c"'
        not in builder
    ):
        raise RuntimeError("Linux AmneziaWG awg-quick source pin is missing")
    required_builder = {
        'AWG_TOOLS_VERSION="v3.1.20260812"',
        'AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"',
        'AWG_GO_TAG="v3.1.20260828"',
        'AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"',
        'GO_VERSION="1.27.1"',
        "GOTOOLCHAIN=local",
        "GOPROXY=off",
        "GOSUMDB=off",
        "-buildvcs=false",
        "-buildid=",
        '"winsvpn-bypass-bpf",',
        'bash "$ROOT/tools/build_xray_engine.sh" "linux-${LINUX_RELEASE_GOARCH}"',
        'XRAY_LICENSE_SHA256="1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5"',
    }
    if any(value not in builder for value in required_builder) or "/releases/latest/" in builder:
        raise RuntimeError("Linux AmneziaWG release builder is not immutably pinned")
    if "Xray-linux-64.zip" in builder or "XRAY_ARCHIVE_SHA256" in builder:
        raise RuntimeError(
            "build_linux_release.sh must not silently re-download the upstream "
            "Xray release archive -- that would resurrect the outdated Go "
            "runtime M-1 fixed. Xray must be built from source via "
            "build_xray_engine.sh."
        )
    for required in (
        'WG_QUICK_USERSPACE_IMPLEMENTATION="$BUNDLE_DIR/amneziawg-go"',
        "verify_bundled_tools",
        "sha256sum",
        "HostIpv6Disabled",
        "RemoveIpv6AllowedIps",
        "ResolvePublicIpv4Addresses(host)",
        "winsvpn-xray",
        "uidrange",
        "priority 1 uidrange",
        "activate_xray_transport",
        "rejected a recursive Xray transport route",
        "winsvpn-xray-bypass",
        "winsvpn-xray-connmark",
        "CONNMARK --save-mark",
        "CONNMARK --restore-mark",
        "setpriv --reuid=",
        "--no-new-privs",
    ):
        if required not in backend:
            raise RuntimeError(f"Linux bundled runtime verification is missing: {required}")
    for required in (
        "BPF_PROG_TYPE_CGROUP_SOCK",
        "BPF_CGROUP_INET_SOCK_CREATE",
        "BPF_LINK_CREATE",
        "PR_SET_NO_NEW_PRIVS",
        "setuid(nobody->pw_uid)",
        "__NR_pidfd_open",
    ):
        if required not in bpf_helper:
            raise RuntimeError(f"Linux split-tunnel BPF helper is missing: {required}")
    linux_main = (root / "linux" / "runner" / "main.cc").read_text(encoding="utf-8")
    for required in ("umask(0077)", "HardenLegacyStateFiles", "HardenLegacyStateDirectory"):
        if required not in linux_main:
            raise RuntimeError(f"Linux owner-only state contract is missing: {required}")
    secure_store = (
        root / "linux" / "runner" / "linux_secure_store.cc"
    ).read_text(encoding="utf-8")
    for required in ("chmod(directory.c_str(), 0700)", "chmod(path.c_str(), 0600)"):
        if required not in secure_store:
            raise RuntimeError(
                f"Linux secure-store owner-only migration is missing: {required}"
            )
    for required in (
        "Dpkg::Options::=--force-confold",
        "nftables",
        "openresolv",
        "systemd-resolved",
        "policykit-1",
        "iptables",
        "util-linux",
        "winsvpn-xray",
        "select_unreferenced_system_uid",
        'useradd --system --uid "$xray_install_uid" --no-create-home',
        "usermod --home /nonexistent",
    ):
        if required not in installer:
            raise RuntimeError(f"Linux fresh-install dependency contract is missing: {required}")
    print("PASS Linux pinned AmneziaWG kernel-first/userspace-fallback bundle")


def verify_latest_awg_release() -> None:
    tools_dir = str(pathlib.Path(__file__).resolve().parent)
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    import verify_latest_awg_release as latest_awg

    latest_awg.verify_latest_awg_release(root=pathlib.Path(__file__).resolve().parent.parent)


def main() -> int:
    try:
        verify_latest_awg_release()
        verify_downloads()
        verify_tpot_commit()
        verify_latest_release_pins()
        verify_suricata_package_contract()
        verify_ollama_pins()
        verify_server_awg_source_build_contract()
        verify_workflow_pins()
        verify_android_runtime_pins()
        verify_xray_engine_rebuild_pins()
        verify_amneziawg_engine_rebuild_pins()
        verify_windows_amneziawg_client_rebuild_pins()
        verify_linux_runtime_pins()
    except Exception as exc:
        print(f"FAIL deployment supply chain: {exc}", file=sys.stderr)
        return 1
    print("Deployment supply-chain pins verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
