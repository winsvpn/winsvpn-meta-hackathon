#!/usr/bin/env python3
"""Focused regression tests for the official Apple AWG 3.1 producers."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_latest_awg_release as latest_awg  # noqa: E402

BRIDGE = ROOT / "tools" / "build_apple_wg_go_bridge.sh"
WRAPPERS = ROOT / "tools" / "build_apple_engine_wrappers.sh"
STAGING = ROOT / "tools" / "stage_apple_engine_artifacts.sh"
RELEASE = ROOT / "tools" / "build_apple_release_candidates.sh"
README = ROOT / "apple" / "EngineArtifacts" / "README.md"

REPOSITORY = "https://github.com/amnezia-vpn/amneziawg-apple.git"
TAG = "v3.1.20260814"
COMMIT = "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"
TREE = "24183de0cc22b957ff9e34ac3494a80f515ac565"
GO_MOD_SHA256 = "790252dad6cad8aa668ccc4dafdfdac4f2fa3d3fbefce16ded750f0a46cabe0d"
GO_SUM_SHA256 = "1a806e7973118c0ce8832e15d246fea0c44335a31fc4a0abe36a2ed165fada9d"
GO_ARM64_SHA256 = "ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12"
GO_AMD64_SHA256 = "8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4"
GO_ARM64_TREE_SHA256 = "f8de74060cc6cfa4a52c3768a6999c0eb4119dec0281d75d225d44a35a2975ac"
GO_ARM64_EXECUTABLE_SHA256 = "132b69336a1f809932a8a20b0201dbbb980e86e3a323ae32e893639d83d71598"
LIBXRAY_COMMIT = "e8cc06d7427251fa549093e7cc32c28b0f5fbafa"
LIBXRAY_ZIP_SHA256 = "9435bf77b8da780438b4e152a6b75b35991a920bd4ab5b00533613e8d1d54f4f"
XRAY_COMMIT = "77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3"
XRAY_ZIP_SHA256 = "7df5ebc400da6cc4ab13f5578e2fd19b855f98807f1ef1d86a30afc2cd213c40"
AWG_GO_MODULE_ZIP_SHA256 = "14f378d365a612a60aa4352e257d06a02a0091023fd47cb0b4fa7a3e27a174dd"
XRAY_REVIEW_MOD_SHA256 = "b8d76ea5d2b8cc175934df7be21bbd4f2d8c077b1e3d8b89b0e407017b143f83"
XRAY_REVIEW_SUM_SHA256 = "7b3bed540ff49c058d43a3bd778880e0e57e402527a9da8ba7822aa8bdc2329b"
XRAY_VENDOR_CLOSURE_SHA256 = "ce72b7f83277a9011e3ba40d9bb754df4a7d043c5f84c6e5c05a5cfb067f4778"
GO_VERSION = "1.27.1"
LOWER_POLICY_TAG = "v3.1.4"
LOWER_POLICY_COMMIT = "811f5c8213e6b257e9520fff713ec4d22086e9ac"
TOOLS_TAG = "v3.1.20260812"
TOOLS_COMMIT = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
# Release pins that cannot be measured without network access. Measured
# 2026-10-15 from the official tag and proxy.golang.org (each module ZIP's h1:
# dirhash checked against sum.golang.org); the reviewed modfile, sumfile and
# vendor closure come from the bridge's own tidy/vendor/patch sequence. The
# bridge still refuses (exit 65) while any of them is empty or malformed.
MEASURED_BRIDGE_PINS = {
    "AMNEZIAWG_APPLE_GO_MOD_SHA256": GO_MOD_SHA256,
    "AMNEZIAWG_APPLE_GO_SUM_SHA256": GO_SUM_SHA256,
    "AMNEZIAWG_GO_MODULE_ZIP_SHA256": AWG_GO_MODULE_ZIP_SHA256,
    "AMNEZIA_LIBXRAY_ZIP_SHA256": LIBXRAY_ZIP_SHA256,
    "AMNEZIA_XRAY_ZIP_SHA256": XRAY_ZIP_SHA256,
    "AMNEZIA_XRAY_REVIEW_MOD_SHA256": XRAY_REVIEW_MOD_SHA256,
    "AMNEZIA_XRAY_REVIEW_SUM_SHA256": XRAY_REVIEW_SUM_SHA256,
    "AMNEZIA_XRAY_PATCHED_VENDOR_CLOSURE_SHA256": XRAY_VENDOR_CLOSURE_SHA256,
}
UNPINNED_BRIDGE_PINS = tuple(MEASURED_BRIDGE_PINS)
DRIVER = ROOT / "tools" / "winn_release.py"
PINS = ROOT / "tools" / "toolchain-pins.json"
# Strings of the retired ReleaseGo/ReleasePython custody gate. None may remain
# in the AWG bridge or the Apple release-candidate producer.
RETIRED_GO_CUSTODY = (
    "wins_release_go_run",
    "wins_release_go_verify",
    "wins_release_go_prepare",
    "wins_release_go_cleanup",
    "wins_release_python_",
    "release_go_archive_custody.sh",
    "release_python_archive_custody.sh",
    "prepare_release_go_custody",
    "APPLE_AWG_RELEASE_GO_EXECUTION_CONTRACT",
    "wins-release-go-run-v1",
    "WINS_RELEASE_GO_TREE_SHA256",
    "WINS_RELEASE_GO_SHA256",
    "/Library/WinsVPN/Release",
)


def bridge_pin(name: str) -> str:
    """The value of a NAME="..." pin line in the AWG bridge."""
    prefix = f'{name}="'
    for line in BRIDGE.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix) and line.endswith('"'):
            return line[len(prefix):-1]
    raise AssertionError(f"{name} pin is missing from {BRIDGE}")


def pinned_go_archive() -> pathlib.Path | None:
    """The official pinned Go archive, if this host has one (no download)."""
    candidates = [os.environ.get("WINS_WINN_GO_ARCHIVE", "")]
    try:
        paths = json.loads(PINS.read_text(encoding="utf-8"))["tools"]["go"].get("archive_path", {})
        candidates.extend(paths.values() if isinstance(paths, dict) else ())
    except (OSError, KeyError, ValueError):
        pass
    for candidate in candidates:
        if candidate and pathlib.Path(candidate).expanduser().is_file():
            return pathlib.Path(candidate).expanduser()
    return None


def bash_function(path: pathlib.Path, name: str) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.index(f"\n{name}() {{\n") + 1
    return text[start : text.index("\n}\n", start) + 3]


def remove_frozen_tree(path: pathlib.Path) -> None:
    """Remove a test-owned copy of a frozen (0500/0400) Go tree."""
    if not path.exists():
        return
    subprocess.run(["chmod", "-R", "u+w", str(path)], check=False)
    shutil.rmtree(path)


def bridge_environment(**extra: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("BASH_ENV", None)
    for inherited in tuple(environment):
        if inherited.startswith("BASH_FUNC_"):
            environment.pop(inherited, None)
    for name in (
        "GOFLAGS",
        "GOWORK",
        "GOPROXY",
        "GOSUMDB",
        "GOEXPERIMENT",
        "APPLE_WG_GO_ARCHS",
        "WINS_RELEASE_GO",
        "WINS_RELEASE_GO_ROOT",
        "WINS_RELEASE_GO_TREE_SHA256",
        "WINS_RELEASE_GO_SHA256",
    ):
        environment.pop(name, None)
    environment.update(extra)
    return environment


def _clang() -> str:
    return subprocess.check_output(["xcrun", "-f", "clang"], text=True).strip()


def _sdk(name: str) -> str:
    return subprocess.check_output(
        ["xcrun", "--sdk", name, "--show-sdk-path"], text=True
    ).strip()


XRAY_IMPORT_STUB = """\
#include <ifaddrs.h>
#include <sys/socket.h>
#include <unistd.h>
extern char *LibXraySetSockCallback(void *cb, void *ctx);
int wins_xray_vless_ws_transport_contract_version(void) { return 1; }
int wins_xray_vless_ws_transport_configure(const char *config_json) {
  (void)config_json;
  return 1;
}
int wins_xray_vless_ws_transport_start(void) {
  struct ifaddrs *list = 0;
  (void)getifaddrs(&list);
  (void)setsockopt(0, 0, 0, 0, 0);
  (void)dup2(0, 1);
  (void)LibXraySetSockCallback(0, 0);
  return 1;
}
void wins_xray_vless_ws_transport_stop(void) {}
"""
XRAY_TRIPLES = {
    "iphoneos": "arm64-apple-ios13.0",
    "iphonesimulator": "arm64-apple-ios14.0-simulator",
    "macosx": "arm64-apple-macos13.0",
}


def compile_xray_wrapper(path: pathlib.Path, platform: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    src = path.with_suffix(".c")
    src.write_text(XRAY_IMPORT_STUB, encoding="utf-8")
    completed = subprocess.run(
        [
            _clang(),
            "-dynamiclib",
            "-target",
            XRAY_TRIPLES[platform],
            "-isysroot",
            _sdk(platform),
            "-Wl,-undefined,dynamic_lookup",
            "-Wl,-install_name,@rpath/WinsXrayVlessWsTransport.framework/WinsXrayVlessWsTransport",
            str(src),
            "-o",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    src.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise AssertionError(
            f"clang -dynamiclib failed for {path}: {completed.stderr or completed.stdout}"
        )


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def consumer_normalized_sha256(path: pathlib.Path, scratch: pathlib.Path) -> str:
    """The macOS verifier's signature-normalized digest of one file.

    The verifier holds the file and watches its nine nearest ancestors, so the
    copy it holds sits nine quiet directories deep under scratch.
    """
    import verify_macos_release_artifact as consumer

    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The verifier refuses any symbolic path component (for example /var).
    scratch = scratch.resolve()
    held_dir = scratch.joinpath("held", *"abcdefgh")
    held_dir.mkdir(mode=0o700, parents=True)
    work = scratch / "work"
    work.mkdir(mode=0o700)
    copy = held_dir / "engine"
    copy.write_bytes(path.read_bytes())
    with consumer.HeldFile(copy, "fixture engine") as held:
        return consumer.signature_normalized_sha256(
            held, work, "engine", consumer.run_command
        )


class AppleAwg31ProducerTests(unittest.TestCase):
    def source(self, path: pathlib.Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_bridge_freezes_official_source_and_reviewed_dependencies(self) -> None:
        text = self.source(BRIDGE)
        for literal in (
            f'AMNEZIAWG_APPLE_REPO="{REPOSITORY}"',
            f'AMNEZIAWG_APPLE_TAG="{TAG}"',
            f'AMNEZIAWG_APPLE_COMMIT="{COMMIT}"',
            f'AMNEZIAWG_APPLE_TREE="{TREE}"',
            'AMNEZIAWG_APPLE_GENERATION="3.1"',
            f'AMNEZIAWG_APPLE_GO_MOD_SHA256="{GO_MOD_SHA256}"',
            f'AMNEZIAWG_APPLE_GO_SUM_SHA256="{GO_SUM_SHA256}"',
            f'AMNEZIAWG_GO_MODULE_ZIP_SHA256="{AWG_GO_MODULE_ZIP_SHA256}"',
            'AMNEZIAWG_GO_TAG="v3.1.20260828"',
            'AMNEZIAWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"',
            'AMNEZIAWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"',
            'AMNEZIA_LIBXRAY_MODULE="github.com/amnezia-vpn/amnezia-libxray"',
            'AMNEZIA_LIBXRAY_VERSION="v1.0.3"',
            f'AMNEZIA_LIBXRAY_COMMIT="{LIBXRAY_COMMIT}"',
            'AMNEZIA_LIBXRAY_SUM="h1:xaBuYYVwJgwDZEg4zjzpbg2bDlOczXxM7QNV97Z4ZSU="',
            'AMNEZIA_LIBXRAY_GO_MOD_SUM="h1:rhrXlhRYuWZK7Ok3IDM/JxiaPPszmiJxoWFABwAm6Sg="',
            f'AMNEZIA_LIBXRAY_ZIP_SHA256="{LIBXRAY_ZIP_SHA256}"',
            'REVIEWED_GO_VERSION="1.27.1"',
            f'REVIEWED_GO_DARWIN_ARM64_SHA256="{GO_ARM64_SHA256}"',
            f'REVIEWED_GO_DARWIN_AMD64_SHA256="{GO_AMD64_SHA256}"',
            f'REVIEWED_GO_DARWIN_ARM64_TREE_SHA256="{GO_ARM64_TREE_SHA256}"',
            f'REVIEWED_GO_DARWIN_ARM64_EXECUTABLE_SHA256="{GO_ARM64_EXECUTABLE_SHA256}"',
            'AMNEZIA_XRAY_REPLACED_MODULE="github.com/xtls/xray-core"',
            'AMNEZIA_XRAY_VERSION="v1.260924.0"',
            f'AMNEZIA_XRAY_COMMIT="{XRAY_COMMIT}"',
            'AMNEZIA_XRAY_SUM="h1:4PniqnMxVxC54OdTx3e73BOMH/GD6jf85iaRyApAwGQ="',
            'AMNEZIA_XRAY_GO_MOD_SUM="h1:VwJOtL3vj2w+8TWa6MZE1q88NsfrWvOXGJ+5wZ2N2ro="',
            f'AMNEZIA_XRAY_ZIP_SHA256="{XRAY_ZIP_SHA256}"',
            f'AMNEZIA_XRAY_REVIEW_MOD_SHA256="{XRAY_REVIEW_MOD_SHA256}"',
            f'AMNEZIA_XRAY_REVIEW_SUM_SHA256="{XRAY_REVIEW_SUM_SHA256}"',
            f'AMNEZIA_XRAY_PATCHED_VENDOR_CLOSURE_SHA256="{XRAY_VENDOR_CLOSURE_SHA256}"',
        ):
            self.assertIn(literal, text)
        self.assertNotIn("FROZEN_APPLE_", text)
        self.assertNotIn("AMNEZIAWG_APPLE_REF", text)
        self.assertNotIn("0c4d98d1bd927bbba1c3b23c382c3f8881fd6631", text)
        self.assertNotIn(f'AMNEZIAWG_APPLE_TAG="{LOWER_POLICY_TAG}"', text)
        self.assertNotIn(f'AMNEZIAWG_APPLE_COMMIT="{LOWER_POLICY_COMMIT}"', text)
        self.assertNotIn('AMNEZIA_LIBXRAY_VERSION="v1.0.2"', text)
        self.assertNotIn('AMNEZIA_XRAY_VERSION="v1.260206.0"', text)
        self.assertNotIn("${AMNEZIAWG_APPLE_REPO:-", text)
        self.assertNotIn("https://go.dev/dl/go${REVIEWED_GO_VERSION}", text)

    def test_repo_policy_selects_date_tag_over_shorter_semver_tag(self) -> None:
        self.assertGreater(
            latest_awg.version_key(TAG), latest_awg.version_key(LOWER_POLICY_TAG)
        )
        policy_test = self.source(ROOT / "tools" / "test_latest_awg_release.py")
        for literal in (TAG, COMMIT, TOOLS_TAG, TOOLS_COMMIT):
            self.assertIn(literal, policy_test)

    def test_bridge_has_no_sibling_self_pins_or_grep_handoff(self) -> None:
        """The bridge no longer pins the bytes of its sibling producers or greps
        them for schema strings they never contain. The consumers keep their own
        reviewed source pins, which are checked here instead."""
        bridge = self.source(BRIDGE)
        for gone in (
            "FROZEN_APPLE_WRAPPERS",
            "FROZEN_APPLE_STAGING",
            "require_release_closure_and_handoff",
            "APPLE_AWG_PROVENANCE_SCHEMA_VERSION",
            "APPLE_AWG_PER_SLICE_FACTS",
            "staging handoff",
            "OWNER-BLOCKED",
        ):
            self.assertNotIn(gone, bridge)
        self.assertNotIn('"${PROJECT_ROOT}/tools/build_apple_engine_wrappers.sh"', bridge)
        self.assertNotIn('"${PROJECT_ROOT}/tools/stage_apple_engine_artifacts.sh"', bridge)
        for consumer in (WRAPPERS, STAGING):
            text = self.source(consumer)
            for literal in (
                f'APPLE_AWG_EXPECTED_TAG="{TAG}"',
                f'APPLE_AWG_EXPECTED_COMMIT="{COMMIT}"',
                f'APPLE_AWG_EXPECTED_TREE="{TREE}"',
                f'APPLE_AWG_EXPECTED_GO_MOD_SHA256="{GO_MOD_SHA256}"',
                f'APPLE_AWG_EXPECTED_GO_SUM_SHA256="{GO_SUM_SHA256}"',
                f'APPLE_AWG_EXPECTED_XRAY_ZIP_SHA256="{XRAY_ZIP_SHA256}"',
            ):
                self.assertIn(literal, text)
            self.assertIn('APPLE_AWG_EXPECTED_XRAY_VERSION="v1.260924.0"', text)
            self.assertNotIn('APPLE_AWG_PROVENANCE_SCHEMA_VERSION="3"', text)
            self.assertNotIn('APPLE_AWG_PER_SLICE_FACTS=', text)

    def test_libxray_and_core_pairing_matches_current_apple_source(self) -> None:
        readme = self.source(README)
        bridge = self.source(BRIDGE)
        self.assertIn("amnezia-libxray v1.0.3", readme)
        self.assertIn("mixed this policy-selected", readme)
        self.assertIn("Status: pinned 2026-10-15", readme)
        self.assertNotIn("OWNER-BLOCKED", readme)
        self.assertNotIn("handoff", readme)
        self.assertIn("must not be reused, edited", readme)
        self.assertIn('AMNEZIA_LIBXRAY_VERSION="v1.0.3"', bridge)
        self.assertIn('AMNEZIA_XRAY_VERSION="v1.260924.0"', bridge)
        self.assertNotIn('AMNEZIA_XRAY_VERSION="v1.260728.0"', bridge)
        self.assertNotIn('AMNEZIA_XRAY_VERSION="v1.260724.0"', bridge)
        self.assertIn("LibXraySetSockCallback", self.source(WRAPPERS))
        wrapper = self.source(ROOT / "apple" / "EngineWrappers" / "WinsXrayVlessWsTransport.m")
        self.assertIn("LibXraySetSockCallback", wrapper)
        self.assertIn("WINS_XRAY_LIBXRAY_MAX_MEMORY_BYTES", wrapper)
        self.assertNotIn("LibXrayRunXray(g_xray_dat_dir, g_xray_config_path, 0)", wrapper)

    def test_bridge_fails_closed_on_source_and_module_drift(self) -> None:
        text = self.source(BRIDGE)
        sync = text.split("sync_source() {", 1)[1].split("\n}\n", 1)[0]
        contract = text.split("verify_upstream_source_contract() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        xray = text.split("prepare_hostname_safe_xray_module() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        libxray = text.split("verify_pinned_libxray_module() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        awg_go = text.split("verify_pinned_awg_go_module() {", 1)[1].split(
            "\nverify_pinned_libxray_module() {", 1
        )[0]
        closure = text.split("require_release_closure() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn('"refs/tags/${AMNEZIAWG_APPLE_TAG}"', sync)
        self.assertIn('"${fetched_commit}" == "${AMNEZIAWG_APPLE_COMMIT}"', sync)
        self.assertIn('verify_upstream_source_contract', sync)
        self.assertIn('require_absent_path "${APPLE_WG_GO_SOURCE_DIR}"', sync)
        self.assertIn('reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" init -q', sync)
        self.assertNotIn('if [[ -d "${APPLE_WG_GO_SOURCE_DIR}/.git"', sync)
        self.assertIn("HEAD^{tree}", contract)
        self.assertIn("status --porcelain --untracked-files=all", contract)
        self.assertIn("AMNEZIAWG_APPLE_GO_MOD_SHA256", contract)
        self.assertIn("AMNEZIAWG_APPLE_GO_SUM_SHA256", contract)
        self.assertIn("amneziawg-go/v3 ${AMNEZIAWG_APPLE_UPSTREAM_GO_TAG}", contract)
        self.assertIn("AMNEZIAWG_GO_COMMIT", contract)
        self.assertIn("AMNEZIAWG_APPLE_UPSTREAM_GO_SUM", contract)
        self.assertIn(
            '-require="${AMNEZIAWG_GO_MODULE}@${AMNEZIAWG_GO_TAG}"', text
        )
        self.assertIn(
            'Reviewed Apple sum file does not bind amneziawg-go ${AMNEZIAWG_GO_TAG}.',
            text,
        )
        self.assertIn("AMNEZIAWG_GO_MOD_SUM", contract)
        # The pristine checkout is verified against the official tag's own
        # libxray pin, never against the raised reviewed release.
        self.assertIn("AMNEZIA_LIBXRAY_UPSTREAM_VERSION", contract)
        self.assertIn("AMNEZIA_LIBXRAY_UPSTREAM_SUM", contract)
        self.assertIn("AMNEZIA_LIBXRAY_UPSTREAM_GO_MOD_SUM", contract)
        self.assertNotIn("${AMNEZIA_LIBXRAY_VERSION}", contract)
        self.assertNotIn("${AMNEZIA_LIBXRAY_SUM}", contract)
        self.assertNotIn("${AMNEZIA_LIBXRAY_GO_MOD_SUM}", contract)
        self.assertIn('awk -v module="${AMNEZIA_LIBXRAY_MODULE}"', contract)
        self.assertIn("Apple wrapper commit must remain distinct from the Go engine commit.", contract)
        self.assertIn("AMNEZIA_LIBXRAY_SUM", libxray)
        self.assertIn("AMNEZIA_LIBXRAY_GO_MOD_SUM", libxray)
        self.assertIn("AMNEZIA_LIBXRAY_COMMIT", libxray)
        self.assertIn("AMNEZIA_LIBXRAY_ZIP_SHA256", text)
        self.assertIn("AMNEZIA_XRAY_SUM", xray)
        self.assertIn("AMNEZIA_XRAY_GO_MOD_SUM", xray)
        self.assertIn("AMNEZIA_XRAY_COMMIT", xray)
        self.assertIn("AMNEZIA_XRAY_ZIP_SHA256", text)
        self.assertIn("verify_reviewed_modfile", text)
        for literal in (
            'AMNEZIA_LIBXRAY_UPSTREAM_VERSION="v1.0.2"',
            'AMNEZIA_LIBXRAY_UPSTREAM_SUM="h1:em3rcsaOztgOXxvpBOEyAw+OKdfX+fUiibEMI3K79/s="',
            'AMNEZIA_LIBXRAY_UPSTREAM_GO_MOD_SUM="h1:jWzoA5Zd3qu6XJ/4Knz7kQyvaOrLZrPXGQQ0NL7mfPQ="',
        ):
            self.assertIn(literal, text)
        require = '-require="${AMNEZIA_LIBXRAY_MODULE}@${AMNEZIA_LIBXRAY_VERSION}"'
        self.assertEqual(1, text.count(require))
        self.assertLess(
            text.index(require),
            text.index("reviewed_go '' mod tidy -modfile"),
        )
        self.assertIn(
            'grep -Fqx "# ${AMNEZIAWG_GO_MODULE} ${AMNEZIAWG_GO_TAG}"', text
        )
        self.assertIn("mod tidy -modfile", text)
        self.assertIn("reviewed_go '' mod tidy -modfile", text)
        self.assertIn("AMNEZIA_XRAY_REVIEW_MOD_SHA256", text)
        self.assertIn("AMNEZIA_XRAY_REVIEW_SUM_SHA256", text)
        self.assertIn("AMNEZIA_XRAY_PATCHED_VENDOR_CLOSURE_SHA256", text)
        self.assertIn(
            'require_sha256 "${module_zip}" "${AMNEZIAWG_GO_MODULE_ZIP_SHA256}"',
            awg_go,
        )
        self.assertNotIn("AMNEZIAWG_GO_MODULE_ZIP_SHA256=", awg_go)
        for literal in (
            "FROZEN_APPLE_WRAPPERS_SHA256",
            "FROZEN_APPLE_STAGING_SHA256",
            "APPLE_AWG_PROVENANCE_SCHEMA_VERSION",
            "APPLE_AWG_PER_SLICE_FACTS",
            "grep -Fqx",
        ):
            self.assertNotIn(literal, closure)
        # The pinned module checksums, commits and Go sums stay real gates.
        for literal in UNPINNED_BRIDGE_PINS + (
            '"${AMNEZIAWG_APPLE_TREE}" =~ ^[0-9a-f]{40}$',
            '"${AMNEZIA_LIBXRAY_COMMIT}" =~ ^[0-9a-f]{40}$',
            '"${AMNEZIA_XRAY_COMMIT}" =~ ^[0-9a-f]{40}$',
            '"${AMNEZIA_LIBXRAY_SUM}" == h1:*',
            '"${AMNEZIA_LIBXRAY_GO_MOD_SUM}" == h1:*',
            '"${AMNEZIA_XRAY_SUM}" == h1:*',
            '"${AMNEZIA_XRAY_GO_MOD_SUM}" == h1:*',
            'die_unpinned "${missing[@]}"',
        ):
            self.assertIn(literal, closure)
        self.assertNotIn("wins_release_go_run", closure)
        main = text.split("main() {", 1)[1].split("\n}\n", 1)[0]
        self.assertLess(
            main.index("require_release_closure"),
            main.index("ensure_tools"),
        )
        self.assertLess(
            main.index("require_release_closure"),
            main.index('require_absent_path "${APPLE_WG_GO_OUTPUT_DIR}"'),
        )
        self.assertIn("mod vendor -modfile", text)
        self.assertIn("-mod=vendor", text)
        flags = text.split("apple_wg_go_flags() {", 1)[1].split("\n}\n", 1)[0]
        self.assertLess(
            flags.index('"${APPLE_WG_GO_REPRODUCIBLE_GOFLAGS}"'),
            flags.index('"${PATCHED_GOFLAGS}"'),
            "-mod=vendor must follow and override the generic -mod=readonly flag",
        )
        self.assertIn("GOWORK=off", text)
        self.assertIn('require_absent_path "${APPLE_WG_GO_OUTPUT_DIR}"', text)
        self.assertNotIn('"${APPLE_WG_GO_OUTPUT_DIR}"/.tmp/iphonesimulator', text)
        self.assertNotIn('-replace="${AMNEZIA_XRAY_REPLACED_MODULE}=${patched_root}"', text)
        self.assertIn("-mod=readonly", text)

    def test_bridge_takes_pinned_go_root_and_constructs_environment(self) -> None:
        text = self.source(BRIDGE)
        custody = text.split("prepare_reviewed_go() {", 1)[1].split("\n}\n", 1)[0]
        measure = text.split("verify_reviewed_go_root() {", 1)[1].split("\n}\n", 1)[0]
        reviewed = text.split("\nreviewed_go() {", 1)[1].split("\n}\n", 1)[0]
        reviewed_git = text.split("\nreviewed_git() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        build_once = text.split("build_platform_once() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        main = text.split("\nmain() {", 1)[1].split("\n}\n", 1)[0]
        for retired in RETIRED_GO_CUSTODY:
            self.assertNotIn(retired, text, retired)
        self.assertIn("WINS_RELEASE_GO_ROOT", custody)
        self.assertIn('verify_reviewed_go_root "before build"', custody)
        self.assertIn('"go version go${REVIEWED_GO_VERSION} darwin/arm64"', custody)
        self.assertLess(
            custody.index('verify_reviewed_go_root "before build"'),
            custody.index("reviewed_go '' version"),
            "bin/go must be measured before it is ever executed",
        )
        for literal in (
            'require_sha256 "${GO_BIN}" "${REVIEWED_GO_DARWIN_ARM64_EXECUTABLE_SHA256}"',
            '/usr/bin/python3 -I "${PROJECT_ROOT}/tools/winn_release.py"',
            'digest --kind go-tree "${WINS_RELEASE_GO_ROOT}"',
            '"${measured_tree}" == "${REVIEWED_GO_DARWIN_ARM64_TREE_SHA256}"',
        ):
            self.assertIn(literal, measure)
        self.assertIn('verify_reviewed_go_root "after build"', main)
        self.assertLess(
            main.index("build_platform iphonesimulator"),
            main.index('verify_reviewed_go_root "after build"'),
        )
        self.assertEqual(bridge_pin("REVIEWED_GO_VERSION"), GO_VERSION)
        pins = json.loads(PINS.read_text(encoding="utf-8"))["tools"]["go"]
        self.assertEqual(pins["version"], GO_VERSION)
        self.assertEqual(
            bridge_pin("REVIEWED_GO_DARWIN_ARM64_EXECUTABLE_SHA256"), pins["executable_sha256"]
        )
        self.assertEqual(
            bridge_pin("REVIEWED_GO_DARWIN_ARM64_TREE_SHA256"),
            pins["install_tree_sha256"]["darwin_arm64"],
        )
        self.assertEqual(
            bridge_pin("REVIEWED_GO_DARWIN_ARM64_SHA256"), pins["archive_sha256"]["darwin_arm64"]
        )
        for block in (reviewed, build_once):
            self.assertIn("/usr/bin/env -i", block)
            for assignment in (
                "GOENV=off",
                "GOTOOLCHAIN=local",
                "GOWORK=off",
                "GOEXPERIMENT=",
                "GOPRIVATE=",
                "GONOPROXY=",
                "GONOSUMDB=",
                "GOAUTH=off",
                "GOTELEMETRY=off",
            ):
                self.assertIn(assignment, block)
        self.assertIn("GOPROXY=${REVIEWED_GO_PROXY}", reviewed)
        self.assertIn("GOSUMDB=${REVIEWED_GO_SUMDB}", reviewed)
        self.assertNotIn("curl ", custody)
        self.assertNotIn("tar -x", custody)
        self.assertIn("/usr/bin/env -i", reviewed_git)
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", reviewed_git)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", reviewed_git)
        self.assertIn("GIT_TERMINAL_PROMPT=0", reviewed_git)
        self.assertIn("GIT_ASKPASS=/usr/bin/false", reviewed_git)

    def test_bridge_refuses_hostile_ambient_go_variables(self) -> None:
        clean = os.environ.copy()
        for name in (
            "GOFLAGS",
            "GOWORK",
            "GOPROXY",
            "GOSUMDB",
            "GOEXPERIMENT",
            "APPLE_WG_GO_ARCHS",
        ):
            clean.pop(name, None)
        for name in (
            "GOFLAGS",
            "GOWORK",
            "GOPROXY",
            "GOSUMDB",
            "GOEXPERIMENT",
            "APPLE_WG_GO_ARCHS",
        ):
            environment = clean.copy()
            environment[name] = "hostile-value"
            completed = subprocess.run(
                ["bash", str(BRIDGE), "--self-test"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0, name)
            self.assertIn("refused", completed.stderr, name)

    def test_bridge_fails_before_network_without_pinned_module_checksums(self) -> None:
        """A bridge copy whose eight network-measured pins are emptied still
        refuses with exit 65 before any fetch or output directory exists."""
        text = self.source(BRIDGE)
        with tempfile.TemporaryDirectory(prefix="wins-apple-awg-closure-test-") as raw:
            root = pathlib.Path(raw)
            source = root / "source"
            output = root / "output"
            tools = root / "tools"
            tools.mkdir()
            bridge_copy = tools / "build_apple_wg_go_bridge.sh"
            emptied = text
            for name, value in MEASURED_BRIDGE_PINS.items():
                pinned = f'\n{name}="{value}"\n'
                self.assertEqual(emptied.count(pinned), 1, name)
                emptied = emptied.replace(pinned, f'\n{name}=""\n')
            bridge_copy.write_text(emptied, encoding="utf-8")
            environment = bridge_environment(
                APPLE_WG_GO_SOURCE_DIR=str(source), APPLE_WG_GO_OUTPUT_DIR=str(output)
            )
            completed = subprocess.run(
                ["bash", str(bridge_copy)],
                cwd=raw,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 65, completed.stderr)
            self.assertNotIn("OWNER-BLOCKED", completed.stderr)
            for name in UNPINNED_BRIDGE_PINS:
                self.assertIn(f"ERROR: unpinned {name} (", completed.stderr)
            self.assertIn(
                "measure it on a networked host and record it in "
                "tools/build_apple_wg_go_bridge.sh",
                completed.stderr,
            )
            self.assertFalse(source.exists())
            self.assertFalse(output.exists())

    def test_bridge_preflight_passes_once_every_pin_is_recorded(self) -> None:
        """The handoff loop could never pass; with it gone, the bridge with its
        eight measured pins clears --preflight, and each pin alone still blocks."""
        text = self.source(BRIDGE)
        with tempfile.TemporaryDirectory(prefix="wins-apple-awg-preflight-") as raw:
            tools = pathlib.Path(raw) / "tools"
            tools.mkdir()
            bridge_copy = tools / "build_apple_wg_go_bridge.sh"

            def preflight(body: str) -> subprocess.CompletedProcess[str]:
                bridge_copy.write_text(body, encoding="utf-8")
                return subprocess.run(
                    ["/bin/bash", str(bridge_copy), "--preflight"],
                    cwd=raw,
                    env=bridge_environment(),
                    text=True,
                    capture_output=True,
                    check=False,
                )

            filled = text
            for name, value in MEASURED_BRIDGE_PINS.items():
                self.assertRegex(value, r"^[0-9a-f]{64}$", name)
                self.assertEqual(bridge_pin(name), value, name)
                self.assertEqual(filled.count(f'\n{name}="{value}"\n'), 1, name)
            completed = preflight(filled)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Apple AWG release closure pins verified.", completed.stdout)
            for name, value in MEASURED_BRIDGE_PINS.items():
                pinned = f'\n{name}="{value}"\n'
                for bad in ("", "A" * 64, "a" * 63):
                    completed = preflight(filled.replace(pinned, f'\n{name}="{bad}"\n'))
                    self.assertEqual(completed.returncode, 65, (name, bad))
                    self.assertEqual(
                        completed.stderr.count("ERROR: unpinned "), 1, (name, bad)
                    )
                    self.assertIn(f"ERROR: unpinned {name} (", completed.stderr)
            for name, value in (
                ("AMNEZIA_LIBXRAY_COMMIT", "e8cc06d"),
                ("AMNEZIA_XRAY_COMMIT", ""),
                ("AMNEZIAWG_APPLE_TREE", "z" * 40),
            ):
                broken = re.sub(
                    rf'\n{name}="[^"]*"\n', f'\n{name}="{value}"\n', filled, count=1
                )
                completed = preflight(broken)
                self.assertEqual(completed.returncode, 65, name)
                self.assertIn(f"ERROR: unpinned {name} (", completed.stderr)
            for name in ("AMNEZIA_XRAY_SUM", "AMNEZIA_LIBXRAY_GO_MOD_SUM"):
                broken = re.sub(
                    rf'\n{name}="h1:', f'\n{name}="h2:', filled, count=1
                )
                completed = preflight(broken)
                self.assertEqual(completed.returncode, 65, name)
                self.assertIn("ERROR: unpinned ", completed.stderr)

    def test_require_sha256_refuses_unpinned_and_mismatched_files(self) -> None:
        text = self.source(BRIDGE)

        def function(name: str) -> str:
            start = text.index("\n" + name + "() {\n") + 1
            return text[start:text.index("\n}\n", start) + 3]

        harness = "".join(function(name) for name in ("die", "die_unpinned", "require_sha256"))
        with tempfile.TemporaryDirectory(prefix="wins-apple-awg-require-sha-") as raw:
            payload = pathlib.Path(raw) / "payload.bin"
            payload.write_bytes(b"reviewed bytes\n")
            digest = sha256(payload)
            link = pathlib.Path(raw) / "link.bin"
            link.symlink_to(payload)

            def check(path: pathlib.Path, expected: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["/bin/bash", "-c",
                     "set -Eeuo pipefail\n" + harness + 'require_sha256 "$1" "$2" "fixture input"\n',
                     "harness", str(path), expected],
                    env={"PATH": "/usr/bin:/bin"},
                    text=True,
                    capture_output=True,
                    check=False,
                )

            self.assertEqual(check(payload, digest).returncode, 0)
            for expected in ("", digest.upper(), digest[:-1]):
                completed = check(payload, expected)
                self.assertEqual(completed.returncode, 65, expected)
                self.assertIn(
                    "ERROR: unpinned fixture input SHA-256: measure it on a networked host",
                    completed.stderr,
                )
            mismatch = check(payload, "0" * 64)
            self.assertEqual(mismatch.returncode, 1)
            self.assertNotIn("unpinned", mismatch.stderr)
            symbolic = check(link, digest)
            self.assertEqual(symbolic.returncode, 1)
            self.assertIn("missing, non-regular, or symbolic", symbolic.stderr)

    def test_cleanup_removes_read_only_go_module_cache(self) -> None:
        """Go writes its module cache read-only (dirs 0555, files 0444). The
        EXIT-trap cleanup must still remove the private work root and return 0;
        a bare rm -rf failed with EACCES and turned a finished run into exit 1."""
        text = self.source(BRIDGE)

        def function(name: str) -> str:
            start = text.index("\n" + name + "() {\n") + 1
            return text[start:text.index("\n}\n", start) + 3]

        harness = "".join(function(name) for name in ("die", "cleanup_patch_work_root"))
        work_root = pathlib.Path(
            tempfile.mkdtemp(prefix="wins-apple-reviewed-go.", dir="/private/tmp")
        )
        try:
            module = work_root / "gomodcache" / "example.com" / "mod@v1.0.0" / "pkg"
            module.mkdir(parents=True)
            (module / "file.go").write_text("package pkg\n", encoding="utf-8")
            (module / "file.go").chmod(0o444)
            for directory in (module, module.parent, module.parent.parent):
                directory.chmod(0o555)
            completed = subprocess.run(
                ["/bin/bash", "-c",
                 "set -Eeuo pipefail\n" + harness
                 + 'PATCH_MODFILE=""\nPATCH_WORK_ROOT=""\nAPPLE_WG_GO_SOURCE_DIR=""\n'
                 + 'REVIEWED_GO_WORK_ROOT="$1"\ncleanup_patch_work_root\n',
                 "harness", str(work_root)],
                env={"PATH": "/usr/bin:/bin"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(work_root.exists())
        finally:
            remove_frozen_tree(work_root)

    def _deterministic_ar_normalize(self):
        """The normalize() function of the private `ar` the bridge installs."""
        text = self.source(BRIDGE)
        body = text.split("install_deterministic_ar() {", 1)[1].split("\n}\n", 1)[0]
        script = body.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        self.assertTrue(script.startswith("#!/usr/bin/python3 -I\n"))
        self.assertIn('subprocess.run(["/usr/bin/ar", *arguments], check=False)', script)
        namespace: dict[str, object] = {}
        exec(compile(script.split("\narguments = sys.argv[1:]\n", 1)[0], "ar", "exec"), namespace)
        return namespace["normalize"]

    @staticmethod
    def _symdef_padding(data: bytes) -> tuple[int, int]:
        """(first padding byte, end of string table) of a 32-bit __.SYMDEF."""
        import struct

        name = data[8:24].rstrip(b" ")
        body = 68
        if name.startswith(b"#1/"):
            body += int(name[3:])
        ranlib = struct.unpack_from("<I", data, body)[0]
        strings = body + 4 + ranlib + 4
        end = strings + struct.unpack_from("<I", data, body + 4 + ranlib)[0]
        last = strings
        for index in range(ranlib // 8):
            offset = struct.unpack_from("<I", data, body + 4 + index * 8)[0]
            last = max(last, data.index(b"\0", strings + offset) + 1)
        return last, end

    def test_deterministic_ar_zeroes_only_symbol_table_padding(self) -> None:
        """Xcode 27.0 ar/ranlib/libtool leave stray bytes in the __.SYMDEF
        string-table padding in about 1 run in 10. The bridge's private `ar`
        zeroes exactly those bytes, leaves every other byte alone, and refuses
        an archive whose symbol table it cannot parse."""
        normalize = self._deterministic_ar_normalize()
        with tempfile.TemporaryDirectory(prefix="wins-apple-awg-ar-") as raw:
            root = pathlib.Path(raw)
            objects = []
            for name, source in (
                ("a", "int wins_a(void) { return 1; }\n"),
                ("b", "int wins_bb_longer_name(void) { return 2; }\n"),
            ):
                (root / f"{name}.c").write_text(source, encoding="utf-8")
                subprocess.run(
                    [_clang(), "-c", "-target", "arm64-apple-macos13.0",
                     str(root / f"{name}.c"), "-o", str(root / f"{name}.o")],
                    check=True, capture_output=True,
                )
                objects.append(str(root / f"{name}.o"))
            archive = root / "lib.a"
            subprocess.run(
                ["/usr/bin/ar", "-q", "-c", "-s", str(archive), *objects],
                check=True, capture_output=True, env={"ZERO_AR_DATE": "1"},
            )
            clean = bytearray(archive.read_bytes())
            first, end = self._symdef_padding(bytes(clean))
            self.assertGreater(end, first, "fixture needs string-table padding")
            clean[first:end] = bytes(end - first)
            dirty = bytearray(clean)
            dirty[first:end] = bytes(range(1, end - first + 1))
            archive.write_bytes(bytes(dirty))
            normalize(str(archive))
            self.assertEqual(archive.read_bytes(), bytes(clean))
            normalize(str(archive))
            self.assertEqual(archive.read_bytes(), bytes(clean))

            plain = root / "plain.a"
            subprocess.run(
                ["/usr/bin/ar", "-q", "-c", "-S", str(plain), *objects],
                check=True, capture_output=True, env={"ZERO_AR_DATE": "1"},
            )
            not_archive = root / "not-archive.a"
            not_archive.write_bytes(b"not an archive\n" * 8)
            for bad in (plain, not_archive):
                before = bad.read_bytes()
                with self.assertRaises(SystemExit):
                    normalize(str(bad))
                self.assertEqual(bad.read_bytes(), before)

    def test_deterministic_ar_refuses_any_shape_but_the_go_linker_call(self) -> None:
        text = self.source(BRIDGE)
        body = text.split("install_deterministic_ar() {", 1)[1].split("\n}\n", 1)[0]
        script = body.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            wrapper = root / "ar"
            wrapper.write_text(script, encoding="utf-8")
            member = root / "member.o"
            member.write_bytes(b"member")
            for arguments in (
                ["-qcs", str(root / "a.a"), str(member)],
                ["qcs", str(root / "b.a"), str(member)],
                ["-r", "-c", "-s", str(root / "c.a"), str(member)],
                ["-q", "-c", "-s", str(root / "d.a")],
                ["-q", "-c", "-s", str(root / "e.a"), "-v", str(member)],
            ):
                with self.subTest(arguments=arguments[0]):
                    completed = subprocess.run(
                        ["/usr/bin/python3", "-I", str(wrapper), *arguments],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("deterministic ar wrapper accepts only", completed.stderr + completed.stdout)
                    self.assertEqual(sorted(path.name for path in root.glob("*.a")), [])

    def test_bridge_builds_with_the_deterministic_ar(self) -> None:
        text = self.source(BRIDGE)
        build_once = text.split("build_platform_once() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn(
            '"PATH=${WINS_RELEASE_GO_ROOT:?}/bin:${REVIEWED_GO_AR_DIR:?}:/usr/bin:/bin:/usr/sbin:/sbin"',
            build_once,
        )
        self.assertIn('! -e "${WINS_RELEASE_GO_ROOT:?}/bin/ar"', build_once)
        # cmd/link takes its archiver from `clang --print-prog-name=ar`, so the
        # private ar reaches it through COMPILER_PATH, and the build refuses
        # if this Xcode's clang does not resolve it there.
        self.assertIn('"COMPILER_PATH=${REVIEWED_GO_AR_DIR:?}"', build_once)
        self.assertIn('--print-prog-name=ar)" == "${REVIEWED_GO_AR_DIR}/ar"', build_once)
        self.assertLess(
            build_once.index("--print-prog-name=ar"), build_once.index("/usr/bin/make")
        )
        main = text.split("\nmain() {", 1)[1].split("\n}\n", 1)[0]
        self.assertLess(main.index("install_deterministic_ar"), main.index("build_platform macosx"))
        install = text.split("install_deterministic_ar() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('REVIEWED_GO_AR_DIR="${REVIEWED_GO_WORK_ROOT:?}/ar-bin"', install)
        self.assertIn('require_absent_path "${REVIEWED_GO_AR_DIR}"', install)

    def test_bridge_go_check_refuses_absent_or_unpinned_go_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-apple-awg-go-root-") as raw:
            root = pathlib.Path(raw).resolve()
            missing = subprocess.run(
                ["bash", str(BRIDGE), "--check-release-go"],
                cwd=ROOT,
                env=bridge_environment(),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("WINS_RELEASE_GO_ROOT must name the pinned Go", missing.stderr)

            # A fake Go that reports the pinned version. Claimed digests in
            # the environment must not admit it, and it must never run.
            fake = root / "go"
            (fake / "bin").mkdir(parents=True)
            marker = root / "fake-go-ran"
            go_bin = fake / "bin" / "go"
            go_bin.write_text(
                "#!/bin/sh\n"
                f"echo ran > '{marker}'\n"
                f"echo 'go version go{GO_VERSION} darwin/arm64'\n",
                encoding="utf-8",
            )
            go_bin.chmod(0o755)
            completed = subprocess.run(
                ["bash", str(BRIDGE), "--check-release-go"],
                cwd=ROOT,
                env=bridge_environment(
                    WINS_RELEASE_GO_ROOT=str(fake),
                    WINS_RELEASE_GO_SHA256=bridge_pin("REVIEWED_GO_DARWIN_ARM64_EXECUTABLE_SHA256"),
                    WINS_RELEASE_GO_TREE_SHA256=bridge_pin("REVIEWED_GO_DARWIN_ARM64_TREE_SHA256"),
                ),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "WINS_RELEASE_GO_ROOT bin/go (before build) SHA-256 verification failed",
                completed.stderr,
            )
            self.assertFalse(marker.exists(), "an unpinned bin/go was executed")

            relative = subprocess.run(
                ["bash", str(BRIDGE), "--check-release-go"],
                cwd=ROOT,
                env=bridge_environment(WINS_RELEASE_GO_ROOT="go"),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(relative.returncode, 0)
            self.assertIn("WINS_RELEASE_GO_ROOT must name the pinned Go", relative.stderr)

    @unittest.skipUnless(
        sys.platform == "darwin" and os.uname().machine == "arm64",
        "the bridge's Go pins are for darwin/arm64",
    )
    def test_bridge_go_check_accepts_pinned_go_and_refuses_changed_copies(self) -> None:
        archive = pinned_go_archive()
        if archive is None:
            self.skipTest("pinned Go archive unavailable; set WINS_WINN_GO_ARCHIVE")
        with tempfile.TemporaryDirectory(prefix="wins-apple-awg-pinned-go-") as raw:
            root = pathlib.Path(raw).resolve()
            try:
                prepared = subprocess.run(
                    ["/usr/bin/python3", "-I", str(DRIVER), "prepare-go",
                     "--out", str(root / "pinned"), "--go-archive", str(archive)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(prepared.returncode, 0, prepared.stderr)
                go_root = pathlib.Path(json.loads(prepared.stdout)["go_root"])

                accepted = subprocess.run(
                    ["bash", str(BRIDGE), "--check-release-go"],
                    cwd=ROOT,
                    env=bridge_environment(WINS_RELEASE_GO_ROOT=str(go_root)),
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                self.assertIn("APPLE AWG PINNED RELEASE GO: PASS", accepted.stdout)

                def changed_copy(name: str, relative: str) -> pathlib.Path:
                    copy = root / name
                    subprocess.run(["cp", "-cR", str(root / "pinned"), str(copy)], check=True)
                    copied_root = copy / go_root.relative_to(root / "pinned")
                    target = copied_root / relative
                    mode = target.stat().st_mode & 0o777
                    target.parent.chmod(0o700)
                    target.chmod(0o600)
                    data = bytearray(target.read_bytes())
                    data[len(data) // 2] ^= 0x01
                    target.write_bytes(bytes(data))
                    target.chmod(mode)
                    target.parent.chmod(0o500)
                    return copied_root

                for name, relative, expected in (
                    ("bin-go", "bin/go", "bin/go (before build) SHA-256 verification failed"),
                    ("tree", "VERSION", "is not the reviewed Go tree"),
                ):
                    copied = changed_copy(name, relative)
                    refused = subprocess.run(
                        ["bash", str(BRIDGE), "--check-release-go"],
                        cwd=ROOT,
                        env=bridge_environment(WINS_RELEASE_GO_ROOT=str(copied)),
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertNotEqual(refused.returncode, 0, name)
                    self.assertIn(expected, refused.stderr, name)
            finally:
                for child in list(root.iterdir()):
                    remove_frozen_tree(child)

    def test_release_candidates_take_pinned_go_from_release_driver(self) -> None:
        release = self.source(RELEASE)
        for retired in RETIRED_GO_CUSTODY:
            self.assertNotIn(retired, release, retired)
        self.assertNotIn("OWNER-BLOCKED: production Release", release)
        self.assertIn('WINN_RELEASE_DRIVER="${ROOT}/tools/winn_release.py"', release)
        prepare = bash_function(RELEASE, "prepare_pinned_release_go")
        self.assertIn("prepare_args=(prepare-go --out", prepare)
        self.assertIn('prepare_args+=(--go-archive "${WINS_WINN_GO_ARCHIVE}")', prepare)
        self.assertIn('"${PYTHON_BIN}" -I "${WINN_RELEASE_DRIVER}" "${prepare_args[@]}"', prepare)
        self.assertIn("export WINS_RELEASE_GO_ROOT", prepare)
        self.assertIn("release_go_cleanup", bash_function(RELEASE, "release_cleanup"))
        call = release.index("\nprepare_pinned_release_go\n")
        self.assertLess(release.index("\nunset WINS_RELEASE_GO_ROOT\n"), call)
        self.assertLess(release.index("\nbegin_receipts\n"), call)
        self.assertLess(call, release.index('source "${ROOT}/tools/build_apple_engine_wrappers.sh" all'))
        # The rest of the producer's gates stay.
        for literal in (
            "Apple releases require Flutter",
            "Set WINS_WINN_RELEASE_DIR to the signed Winn release directory",
            "verify-awg-provenance",
            "verify-winn-provenance",
            "finish_receipt ios",
            "freeze_apple_release_candidates.py",
        ):
            self.assertIn(literal, release)

    def run_release_go_preparation(self, temp: pathlib.Path, archive: str) -> subprocess.CompletedProcess:
        """Run the producer's own prepare/cleanup functions in isolation."""
        script = "\n".join(
            (
                "set -Eeuo pipefail",
                f"ROOT='{ROOT}'",
                "PYTHON_BIN=/usr/bin/python3",
                'WINN_RELEASE_DRIVER="${ROOT}/tools/winn_release.py"',
                'RELEASE_GO_WORK=""',
                'RELEASE_GO_WORK_PARENT=""',
                f"REQUIRED_GO_VERSION='{GO_VERSION}'",
                "die() { printf 'DIE: %s\\n' \"$*\" >&2; exit 65; }",
                bash_function(RELEASE, "release_go_cleanup"),
                bash_function(RELEASE, "prepare_pinned_release_go"),
                "trap release_go_cleanup EXIT",
                "unset WINS_RELEASE_GO_ROOT",
                "prepare_pinned_release_go",
                "printf 'WORK=%s\\n' \"${RELEASE_GO_WORK}\"",
                "/usr/bin/env | /usr/bin/sed -n 's/^WINS_RELEASE_GO_ROOT=/EXPORTED=/p'",
            )
        )
        environment = os.environ.copy()
        environment["TMPDIR"] = str(temp)
        environment["WINS_WINN_GO_ARCHIVE"] = archive
        environment.pop("WINS_RELEASE_GO_ROOT", None)
        return subprocess.run(
            ["bash", "-c", script],
            cwd=temp,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_release_candidates_refuse_go_archive_off_the_pin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-apple-release-go-") as raw:
            temp = pathlib.Path(raw).resolve()
            archive = temp / "go-tampered.tar.gz"
            archive.write_bytes(b"not the pinned Go archive")
            completed = self.run_release_go_preparation(temp, str(archive))
            self.assertEqual(completed.returncode, 65, completed.stderr)
            self.assertIn("is not the pinned", completed.stderr)
            self.assertIn("DIE: Pinned Go could not be prepared", completed.stderr)
            self.assertNotIn("EXPORTED=", completed.stdout)
            leftovers = [path.name for path in temp.iterdir() if path.name != archive.name]
            self.assertEqual(leftovers, [], "the private Go work directory must be removed")

    @unittest.skipUnless(sys.platform == "darwin", "Go install-tree pin exists for darwin only")
    def test_release_candidates_export_verified_pinned_go_and_clean_up(self) -> None:
        archive = pinned_go_archive()
        if archive is None:
            self.skipTest("pinned Go archive unavailable; set WINS_WINN_GO_ARCHIVE")
        with tempfile.TemporaryDirectory(prefix="wins-apple-release-go-") as raw:
            temp = pathlib.Path(raw).resolve()
            try:
                completed = self.run_release_go_preparation(temp, str(archive))
                self.assertEqual(completed.returncode, 0, completed.stderr)
                lines = dict(
                    line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
                )
                work = pathlib.Path(lines["WORK"])
                exported = pathlib.Path(lines["EXPORTED"])
                self.assertEqual(work.parent, temp)
                self.assertTrue(str(exported).startswith(str(work) + "/go/"))
                self.assertFalse(work.exists(), "cleanup must remove the extracted Go")
                self.assertEqual([path for path in temp.iterdir()], [])
            finally:
                for child in list(temp.iterdir()):
                    remove_frozen_tree(child)

    @unittest.skipUnless(
        sys.platform == "darwin" and os.uname().machine == "arm64",
        "the bridge's Go pins are for darwin/arm64",
    )
    def test_release_candidates_go_is_accepted_by_the_bridge(self) -> None:
        archive = pinned_go_archive()
        if archive is None:
            self.skipTest("pinned Go archive unavailable; set WINS_WINN_GO_ARCHIVE")
        with tempfile.TemporaryDirectory(prefix="wins-apple-release-go-") as raw:
            temp = pathlib.Path(raw).resolve()
            script_suffix = (
                '\n/bin/bash "${ROOT}/tools/build_apple_wg_go_bridge.sh" --check-release-go'
            )
            try:
                environment = bridge_environment(TMPDIR=str(temp), WINS_WINN_GO_ARCHIVE=str(archive))
                script = "\n".join(
                    (
                        "set -Eeuo pipefail",
                        f"ROOT='{ROOT}'",
                        "PYTHON_BIN=/usr/bin/python3",
                        'WINN_RELEASE_DRIVER="${ROOT}/tools/winn_release.py"',
                        'RELEASE_GO_WORK=""',
                        'RELEASE_GO_WORK_PARENT=""',
                        f"REQUIRED_GO_VERSION='{GO_VERSION}'",
                        "die() { printf 'DIE: %s\\n' \"$*\" >&2; exit 65; }",
                        bash_function(RELEASE, "release_go_cleanup"),
                        bash_function(RELEASE, "prepare_pinned_release_go"),
                        "trap release_go_cleanup EXIT",
                        "prepare_pinned_release_go",
                    )
                ) + script_suffix
                completed = subprocess.run(
                    ["bash", "-c", script],
                    cwd=temp,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("APPLE AWG PINNED RELEASE GO: PASS", completed.stdout)
                self.assertEqual([path for path in temp.iterdir()], [])
            finally:
                for child in list(temp.iterdir()):
                    remove_frozen_tree(child)

    def test_all_required_architectures_remain_mandatory(self) -> None:
        bridge = self.source(BRIDGE)
        wrappers = self.source(WRAPPERS)
        for text in (bridge, wrappers):
            self.assertIn("macosx) printf 'arm64 x86_64", text)
            self.assertIn("iphoneos) printf 'arm64", text)
            self.assertIn("iphonesimulator) printf 'arm64 x86_64", text)
        self.assertIn('APPLE_MACOS_DEPLOYMENT_TARGET="${APPLE_MACOS_DEPLOYMENT_TARGET:-13.0}"', bridge)
        self.assertIn('APPLE_MACOS_DEPLOYMENT_TARGET="${APPLE_MACOS_DEPLOYMENT_TARGET:-13.0}"', wrappers)
        winn_builder = (ROOT / "tools" / "build_winn_protocol_engine.sh").read_text()
        self.assertIn("MACOS_DEPLOYMENT_TARGET=13.0", winn_builder)
        self.assertNotIn("MACOS_DEPLOYMENT_TARGET=11.0", winn_builder)
        self.assertNotIn(
            'stage="$(new_stage_dir)"',
            winn_builder,
            "command substitution loses the parent cleanup-array update",
        )
        self.assertNotIn("$(new_stage_dir)", winn_builder)
        self.assertIn('"${NEW_STAGE_DIR}/', winn_builder)
        simulator_gate = bridge.split("validate_simulator_cgo_helpers() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        for symbol in (
            "_cgo_sys_thread_start",
            "x_cgo_getstackbound",
            "x_cgo_init",
            "x_cgo_sys_thread_create",
            "x_cgo_thread_start",
        ):
            self.assertIn(symbol, simulator_gate)
        self.assertNotIn("darwin_arm_init_thread_exception_port", simulator_gate)
        self.assertNotIn("darwin_arm_init_mach_exception_handler", simulator_gate)
        exact = bridge.split("validate_archs() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('"${actual_normalized}" == "${required_normalized}"', exact)
        deterministic = bridge.split("build_platform() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn("first_sha", deterministic)
        self.assertIn("second_sha", deterministic)
        self.assertIn('"${first_sha}" == "${second_sha}"', deterministic)
        self.assertEqual(deterministic.count("build_platform_once"), 2)

    def test_provenance_is_required_across_the_release_producer_chain(self) -> None:
        bridge = self.source(BRIDGE)
        wrappers = self.source(WRAPPERS)
        staging = self.source(STAGING)
        release = self.source(RELEASE)
        readme = self.source(README)

        self.assertIn("write_bridge_provenance", bridge)
        self.assertIn("apple_awg_31_bridge_provenance.json", bridge)
        for literal in (
            '"build_contract":',
            '"double_build_verified": True',
            '"go_engine":',
            '"module_zip_sha256": awg_go_module_zip_sha256',
            '"libxray":',
            '"module_closure":',
            '"pinned_go_root":',
            '"source_archive_sha256": awg_go_source_sha256',
        ):
            self.assertIn(literal, bridge)
        self.assertLess(
            bridge.index("run_embedded_runtime_gate", bridge.index("main() {")),
            bridge.index("write_bridge_provenance", bridge.index("main() {")),
        )
        self.assertIn("verify_awg_provenance bridge", wrappers)
        self.assertIn("write_engine_provenance", wrappers)
        self.assertIn("write_xray_provenance", wrappers)
        self.assertIn("verify-awg-provenance", wrappers)
        self.assertIn("verify-xray-provenance", wrappers)
        self.assertIn("verify_and_stage_awg_provenance", staging)
        self.assertIn("apple_awg_31_provenance_sha256", staging)
        self.assertIn("apple_xray_vless_ws_provenance_sha256", staging)
        verification = (
            '/bin/bash "${ROOT}/tools/build_apple_engine_wrappers.sh" '
            "verify-awg-provenance"
        )
        self.assertIn(verification, release)
        self.assertGreater(
            release.index(verification),
            release.index("WINS_SKIP_APPLE_ENGINE_WRAPPER_BUILD"),
        )
        self.assertIn("apple_awg_31_bridge_provenance.json", readme)
        self.assertIn("apple_awg_31_engine_provenance.json", readme)
        self.assertIn("apple_xray_vless_ws_engine_provenance.json", readme)

    def test_shell_syntax_and_offline_self_tests(self) -> None:
        subprocess.run(["bash", "-n", str(BRIDGE)], cwd=ROOT, check=True)
        environment = os.environ.copy()
        for name in (
            "GOFLAGS",
            "GOWORK",
            "GOPROXY",
            "GOSUMDB",
            "GOEXPERIMENT",
            "APPLE_WG_GO_ARCHS",
        ):
            environment.pop(name, None)
        subprocess.run(
            ["bash", str(BRIDGE), "--self-test"],
            cwd=ROOT,
            env=environment,
            check=True,
        )

    def _awg_engine_fixture(self, root: pathlib.Path) -> dict[str, object]:
        """Bridge and wrapper fixtures; the macOS wrappers are real dylibs.

        Returns the environment, engine root, source root and the engine
        manifest whose macOS records carry the consumer's signature-normalized
        digest of the bytes on disk, so codesign can normalize them.
        """
        bridge_root = root / "bridge"
        engine_root = root / "engines"
        source_root = root / "sources"
        bridge_root.mkdir()
        engine_root.mkdir()
        source_root.mkdir()
        for name in (
            "WinsAmneziaWGPacketEngine.m",
            "WinsXrayVlessWsTransport.m",
        ):
            shutil.copy2(ROOT / "apple/EngineWrappers" / name, source_root / name)

        archive_specs = {
            "iphoneos": ("iphoneos/libwg-go.a", ["arm64"]),
            "iphonesimulator": (
                "iphonesimulator/libwg-go.a",
                ["arm64", "x86_64"],
            ),
            "macosx": ("macosx/libwg-go.a", ["arm64", "x86_64"]),
        }
        archives: dict[str, dict[str, object]] = {}
        for platform, (relative, architectures) in archive_specs.items():
            path = bridge_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"bridge-{platform}".encode("ascii"))
            archives[platform] = {
                "architectures": architectures,
                "path": relative,
                "sha256": sha256(path),
            }

        source = {
            "commit": COMMIT,
            "go_mod_sha256": GO_MOD_SHA256,
            "go_sum_sha256": GO_SUM_SHA256,
            "repository": REPOSITORY,
            "tag": TAG,
            "tree": TREE,
        }
        go_toolchain = {
            "darwin_amd64_archive_sha256": GO_AMD64_SHA256,
            "darwin_arm64_archive_sha256": GO_ARM64_SHA256,
            "version": "1.27.1",
        }
        xray = {
            "commit": XRAY_COMMIT,
            "go_mod_sum": "h1:VwJOtL3vj2w+8TWa6MZE1q88NsfrWvOXGJ+5wZ2N2ro=",
            "module_sum": "h1:4PniqnMxVxC54OdTx3e73BOMH/GD6jf85iaRyApAwGQ=",
            "replaced_module": "github.com/xtls/xray-core",
            "source_module": "github.com/amnezia-vpn/amnezia-xray-core",
            "version": "v1.260924.0",
            "zip_sha256": XRAY_ZIP_SHA256,
        }
        bridge_manifest = {
            "archives": archives,
            "component": "amneziawg-apple",
            "generation": "3.1",
            "go_toolchain": go_toolchain,
            "schema_version": 1,
            "source": source,
            "xray_replacement": xray,
        }
        bridge_manifest_path = bridge_root / "apple_awg_31_bridge_provenance.json"
        bridge_manifest_path.write_text(
            json.dumps(bridge_manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        wrapper_specs = {
            "iphoneos": {
                "amneziawg_packet_engine": (
                    "ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib",
                    ["arm64"],
                ),
                "xray_vless_ws_transport": (
                    "ios/iphoneos/libWinsXrayVlessWsTransport.dylib",
                    ["arm64"],
                ),
            },
            "iphonesimulator": {
                "amneziawg_packet_engine": (
                    "ios/iphonesimulator/libWinsAmneziaWGPacketEngine.dylib",
                    ["arm64", "x86_64"],
                ),
                "xray_vless_ws_transport": (
                    "ios/iphonesimulator/libWinsXrayVlessWsTransport.dylib",
                    ["arm64", "x86_64"],
                ),
            },
            "macosx": {
                "amneziawg_packet_engine": (
                    "macos/libWinsAmneziaWGPacketEngine.dylib",
                    ["arm64", "x86_64"],
                ),
                "xray_vless_ws_transport": (
                    "macos/libWinsXrayVlessWsTransport.dylib",
                    ["arm64", "x86_64"],
                ),
            },
        }
        wrappers: dict[str, dict[str, dict[str, object]]] = {}
        for platform, components in wrapper_specs.items():
            wrappers[platform] = {}
            for component, (relative, architectures) in components.items():
                path = engine_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if component == "xray_vless_ws_transport" or platform == "macosx":
                    compile_xray_wrapper(path, platform)
                else:
                    path.write_bytes(
                        f"wrapper-{platform}-{component}".encode("ascii")
                    )
                wrappers[platform][component] = {
                    "architectures": architectures,
                    "path": relative,
                    "sha256": sha256(path),
                }
                if platform == "macosx":
                    wrappers[platform][component][
                        "signature_normalized_sha256"
                    ] = consumer_normalized_sha256(path, root / f"normalize-{component}")

        engine_manifest = {
            "awg_wrapper_source": {
                "path": "apple/EngineWrappers/WinsAmneziaWGPacketEngine.m",
                "sha256": sha256(source_root / "WinsAmneziaWGPacketEngine.m"),
            },
            "bridge_archives": archives,
            "bridge_provenance_sha256": sha256(bridge_manifest_path),
            "component": "amneziawg-apple-engine-wrappers",
            "generation": "3.1",
            "go_toolchain": go_toolchain,
            "schema_version": 2,
            "source": source,
            "wrappers": wrappers,
            "xray_replacement": xray,
        }
        (engine_root / "apple_awg_31_engine_provenance.json").write_text(
            json.dumps(engine_manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["APPLE_WG_GO_OUTPUT_DIR"] = str(bridge_root)
        environment["APPLE_ENGINE_WRAPPER_OUTPUT_ROOT"] = str(engine_root)
        environment["APPLE_ENGINE_WRAPPER_SOURCE_DIR"] = str(source_root)
        return {
            "environment": environment,
            "engine_root": engine_root,
            "source_root": source_root,
            "manifest": engine_manifest,
        }

    @unittest.skipIf(
        os.environ.get("WINS_NO_BUILD_TESTS") == "1",
        "fixture Mach-O compilation disabled by no-build lane policy",
    )
    def test_engine_provenance_rejects_changed_wrapper_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-apple-awg31-provenance-") as raw:
            fixture = self._awg_engine_fixture(pathlib.Path(raw))
            environment = fixture["environment"]
            engine_root = fixture["engine_root"]
            source_root = fixture["source_root"]
            command = ["bash", str(WRAPPERS), "verify-awg-provenance"]
            written = subprocess.run(
                ["bash", str(WRAPPERS), "write-xray-provenance"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(written.returncode, 0, written.stderr + written.stdout)
            subprocess.run(command, cwd=ROOT, env=environment, check=True)

            awg_source = source_root / "WinsAmneziaWGPacketEngine.m"
            original_source = awg_source.read_bytes()
            awg_source.write_bytes(original_source + b"\n// hostile source mutation\n")
            stale_source = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(stale_source.returncode, 0)
            self.assertIn("AWG wrapper source mismatch", stale_source.stderr)
            awg_source.write_bytes(original_source)

            changed = engine_root / "macos/libWinsAmneziaWGPacketEngine.dylib"
            changed.write_bytes(changed.read_bytes() + b"tampered")
            failed = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("SHA-256 mismatch", failed.stderr)

    @unittest.skipIf(
        os.environ.get("WINS_NO_BUILD_TESTS") == "1",
        "fixture Mach-O compilation disabled by no-build lane policy",
    )
    def test_engine_provenance_requires_the_macos_signature_normalized_digest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-apple-awg31-normalized-") as raw:
            fixture = self._awg_engine_fixture(pathlib.Path(raw))
            environment = fixture["environment"]
            manifest_path = fixture["engine_root"] / "apple_awg_31_engine_provenance.json"
            command = ["bash", str(WRAPPERS), "verify-awg-provenance"]
            subprocess.run(
                ["bash", str(WRAPPERS), "write-xray-provenance"],
                cwd=ROOT, env=environment, capture_output=True, check=True,
            )
            subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, check=True)
            for label, value in (("missing", None), ("foreign", "0" * 64)):
                with self.subTest(label=label):
                    manifest = json.loads(json.dumps(fixture["manifest"]))
                    record = manifest["wrappers"]["macosx"]["amneziawg_packet_engine"]
                    if value is None:
                        del record["signature_normalized_sha256"]
                    else:
                        record["signature_normalized_sha256"] = value
                    manifest_path.write_text(
                        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                    )
                    failed = subprocess.run(
                        command, cwd=ROOT, env=environment, text=True,
                        capture_output=True, check=False,
                    )
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertIn(
                        "engine macosx amneziawg_packet_engine signature-normalized SHA-256 mismatch",
                        failed.stderr,
                    )

    @unittest.skipIf(
        os.environ.get("WINS_NO_BUILD_TESTS") == "1",
        "fixture Mach-O compilation disabled by no-build lane policy",
    )
    def test_engine_provenance_writer_records_signature_normalized_digests(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-apple-awg31-writer-") as raw:
            root = pathlib.Path(raw)
            fixture = self._awg_engine_fixture(root)
            engine_root = fixture["engine_root"]
            manifest_path = engine_root / "apple_awg_31_engine_provenance.json"
            manifest_path.unlink()
            environment = dict(fixture["environment"], PROJECT_ROOT=str(ROOT))
            # The real writer function, without the build steps main() runs first.
            script = WRAPPERS.read_text(encoding="utf-8")
            self.assertTrue(script.endswith('\nmain "$@"\n'))
            harness = root / "write_engine_provenance.sh"
            harness.write_text(
                script[: -len('main "$@"\n')] + "write_engine_provenance\n", encoding="utf-8"
            )
            written = subprocess.run(
                ["bash", str(harness)], cwd=ROOT, env=environment, text=True,
                capture_output=True, check=False,
            )
            self.assertEqual(written.returncode, 0, written.stderr + written.stdout)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for platform, components in manifest["wrappers"].items():
                for component, record in components.items():
                    path = engine_root / record["path"]
                    with self.subTest(platform=platform, component=component):
                        self.assertEqual(record["sha256"], sha256(path))
                        if platform == "macosx":
                            self.assertEqual(
                                record["signature_normalized_sha256"],
                                consumer_normalized_sha256(
                                    path, root / f"check-{platform}-{component}"
                                ),
                            )
                            self.assertNotEqual(
                                record["signature_normalized_sha256"], record["sha256"]
                            )
                        else:
                            self.assertNotIn("signature_normalized_sha256", record)


if __name__ == "__main__":
    unittest.main()
