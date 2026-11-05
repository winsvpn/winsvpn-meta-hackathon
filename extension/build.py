#!/usr/bin/env python3
"""Build the Chrome, Edge and Firefox packages from one source tree.

    python3 build.py            # all three targets
    python3 build.py chrome     # one target
    python3 build.py --no-zip   # unpacked only, for loading in a browser

The source is not forked three ways. Every target gets a byte-identical copy of
src/, and differs only in manifest.json, which is base.jsonc merged with one
small target fragment. Which adapter runs is decided at runtime by feature
detection, so the Firefox code path is present and parsed in the Chrome package
too -- a per-browser path that is never even loaded is a per-browser path that
rots.

No dependencies. Standard library only, deliberately: a censorship-circumvention
tool whose build pulls packages from a registry is a tool that can be
compromised for all of its users at once, and nothing here is hard enough to
justify that risk.

After the byte-identical copy of src/, a separately pinned official esbuild
binary applies the store-permitted JavaScript size transform to every intended
src/*.js member. That pin is fail-closed (exact version, tarball, and binary
digest), is never fetched or floated from a registry at package time, is not
installed globally, and is not shipped inside the store zip. Package minify
requires a local cache of the frozen archive. Authored src/ remains the
human-readable source; shipping pretty or byte-identical authored JavaScript
is refused.

The build refuses to produce a package if any gate fails. Existing Chrome,
Edge, and Firefox zips can be rechecked without rebuilding:

    python3 build.py --verify chrome path/to/wins-vpn-companion-chrome.zip

A release run also records, per store zip, the exact-target hardening receipt
that the cross-store gate verifies (needs WINS_RELEASE_SECRET_INVENTORY):

    python3 build.py --release-hardening-receipts chrome edge firefox

On a darwin release host this file is also the producer-attested dependency-
freeze producer. It begins one build receipt per store zip before staging,
writes the zips under the repository's build/extension/dist, records their
hardening receipts, rechecks each exact zip, then finishes and verifies the
three receipts (chrome-zip, edge-zip, firefox-zip):

    python3 -I -B extension/build.py --release-build-receipts \\
        .artifacts/release-inputs-<release>/RELEASE_INPUT_INDEX.json

`--verify` extracts the exact archive with fail-closed zip hygiene, then reruns
the producer leakscan and policy gates against those extracted bytes. It never
restages `src/`, never trusts a mutable unpacked `dist/<target>/` tree, and
never rebuilds. Verification reads mutable authored source for producer comparison;
the closure records those inputs but does not establish immutable custody.
Build-time host compilation is skipped; the zip-local gates are:

  1. leakscan self-test        -- prove the address scanner still fires
  2. copy-check self-test      -- prove the honesty checker still fires
  3. leakscan on the package   -- no routable address, no remote URL, no
                                  network-capable API, no eval
  4. manifest + structure      -- permissions, CSP, no web_accessible_resources
  5. copy honesty              -- no overclaim, and the disclaimers still there

A full `build.py` run still also requires:

  6. bridge contract           -- the stand-in host and the REAL compiled host
                                  answer the same fixture, and each other,
                                  identically
  7. native-host identity      -- per target: Chrome/Edge templates name
                                  exact, distinct, non-placeholder ids that
                                  match the checked-in store record; the
                                  Firefox template matches the canonical
                                  gecko id; Safari uses its containing app

Gates 1 and 2 exist because this project has repeatedly found guards that had
quietly stopped working. Running the self-test on every build is the difference
between a guard and a comment that looks like a guard.

Gate 3 exists because a guard that looked like a guard was never actually
comparing the two things it existed to keep in agreement. On 2026-08-07 the real
compiled host was found to have nested the status snapshot where the extension
reads it flat -- so the real host and the real extension could not interoperate
on any browser -- and it survived because every verification run in this tree
drove `tools/dev_bridge.py`, which was correct. The fixture lives in that file;
see its module docstring.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath

RELEASE_DEPENDENCY_BUILD_ATTEMPT_SWITCH = (
    "--wins-release-dependency-build-attempt-v2"
)
RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT = (
    "winsvpn-witnessed-build-attempt-v2"
)
RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_MARKER = (
    "WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1"
)
RELEASE_DEPENDENCY_BUILD_ATTEMPT_MARKER = (
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2"
)
RELEASE_DEPENDENCY_NATIVE_HOST = "native-extension-build-host"
RELEASE_DEPENDENCY_NATIVE_RUNTIME = "isolated-python"
RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM = "extension"
RELEASE_DEPENDENCY_BUILD_ATTEMPT_ENV = (
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM",
)
RELEASE_DEPENDENCY_BUILD_ATTEMPT_ENV_PREFIX = (
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_"
)
RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE = re.compile(r"[0-9a-f]{64}\Z")
RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z"
)

# Exact reviewed release-freeze adoption tokens. Keep these literal bindings in
# the native producer; tools/release_dependency_freeze.py verifies their bytes.
RELEASE_DEPENDENCY_NATIVE_HOST_BINDING = (
    "WINS_RELEASE_DEPENDENCY_NATIVE_HOST=native-extension-build-host"
)
RELEASE_DEPENDENCY_NATIVE_RUNTIME_BINDING = (
    "WINS_RELEASE_DEPENDENCY_NATIVE_RUNTIME=isolated-python"
)


def _release_dependency_build_attempt_requested(argv: list[str]) -> bool:
    return RELEASE_DEPENDENCY_BUILD_ATTEMPT_SWITCH in argv[1:]


def _release_dependency_witness_payload(nonce: str) -> bytes:
    return (
        json.dumps(
            {
                "contract": RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT,
                "marker": RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_MARKER,
                "native_host": RELEASE_DEPENDENCY_NATIVE_HOST,
                "nonce": nonce,
                "platform": RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM,
                "runtime": RELEASE_DEPENDENCY_NATIVE_RUNTIME,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _release_dependency_output_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_uid,
    )


def _read_release_dependency_output(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _run_release_dependency_build_attempt(
    argv: list[str], environment: dict[str, str]
) -> int:
    directory_descriptor = -1
    output_descriptor = -1
    try:
        if argv[1:] != [RELEASE_DEPENDENCY_BUILD_ATTEMPT_SWITCH]:
            raise RuntimeError("invalid witnessed build-attempt arguments")
        if not sys.flags.isolated or not sys.flags.no_site:
            raise RuntimeError("witnessed build attempt requires isolated Python")

        namespaced_names = tuple(
            name
            for name in environment
            if isinstance(name, str)
            and name.upper().startswith(RELEASE_DEPENDENCY_BUILD_ATTEMPT_ENV_PREFIX)
        )
        if (
            len(namespaced_names) != len(set(namespaced_names))
            or set(namespaced_names) != set(RELEASE_DEPENDENCY_BUILD_ATTEMPT_ENV)
        ):
            raise RuntimeError("invalid witnessed build-attempt environment")

        contract = environment.get("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT")
        nonce = environment.get("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE")
        output_name = environment.get("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT")
        platform = environment.get("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM")
        if contract != RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT:
            raise RuntimeError("invalid witnessed build-attempt contract")
        if (
            not isinstance(nonce, str)
            or RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE.fullmatch(nonce) is None
        ):
            raise RuntimeError("invalid witnessed build-attempt nonce")
        if platform != RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM:
            raise RuntimeError("invalid witnessed build-attempt platform")
        if (
            not isinstance(output_name, str)
            or RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT.fullmatch(output_name) is None
            or output_name in {".", ".."}
            or os.path.basename(output_name) != output_name
            or "/" in output_name
            or "\\" in output_name
        ):
            raise RuntimeError("invalid witnessed build-attempt output")

        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
            raise RuntimeError("descriptor-safe witnessed output is unsupported")
        directory_descriptor = os.open(
            ".",
            directory_flags,
        )
        directory_info = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(directory_info.st_mode):
            raise RuntimeError("witnessed build-attempt directory is invalid")

        path_info = os.lstat(output_name, dir_fd=directory_descriptor)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or path_info.st_uid != os.geteuid()
            or path_info.st_nlink != 1
            or path_info.st_size != 0
            or stat.S_IMODE(path_info.st_mode) != 0o600
        ):
            raise RuntimeError("witnessed output inode was not safely precreated")

        output_descriptor = os.open(
            output_name,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_descriptor,
        )
        opened_info = os.fstat(output_descriptor)
        if (
            not stat.S_ISREG(opened_info.st_mode)
            or _release_dependency_output_identity(opened_info)
            != _release_dependency_output_identity(path_info)
            or opened_info.st_size != 0
        ):
            raise RuntimeError("witnessed output inode changed while opening")

        payload = _release_dependency_witness_payload(nonce)
        view = memoryview(payload)
        while view:
            written = os.write(output_descriptor, view)
            if written <= 0:
                raise RuntimeError("witnessed output write did not progress")
            view = view[written:]
        os.fsync(output_descriptor)

        final_info = os.fstat(output_descriptor)
        final_path_info = os.lstat(output_name, dir_fd=directory_descriptor)
        if (
            _release_dependency_output_identity(final_info)
            != _release_dependency_output_identity(opened_info)
            or _release_dependency_output_identity(final_path_info)
            != _release_dependency_output_identity(opened_info)
            or final_info.st_size != len(payload)
            or final_path_info.st_size != len(payload)
            or _read_release_dependency_output(output_descriptor, len(payload) + 1)
            != payload
        ):
            raise RuntimeError("witnessed output inode changed while writing")
        return 0
    except BaseException:
        return 1
    finally:
        if output_descriptor >= 0:
            try:
                os.close(output_descriptor)
            except OSError:
                pass
        if directory_descriptor >= 0:
            try:
                os.close(directory_descriptor)
            except OSError:
                pass


if _release_dependency_build_attempt_requested(sys.argv):
    os._exit(_run_release_dependency_build_attempt(sys.argv, dict(os.environ)))

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
sys.path.insert(0, str(ROOT / "tools"))

import checks  # noqa: E402
import jsonc  # noqa: E402
import leakscan  # noqa: E402
import store_js_minifier  # noqa: E402
from store_version import read_pubspec_manifest_version  # noqa: E402

TARGETS = ("chrome", "edge", "firefox", "safari")
SRC = ROOT / "src"
MANIFEST_DIR = ROOT / "manifest"
DIST = ROOT / "dist"
RELEASE_HARDENING_CONTRACT = REPO_ROOT / "tools" / "release_obfuscation_contract.py"
PRIVATE_EXTENSION_RECEIPT_ROOT = (
    REPO_ROOT / ".artifacts" / "private-release-symbols" / "extension"
)
# --release-build-receipts: on a darwin release host this file is the
# producer-attested extension producer (tools/release_dependency_freeze.py
# PLATFORM_BUILD_PRODUCERS_BY_HOST). The store zips are written under the
# repository's build/ directory, which the dependency freeze never selects,
# because extension/dist would add untracked files to the frozen extension root
# between begin-build and finish-build.
RELEASE_DIST = REPO_ROOT / "build" / "extension" / "dist"
RELEASE_RECEIPT_PRODUCER = "extension/build.py"
RELEASE_RECEIPT_TARGETS = {"chrome": "chrome-zip", "edge": "edge-zip", "firefox": "firefox-zip"}
RELEASE_RECEIPT_ROOT = REPO_ROOT / ".artifacts" / "release-build-receipts" / "extension"
# finish-build re-parses each begin receipt path with this character set, so a
# receipt directory such as .artifacts/release-inputs-1.0.16+33/... is refused
# here, before any begin receipt is minted, instead of after the build.
RELEASE_RECEIPT_PATH = re.compile(r"\.artifacts/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}")
DEPENDENCY_FREEZE_PARENT = REPO_ROOT / "tools" / "run_release_dependency_freeze.sh"
DEPENDENCY_FREEZE_AUTHORITY = "winsvpn-release-dependency-freeze-authoritative-v1"
DEPENDENCY_FREEZE_TIMEOUT_SEC = 900
TARGET_IDS = {
    "chrome": "chrome-extension-package",
    "edge": "edge-extension-package",
    "firefox": "firefox-extension-package",
}
BROWSER_BY_TARGET_ID = {target_id: browser for browser, target_id in TARGET_IDS.items()}
SOURCE_ONLY_TARGET_IDS = {"safari": "safari-extension-source"}
VERIFIER_SOURCE_PATHS = (
    "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json",
    "extension/build.py",
    "extension/tools/checks.py",
    "extension/tools/jsonc.py",
    "extension/tools/leakscan.py",
    "extension/tools/store_js_minifier.py",
    "extension/tools/store_version.py",
    "pubspec.yaml",
    "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
    "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
    "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json",
)
NATIVE_HOST_TEMPLATE_PATHS = {
    "chrome": "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
    "edge": "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
    "firefox": "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json",
}
WINDOWS_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]")
FORBIDDEN_PACKAGE_SUFFIXES = frozenset(
    {
        ".a",
        ".dll",
        ".dylib",
        ".exe",
        ".jks",
        ".key",
        ".keystore",
        ".map",
        ".node",
        ".p12",
        ".pem",
        ".pfx",
        ".so",
        ".wasm",
    }
)
MAX_ZIP_MEMBERS = 512
MAX_ZIP_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 8 * 1024 * 1024
MAX_ZIP_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_ZIP_RATIO = 100
MAX_ZIP_PATH_BYTES = 1024
MAX_ZIP_DEPTH = 16
MAX_ZIP_READ_CHUNK = 64 * 1024
UNIX_FIFO_TYPE = 0o010000
UNIX_CHR_TYPE = 0o020000
UNIX_DIR_TYPE = 0o040000
UNIX_BLK_TYPE = 0o060000
UNIX_REG_TYPE = 0o100000
UNIX_SYMLINK_TYPE = 0o120000
UNIX_SOCK_TYPE = 0o140000
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
ZIP_CREATE_SYSTEM = 3
ZIP_CREATE_VERSION = 20
ZIP_EXTRACT_VERSION = 20
ZIP_UNIX_FILE_ATTR = 0o644 << 16
ZIP_COMPRESSLEVEL = 6
ZIP_ENCRYPTED_FLAG = 0x1
ZIP_STRONG_ENCRYPTION_FLAG = 0x40
ZIP_UTF8_FLAG = 0x800
ZIP_UNICODE_PATH_EXTRA = 0x7075
FORBIDDEN_SIGNED_ZIP_PARTS = frozenset({"meta-inf", "_metadata"})


class PackageVerifyError(RuntimeError):
    """Raised when an existing store zip cannot be verified without rebuilding."""


def merge(base: dict, patch: dict) -> dict:
    out = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        elif key == "permissions" and isinstance(value, list) and isinstance(out.get(key), list):
            # Permissions are unioned rather than replaced, so a target fragment
            # adds what only that browser needs without restating the shared
            # list. Chromium needs two permissions to answer the desktop proxy's
            # authentication challenge that Firefox does not need at all; if the
            # fragment replaced the array, the shared list would have to be
            # duplicated three times and would drift.
            out[key] = list(dict.fromkeys(out[key] + value))
        else:
            out[key] = value
    return out


def app_version() -> str:
    try:
        return read_pubspec_manifest_version(ROOT.parent / "pubspec.yaml")
    except (OSError, ValueError) as error:
        raise SystemExit(f"OI-42: {error}") from error


def build_manifest(target: str) -> dict:
    base = jsonc.load_file(MANIFEST_DIR / "base.jsonc")
    patch = jsonc.load_file(MANIFEST_DIR / f"{target}.jsonc")
    m = merge(base, patch)
    m["version"] = app_version()
    # base.jsonc carries background.type so both targets inherit it, but the
    # merged result must not contain the other browser's start mechanism.
    bg = m.get("background", {})
    if target == "firefox":
        bg.pop("service_worker", None)
    elif target == "safari":
        bg.pop("service_worker", None)
        bg.pop("scripts", None)
        bg.pop("type", None)
    else:
        bg.pop("scripts", None)
    if target == "safari":
        # Safari has no WebExtension proxy or privacy.network surface and no
        # auth-provider permission. This unavailable increment also has no site
        # or block-rule feature, so it requests no website-reading permission.
        # Native messaging reaches only the containing app extension.
        excluded = {
            "proxy",
            "privacy",
            "webRequest",
            "webRequestAuthProvider",
            "declarativeNetRequest",
            "activeTab",
        }
        m["permissions"] = [
            permission for permission in m.get("permissions", [])
            if permission not in excluded
        ]
        m.pop("optional_host_permissions", None)
        options = m.get("options_ui")
        if isinstance(options, dict):
            options.pop("open_in_tab", None)
    return m


def stage(target: str) -> Path:
    pkg = DIST / target
    if pkg.exists():
        shutil.rmtree(pkg)
    pkg.mkdir(parents=True)

    # src/ verbatim. __pycache__ and editor droppings are excluded rather than
    # trusted not to exist; this tree lives on a volume that creates AppleDouble
    # `._*` sidecars for almost every file, and one of those inside a package is
    # a load error in Chrome.
    shutil.copytree(
        SRC,
        pkg / "src",
        ignore=shutil.ignore_patterns("._*", ".DS_Store", "__pycache__", "*.pyc", "*.bak_20260807_webrequest"),
    )

    import icons  # noqa: E402  # generated at stage time; verify-only never rebuilds

    icons.write_icons(pkg / "src" / "assets")

    manifest = build_manifest(target)
    (pkg / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    store_js_minifier.minify_package_javascript(pkg, require_intended=True)
    return pkg


def gate(
    pkg: Path,
    target: str,
    verbose: bool,
    *,
    zip_members: frozenset[str] | set[str] | None = None,
    authenticated_host_templates: dict[str, bytes] | None = None,
    require_authenticated_host_templates: bool = False,
) -> bool:
    copy_js = pkg / "src" / "core" / "copy.js"
    problems = checks.run(
        pkg,
        target,
        copy_js,
        zip_members=zip_members,
        authenticated_host_templates=authenticated_host_templates,
        require_authenticated_host_templates=require_authenticated_host_templates,
    )
    findings = leakscan.scan_tree(pkg)

    if not problems and not findings:
        if verbose:
            n = sum(1 for p in pkg.rglob("*") if p.is_file())
            print(f"  gates passed: {n} files, no address, no remote URL, no forbidden permission")
        return True

    for p in problems:
        print(f"  FAIL {p}", file=sys.stderr)
    for f in findings:
        print(f"  FAIL [leak] {f}", file=sys.stderr)
    return False


def resolve_browser(target: str) -> tuple[str, str]:
    if target in SOURCE_ONLY_TARGET_IDS or target in SOURCE_ONLY_TARGET_IDS.values():
        raise PackageVerifyError(
            "Safari is a source-only development target with no owner-approved "
            "App Store identity, so it cannot mint an exact-target verification receipt"
        )
    if target in TARGET_IDS:
        return target, TARGET_IDS[target]
    browser = BROWSER_BY_TARGET_ID.get(target)
    if browser is None:
        raise PackageVerifyError(
            f"unsupported exact extension target: {target!r}; "
            f"expected one of {', '.join((*TARGETS, *TARGET_IDS.values()))}"
        )
    return browser, target


def _absolute_without_follow(path: Path) -> Path:
    path = Path(path)
    if path.is_absolute():
        return path
    return Path.cwd() / path


def _read_regular_bytes(path: Path, label: str) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise PackageVerifyError(f"{label} is missing or not a regular file") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PackageVerifyError(f"{label} is missing or not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino:
            raise PackageVerifyError(f"{label} is missing or not a regular file")
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        payload = b"".join(chunks)
    finally:
        os.close(fd)
    if not payload:
        raise PackageVerifyError(f"{label} is empty")
    return payload


def _verifier_source_relatives() -> tuple[str, ...]:
    relatives = set(VERIFIER_SOURCE_PATHS)
    relatives.add("pubspec.yaml")
    relatives.add("extension/tools/store_version.py")
    for path in store_js_minifier.authored_source_files():
        relatives.add(path.relative_to(ROOT.parent).as_posix())
    for path in sorted(MANIFEST_DIR.glob("*.jsonc")):
        relatives.add(path.relative_to(ROOT.parent).as_posix())
    return tuple(sorted(relatives))

def _read_verifier_source_payloads(repo: Path) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for relative in _verifier_source_relatives():
        path = repo.joinpath(*relative.split("/"))
        payloads[relative] = _read_regular_bytes(path, f"verifier source {relative}")
    return payloads


def _closure_from_payloads(payloads: dict[str, bytes]) -> dict[str, object]:
    inputs: list[dict[str, object]] = []
    for relative in sorted(payloads):
        payload = payloads[relative]
        inputs.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
    encoded = (
        json.dumps(inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")
    return {
        "inputs": inputs,
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def verifier_source_closure(repo: Path) -> dict[str, object]:
    repo = _absolute_without_follow(repo)
    return _closure_from_payloads(_read_verifier_source_payloads(repo))


def _native_host_templates_from_payloads(payloads: dict[str, bytes]) -> dict[str, bytes]:
    templates: dict[str, bytes] = {}
    for browser, relative in NATIVE_HOST_TEMPLATE_PATHS.items():
        payload = payloads.get(relative)
        if not isinstance(payload, (bytes, bytearray)) or not payload:
            raise PackageVerifyError(
                f"authenticated native-host template snapshot missing: {relative}"
            )
        templates[browser] = bytes(payload)
    return templates


def snapshot_extension_artifact(path: Path) -> tuple[bytes, str]:
    """Read one regular artifact into a stable byte snapshot without following links."""
    path = _absolute_without_follow(path)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise PackageVerifyError("extension artifact is missing") from exc
    if stat.S_ISLNK(info.st_mode):
        raise PackageVerifyError("extension artifact must not be a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        raise PackageVerifyError("extension artifact must be one non-empty regular file")
    if info.st_nlink != 1:
        raise PackageVerifyError("extension artifact must not be a hard link")
    if info.st_size <= 0:
        raise PackageVerifyError("extension artifact must be one non-empty regular file")
    if info.st_size > MAX_ZIP_ARCHIVE_BYTES:
        raise PackageVerifyError("zip archive size exceeds the verify-only limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (
            opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
        ):
            raise PackageVerifyError("extension artifact mutated during open")
        if opened.st_size <= 0 or opened.st_size > MAX_ZIP_ARCHIVE_BYTES:
            raise PackageVerifyError("zip archive size exceeds the verify-only limit")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                raise PackageVerifyError("extension artifact mutated during read")
            chunks.append(block)
            remaining -= len(block)
        extra = os.read(fd, 1)
        if extra:
            raise PackageVerifyError("extension artifact mutated during read")
        after = os.fstat(fd)
        if after.st_size != opened.st_size or after.st_ino != opened.st_ino:
            raise PackageVerifyError("extension artifact mutated during read")
    finally:
        os.close(fd)
    payload = b"".join(chunks)
    if len(payload) != opened.st_size:
        raise PackageVerifyError("extension artifact mutated during read")
    return payload, hashlib.sha256(payload).hexdigest()


def _safe_zip_member_path(name: str) -> str:
    if not name or "\x00" in name:
        raise PackageVerifyError("zip member path is empty or contains a NUL")
    if any(ord(character) < 32 for character in name):
        raise PackageVerifyError(f"zip member path contains a control character: {name}")
    if unicodedata.normalize("NFC", name) != name:
        raise PackageVerifyError(f"non-NFC zip member path: {name}")
    if "\\" in name:
        raise PackageVerifyError(f"backslash zip member path: {name}")
    if name.startswith("/") or WINDOWS_DRIVE_ROOT.match(name):
        raise PackageVerifyError(f"unsafe zip member path: {name}")
    trailing_slash = name.endswith("/")
    parts = name[:-1].split("/") if trailing_slash else name.split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise PackageVerifyError(f"ambiguous zip member path: {name}")
    if any(unicodedata.normalize("NFC", part) != part for part in parts):
        raise PackageVerifyError(f"non-NFC zip member path: {name}")
    if len(parts) > MAX_ZIP_DEPTH:
        raise PackageVerifyError(f"zip member path exceeds the depth limit: {name}")
    normalized = "/".join(parts)
    if trailing_slash:
        normalized += "/"
    if len(normalized.encode("utf-8")) > MAX_ZIP_PATH_BYTES:
        raise PackageVerifyError(f"zip member path is too long: {name}")
    return normalized


def _unix_file_type(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0o170000


def _zip_extra_field_types(extra: bytes) -> set[int]:
    types: set[int] = set()
    offset = 0
    extra = extra or b""
    while offset + 4 <= len(extra):
        code = int.from_bytes(extra[offset : offset + 2], "little")
        size = int.from_bytes(extra[offset + 2 : offset + 4], "little")
        offset += 4
        if size < 0 or offset + size > len(extra):
            raise PackageVerifyError("zip extra field is truncated or malformed")
        types.add(code)
        offset += size
    if offset != len(extra):
        raise PackageVerifyError("zip extra field is truncated or malformed")
    return types


def _zip_member_declared_name(info: zipfile.ZipInfo) -> str:
    extra_types = _zip_extra_field_types(info.extra)
    if ZIP_UNICODE_PATH_EXTRA in extra_types:
        raise PackageVerifyError(f"ambiguous zip unicode path extra field: {info.filename}")
    if info.filename != info.orig_filename:
        raise PackageVerifyError(
            f"ambiguous zip member path encoding: {info.orig_filename!r}"
        )
    name = info.orig_filename
    utf8 = bool(info.flag_bits & ZIP_UTF8_FLAG)
    if not utf8 and not name.isascii():
        raise PackageVerifyError(f"non-UTF8 zip member path is ambiguous: {name}")
    return name


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise PackageVerifyError("short write while extracting a zip member")
        view = view[written:]


def extract_existing_zip(payload: bytes, destination: Path) -> frozenset[str]:
    """Extract one in-memory zip snapshot. Pathname reopen is refused."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise PackageVerifyError("zip extraction requires an exact byte snapshot")
    snapshot = bytes(payload)
    if not snapshot or len(snapshot) > MAX_ZIP_ARCHIVE_BYTES:
        raise PackageVerifyError("zip archive size exceeds the verify-only limit")
    destination.mkdir(parents=True, exist_ok=False)
    try:
        zf = zipfile.ZipFile(io.BytesIO(snapshot), "r")
    except zipfile.BadZipFile as exc:
        raise PackageVerifyError(f"not a zip: {exc}") from exc
    with zf:
        if zf.comment:
            raise PackageVerifyError("zip comments are forbidden")
        names = zf.namelist()
        if not names:
            raise PackageVerifyError("zip archive is empty")
        if len(names) > MAX_ZIP_MEMBERS:
            raise PackageVerifyError("zip member count exceeds the verify-only limit")
        seen_names: set[str] = set()
        seen_normalized: dict[str, str] = {}
        seen_folded: dict[str, str] = {}
        files: list[tuple[zipfile.ZipInfo, str]] = []
        claimed_total = 0
        for info in zf.infolist():
            if info.flag_bits & (ZIP_ENCRYPTED_FLAG | ZIP_STRONG_ENCRYPTION_FLAG):
                raise PackageVerifyError(f"encrypted zip member: {info.filename}")
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise PackageVerifyError(
                    f"unsupported zip compression method: {info.filename}"
                )
            name = _zip_member_declared_name(info)
            if name in seen_names:
                raise PackageVerifyError(f"duplicate zip member name: {name}")
            seen_names.add(name)
            normalized = _safe_zip_member_path(name)
            previous = seen_normalized.get(normalized)
            if previous is not None:
                raise PackageVerifyError(
                    f"ambiguous normalized zip member paths: {previous} and {name}"
                )
            folded = normalized.casefold()
            folded_previous = seen_folded.get(folded)
            if folded_previous is not None:
                raise PackageVerifyError(
                    f"Unicode or case-fold zip member collision: {folded_previous} and {name}"
                )
            seen_normalized[normalized] = name
            seen_folded[folded] = name
            file_type = _unix_file_type(info)
            if file_type == UNIX_SYMLINK_TYPE or stat.S_ISLNK(file_type):
                raise PackageVerifyError(f"zip member is a symbolic link: {name}")
            if file_type == UNIX_FIFO_TYPE or stat.S_ISFIFO(file_type):
                raise PackageVerifyError(f"zip member is a FIFO: {name}")
            if (
                file_type in {UNIX_CHR_TYPE, UNIX_BLK_TYPE}
                or stat.S_ISCHR(file_type)
                or stat.S_ISBLK(file_type)
            ):
                raise PackageVerifyError(f"zip member is a device: {name}")
            if file_type == UNIX_SOCK_TYPE or stat.S_ISSOCK(file_type):
                raise PackageVerifyError(f"zip member is a socket: {name}")
            is_directory = bool(info.is_dir() or normalized.endswith("/"))
            if is_directory:
                if info.file_size != 0:
                    raise PackageVerifyError(f"zip directory carries data: {name}")
                if file_type and file_type != UNIX_DIR_TYPE:
                    raise PackageVerifyError(f"zip directory has a non-directory type: {name}")
                continue
            if file_type and file_type != UNIX_REG_TYPE:
                raise PackageVerifyError(f"zip member is not a regular file: {name}")
            path = PurePosixPath(normalized)
            folded_name = path.name.casefold()
            folded_parts = {part.casefold() for part in path.parts}
            if folded_parts & FORBIDDEN_SIGNED_ZIP_PARTS:
                raise PackageVerifyError(
                    f"store-upload zip must not contain {name} "
                    "(already packed or already signed)"
                )
            if (
                path.suffix.casefold() in FORBIDDEN_PACKAGE_SUFFIXES
                or "native_messaging" in folded_parts
                or folded_name.startswith("wins_bridge_host")
            ):
                raise PackageVerifyError(f"secret-bearing or native-host zip member: {name}")
            if info.file_size > MAX_ZIP_MEMBER_BYTES:
                raise PackageVerifyError(f"zip member exceeds the verify-only size limit: {name}")
            claimed_total += info.file_size
            if claimed_total > MAX_ZIP_TOTAL_BYTES:
                raise PackageVerifyError("zip expanded size exceeds the verify-only limit")
            if info.compress_size == 0 and info.file_size:
                raise PackageVerifyError(f"zip member has an invalid compression ratio: {name}")
            if info.compress_size and info.file_size / info.compress_size > MAX_ZIP_RATIO:
                raise PackageVerifyError(f"zip compression ratio exceeds the limit: {name}")
            files.append((info, normalized))
        if "manifest.json" not in seen_normalized:
            raise PackageVerifyError("zip has no manifest.json")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        dest_root = destination.resolve(strict=True)
        actual_total = 0
        extracted: set[str] = set()
        for info, normalized in files:
            current = destination
            for part in PurePosixPath(normalized).parent.parts:
                current /= part
                current.mkdir(exist_ok=True)
                current_info = current.lstat()
                if stat.S_ISLNK(current_info.st_mode) or not stat.S_ISDIR(current_info.st_mode):
                    raise PackageVerifyError(
                        f"zip extraction escaped into a non-directory: {normalized}"
                    )
            try:
                current.resolve(strict=True).relative_to(dest_root)
            except ValueError as exc:
                raise PackageVerifyError(
                    f"zip member escapes the extraction root: {info.filename}"
                ) from exc
            out = destination.joinpath(*normalized.split("/"))
            if out.exists() or out.is_symlink():
                raise PackageVerifyError(f"zip extraction collided on {normalized}")
            descriptor = os.open(out, flags, 0o600)
            crc = 0
            remaining = info.file_size
            try:
                with zf.open(info, "r") as source:
                    while remaining:
                        block = source.read(min(MAX_ZIP_READ_CHUNK, remaining))
                        if not block:
                            raise PackageVerifyError(
                                f"zip member was truncated during extraction: {info.filename}"
                            )
                        if len(block) > remaining:
                            raise PackageVerifyError(
                                f"zip member expanded beyond the verify-only size limit: {info.filename}"
                            )
                        remaining -= len(block)
                        actual_total += len(block)
                        if (
                            len(block) > MAX_ZIP_MEMBER_BYTES
                            or actual_total > MAX_ZIP_TOTAL_BYTES
                        ):
                            raise PackageVerifyError(
                                f"zip member expanded beyond the verify-only size limit: {info.filename}"
                            )
                        crc = zlib.crc32(block, crc)
                        _write_all(descriptor, block)
                    leftover = source.read(1)
                    if leftover:
                        raise PackageVerifyError(
                            f"zip member expanded beyond the verify-only size limit: {info.filename}"
                        )
                os.fsync(descriptor)
            except zipfile.BadZipFile as exc:
                raise PackageVerifyError(f"corrupt zip member: {info.filename}") from exc
            finally:
                os.close(descriptor)
            if remaining != 0:
                raise PackageVerifyError(
                    f"zip member was truncated during extraction: {info.filename}"
                )
            if crc & 0xFFFFFFFF != info.CRC:
                raise PackageVerifyError(f"zip member CRC mismatch: {info.filename}")
            extracted.add(normalized)
        return frozenset(extracted)


def _reject_secret_bearing_source(pkg: Path) -> None:
    for path in sorted(pkg.rglob("*")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise PackageVerifyError(
                f"extracted package contains a symbolic link: {path.relative_to(pkg)}"
            )
        if stat.S_ISDIR(info.st_mode):
            continue
        relative = path.relative_to(pkg).as_posix()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PackageVerifyError(
                f"extracted package contains a hard link or special file: {relative}"
            )
        if path.suffix.casefold() in FORBIDDEN_PACKAGE_SUFFIXES:
            raise PackageVerifyError(f"secret-bearing source: {relative}")
        payload = path.read_bytes()
        if b"-----BEGIN " in payload and b"PRIVATE KEY-----" in payload:
            raise PackageVerifyError(f"secret-bearing source: {relative}")


def _require_filename_target(path: Path, browser: str) -> None:
    stem = path.stem.casefold()
    has_browser = re.search(rf"(?:^|[-_.]){re.escape(browser)}(?:[-_.]|$)", stem)
    has_other = any(
        re.search(rf"(?:^|[-_.]){re.escape(other)}(?:[-_.]|$)", stem)
        for other in set(TARGETS) - {browser}
    )
    if has_browser is None or has_other:
        raise PackageVerifyError(
            f"extension artifact filename does not match exact {browser} target"
        )


def reject_untrusted_store_zip(payload: bytes) -> None:
    """Refuse signed, extra, unminified, or non-producer JavaScript zip bytes."""

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise PackageVerifyError("zip provenance requires an exact byte snapshot")
    snapshot = bytes(payload)
    if not snapshot:
        raise PackageVerifyError("extension artifact is empty")
    try:
        archive = zipfile.ZipFile(io.BytesIO(snapshot), "r")
    except zipfile.BadZipFile as exc:
        raise PackageVerifyError(f"not a zip: {exc}") from exc
    with archive:
        try:
            failures = store_js_minifier.zip_hygiene_failures(archive)
        except store_js_minifier.MinifyError as exc:
            raise PackageVerifyError(str(exc)) from exc
        if failures:
            raise PackageVerifyError("; ".join(failures))
        try:
            store_js_minifier.require_zip_javascript_matches_producer(archive)
            store_js_minifier.require_static_source_members(archive)
        except store_js_minifier.MinifyError as exc:
            raise PackageVerifyError(str(exc)) from exc


def verify_existing_package(
    archive: Path,
    target: str,
    *,
    repo: Path | None = None,
    verbose: bool = False,
) -> dict[str, object]:
    """Rerun producer leak and policy checks on an existing zip.

    This path never stages, never rebuilds, and never reads mutable unpacked
    ``src/`` or ``dist/<target>/`` trees. The only package bytes inspected are
    one exact archive snapshot after fail-closed extraction. The reported hash
    is bound to those snapshot bytes, not to a later pathname reopen.
    """

    browser, target_id = resolve_browser(target)
    archive = _absolute_without_follow(archive)
    payload, digest = snapshot_extension_artifact(archive)
    if archive.suffix.lower() not in {".zip", ".xpi"}:
        raise PackageVerifyError("extension artifact must be a .zip or .xpi file")
    _require_filename_target(archive, browser)
    repo = _absolute_without_follow(repo or REPO_ROOT)
    source_payloads = _read_verifier_source_payloads(repo)
    closure = _closure_from_payloads(source_payloads)
    host_templates = _native_host_templates_from_payloads(source_payloads)
    stdout = io.StringIO()
    stderr = io.StringIO()
    redirect_out = contextlib.nullcontext() if verbose else contextlib.redirect_stdout(stdout)
    redirect_err = contextlib.nullcontext() if verbose else contextlib.redirect_stderr(stderr)
    with redirect_out, redirect_err:
        leak_ok = leakscan.selftest(verbose=verbose)
        copy_ok = checks.selftest()
    if not leak_ok:
        raise PackageVerifyError("leakscan self-test failed")
    if not copy_ok:
        raise PackageVerifyError("copy-honesty self-test failed")
    with tempfile.TemporaryDirectory(prefix="winsvpn-extension-verify-") as tmp:
        extracted = Path(tmp) / "package"
        zip_members = extract_existing_zip(payload, extracted)
        _reject_secret_bearing_source(extracted)
        try:
            reject_untrusted_store_zip(payload)
        except store_js_minifier.MinifyError as exc:
            raise PackageVerifyError(str(exc)) from exc
        if not gate(
            extracted,
            browser,
            verbose=verbose,
            zip_members=zip_members,
            authenticated_host_templates=host_templates,
            require_authenticated_host_templates=True,
        ):
            raise PackageVerifyError(
                f"{target_id} leak or policy checks failed against the exact zip"
            )
    return {
        "ok": True,
        "target_id": target_id,
        "browser": browser,
        "artifact": archive.as_posix(),
        "sha256": digest,
        "bytes": len(payload),
        "verifier_source_closure": closure,
        "rebuilt": False,
        "trusted_loose_source": False,
    }


def _deterministic_zip_info(member: str) -> zipfile.ZipInfo:
    posix = PurePosixPath(member).as_posix()
    if not posix or "\\" in posix or posix != member or posix.startswith("/"):
        raise RuntimeError(f"zip member path is not a contained POSIX name: {member}")
    info = zipfile.ZipInfo(posix, date_time=ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = ZIP_CREATE_SYSTEM
    info.create_version = ZIP_CREATE_VERSION
    info.extract_version = ZIP_EXTRACT_VERSION
    info.external_attr = ZIP_UNIX_FILE_ATTR
    info.extra = b""
    info.comment = b""
    info.flag_bits = 0
    return info


def _write_unsigned_firefox_xpi(zip_path: Path) -> Path:
    """Write a distinct-inode unsigned XPI copy of the Firefox ZIP.

    AMO accepts .xpi; the listing identity names both files. A hardlink would
    make one inode look like two archives and is refused by receipt custody.
    """

    xpi = zip_path.with_suffix(".xpi")
    if xpi.exists() or xpi.is_symlink():
        xpi.unlink()
    payload = zip_path.read_bytes()
    xpi.write_bytes(payload)
    zip_info = zip_path.lstat()
    xpi_info = xpi.lstat()
    if zip_info.st_dev == xpi_info.st_dev and zip_info.st_ino == xpi_info.st_ino:
        xpi.unlink()
        raise RuntimeError("Firefox XPI must not share the ZIP inode")
    if xpi_info.st_nlink != 1 or xpi.read_bytes() != payload:
        raise RuntimeError("Firefox XPI must be a distinct unsigned copy of the ZIP")
    return xpi


def zip_package(pkg: Path, target: str) -> Path:
    DIST.mkdir(parents=True, exist_ok=True)
    product = "proxy" if target == "safari" else "companion"
    out = DIST / f"wins-vpn-{product}-{target}.zip"
    if out.exists() or out.is_symlink():
        out.unlink()
    with zipfile.ZipFile(
        out,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=ZIP_COMPRESSLEVEL,
        allowZip64=False,
    ) as zf:
        zf.comment = b""
        for path in sorted(pkg.rglob("*")):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                continue
            member = path.relative_to(pkg).as_posix()
            zf.writestr(_deterministic_zip_info(member), path.read_bytes())
    if target == "firefox":
        _write_unsigned_firefox_xpi(out)
    return out


def release_hardening_receipt_dir(browser: str) -> Path:
    """Exact receipt directory that tools/release_obfuscation_contract.py binds.

    The cross-store hardening gate (`release_obfuscation_contract.py --verify
    <target-id> <zip>`) refuses unless this directory holds the exact-target
    receipt; the contract's own layout check rejects any other directory.
    """
    match = re.search(
        r"(?m)^version:\s*([^+\s]+)\+(\d+)\s*$",
        (REPO_ROOT / "pubspec.yaml").read_text(encoding="utf-8"),
    )
    if match is None:
        raise RuntimeError("pubspec.yaml must contain version: <semver>+<integer>")
    return PRIVATE_EXTENSION_RECEIPT_ROOT / browser / f"{match.group(1)}+{match.group(2)}"


def record_release_hardening_receipts(outputs: dict[str, Path]) -> None:
    """Write the receipt the cross-store hardening gate verifies, per store zip.

    The Android, Apple, Linux and Windows producers record their own receipts;
    without this step the extension gate pair can never pass. The record step
    reruns the exact-target minification and authenticated secret-inventory
    scan, so it needs WINS_RELEASE_SECRET_INVENTORY. Safari has no store zip
    and no receipt.
    """
    for browser, artifact in outputs.items():
        target_id = TARGET_IDS.get(browser)
        if target_id is None:
            continue
        receipt_dir = release_hardening_receipt_dir(browser)
        receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        record = subprocess.run(
            [
                sys.executable,
                str(RELEASE_HARDENING_CONTRACT),
                "record",
                "--platform",
                browser,
                "--symbols-dir",
                str(receipt_dir),
                "--manifest",
                str(receipt_dir / "manifest.json"),
                "--artifact",
                artifact.relative_to(REPO_ROOT).as_posix(),
                "--target-id",
                target_id,
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        sys.stdout.write(record.stdout or "")
        if record.returncode != 0:
            sys.stderr.write(record.stderr or "")
            raise RuntimeError(f"the {target_id} release hardening receipt was refused")


def require_distinct_chromium_packages(outputs: dict[str, Path]) -> None:
    if not {"chrome", "edge"}.issubset(outputs):
        return
    chrome_hash = hashlib.sha256(outputs["chrome"].read_bytes()).digest()
    edge_hash = hashlib.sha256(outputs["edge"].read_bytes()).digest()
    if chrome_hash == edge_hash:
        raise RuntimeError(
            "Chrome and Edge packages are byte-identical; exact store target "
            "identity is missing or the wrong archive was copied"
        )


class ReleaseReceiptError(RuntimeError):
    """A dependency-freeze build receipt step was refused."""


def release_artifacts_path(value: str, label: str, *, must_exist: bool) -> Path:
    """Return a lexical repository .artifacts path, refusing symlinks and reuse."""

    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ReleaseReceiptError(f"{label} must stay inside the repository") from exc
    if len(relative.parts) < 2 or relative.parts[0] != ".artifacts":
        raise ReleaseReceiptError(f"{label} must stay under repository .artifacts/")
    if not must_exist and not RELEASE_RECEIPT_PATH.fullmatch(relative.as_posix()):
        raise ReleaseReceiptError(
            f"{label} may use only letters, digits, '.', '_', '-' and '/' "
            "(the dependency freeze refuses other receipt paths at finish-build)"
        )
    if must_exist:
        try:
            info = candidate.lstat()
        except FileNotFoundError as exc:
            raise ReleaseReceiptError(f"{label} does not exist: {candidate}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ReleaseReceiptError(f"{label} must be a regular non-symlink file")
    elif candidate.exists() or candidate.is_symlink():
        raise ReleaseReceiptError(f"{label} must be a new path: {candidate}")
    return candidate


def run_dependency_freeze(command: str, *arguments: str) -> dict[str, object]:
    """Run one command through the reviewed parent, as the macOS Android producer does.

    tools/run_release_dependency_freeze.sh refuses an interpreter whose bytes
    differ from tools/toolchain-pins.json and hands the worker the controller
    on a retained descriptor; this only checks the authenticated envelope.
    """

    try:
        completed = subprocess.run(
            [
                "/bin/bash",
                str(DEPENDENCY_FREEZE_PARENT),
                command,
                "--repo",
                str(REPO_ROOT),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"HOME": "/private/tmp", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout=DEPENDENCY_FREEZE_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseReceiptError(f"dependency freeze {command} did not run: {exc}") from exc
    if completed.returncode != 0:
        detail = " ".join(completed.stderr.decode("utf-8", "replace").split())
        raise ReleaseReceiptError(
            f"dependency freeze {command} refused: {detail[:400] or 'no diagnostic'}"
        )
    try:
        result = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReleaseReceiptError(f"dependency freeze {command} output is not JSON") from exc
    if (
        type(result) is not dict
        or result.get("authority_kind") != DEPENDENCY_FREEZE_AUTHORITY
        or result.get("command") != command
        or result.get("production_authority_authenticated") is not True
        or result.get("publication_authorized") is not False
    ):
        raise ReleaseReceiptError(
            f"dependency freeze {command} result lacks its authority envelope"
        )
    return result


def release_toolchain() -> tuple[str, str, str]:
    """The pinned esbuild that transforms every shipped JavaScript member."""

    pin = store_js_minifier.pin_for_host()
    return (
        store_js_minifier.TOOL_NAME,
        store_js_minifier.TOOL_VERSION,
        str(pin["binary_sha256"]),
    )


def begin_release_receipts(index: Path, receipt_dir: Path) -> dict[str, Path]:
    """verify-index, then one single-use begin receipt per store zip, before staging."""

    run_dependency_freeze("verify-index", "--index", str(index), "--platform", "extension")
    receipt_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt_dir.mkdir(mode=0o700)
    begins: dict[str, Path] = {}
    for browser in RELEASE_RECEIPT_TARGETS:
        begin = receipt_dir / f"EXTENSION_{browser.upper()}_BUILD_BEGIN.json"
        run_dependency_freeze(
            "begin-build", "--index", str(index), "--platform", "extension",
            "--output", str(begin),
        )
        begins[browser] = begin
    return begins


def verify_release_receipt(index: Path, receipt: Path, artifact: Path) -> dict[str, object]:
    """verify-receipt through tools/release_freeze_client.py, the reviewed client."""

    tools = str(REPO_ROOT / "tools")
    if tools not in sys.path:
        sys.path.append(tools)
    import release_freeze_client  # noqa: E402  # release receipts only

    return release_freeze_client.verify_build_receipt(
        REPO_ROOT, index, "extension", receipt, artifact
    )


def finish_release_receipts(
    index: Path, receipt_dir: Path, begins: dict[str, Path], outputs: dict[str, Path]
) -> dict[str, Path]:
    """Attest each exact store zip against its begin receipt, then verify it."""

    name, version, revision = release_toolchain()
    receipts: dict[str, Path] = {}
    for browser, target in RELEASE_RECEIPT_TARGETS.items():
        artifact = outputs[browser]
        receipt = receipt_dir / f"EXTENSION_{browser.upper()}_BUILD_RECEIPT.json"
        run_dependency_freeze(
            "finish-build", "--index", str(index), "--platform", "extension",
            "--begin", str(begins[browser]), "--artifact", str(artifact),
            "--producer", RELEASE_RECEIPT_PRODUCER,
            "--toolchain-name", name, "--toolchain-version", version,
            "--toolchain-revision", revision,
            "--target", target, "--output", str(receipt),
        )
        try:
            verified = verify_release_receipt(index, receipt, artifact)
        except Exception as exc:  # the client raises its own DependencyFreezeError
            raise ReleaseReceiptError(
                f"the {target} build receipt did not verify: {exc}"
            ) from exc
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if verified.get("artifact_sha256") != digest:
            raise ReleaseReceiptError(f"the {target} build receipt binds other bytes")
        receipts[browser] = receipt
    return receipts


def main() -> int:
    global DIST
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("targets", nargs="*", default=None, help=f"any of: {', '.join(TARGETS)}")
    ap.add_argument("--no-zip", action="store_true", help="leave the unpacked package only")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument(
        "--verify",
        nargs=2,
        metavar=("TARGET", "ZIP"),
        help="rerun leak and policy checks on an existing zip without rebuilding",
    )
    ap.add_argument(
        "--release-hardening-receipts",
        action="store_true",
        help="after packaging, record each store zip's exact-target hardening "
        "receipt for the cross-store gate (needs WINS_RELEASE_SECRET_INVENTORY)",
    )
    ap.add_argument(
        "--release-build-receipts",
        metavar="RELEASE_INPUT_INDEX",
        help="darwin release producer: begin-build before staging, build the "
        "chrome, edge and firefox store zips under build/extension/dist, record "
        "their hardening receipts, then finish-build and verify-receipt each zip "
        "(run as python3 -I -B; implies --release-hardening-receipts)",
    )
    ap.add_argument(
        "--receipt-dir",
        help="new .artifacts directory for the build receipts (default: "
        ".artifacts/release-build-receipts/extension/<UTC>-<pid>)",
    )
    args = ap.parse_args()

    if args.release_hardening_receipts and (args.verify is not None or args.no_zip):
        print("build: --release-hardening-receipts records only freshly built "
              "store zips; it cannot combine with --verify or --no-zip",
              file=sys.stderr)
        return 2

    release_index: Path | None = None
    receipt_dir: Path | None = None
    if args.receipt_dir is not None and args.release_build_receipts is None:
        print("build: --receipt-dir needs --release-build-receipts", file=sys.stderr)
        return 2
    if args.release_build_receipts is not None:
        if args.verify is not None or args.no_zip:
            print("build: --release-build-receipts builds fresh store zips; it "
                  "cannot combine with --verify or --no-zip", file=sys.stderr)
            return 2
        if args.targets and sorted(args.targets) != sorted(RELEASE_RECEIPT_TARGETS):
            print("build: --release-build-receipts builds exactly chrome, edge "
                  "and firefox", file=sys.stderr)
            return 2
        if not (sys.flags.isolated and sys.flags.dont_write_bytecode):
            print("build: --release-build-receipts must run as python3 -I -B so "
                  "no bytecode lands in the frozen extension inputs", file=sys.stderr)
            return 2
        try:
            release_index = release_artifacts_path(
                args.release_build_receipts, "release input index", must_exist=True
            )
            default_dir = RELEASE_RECEIPT_ROOT / (
                time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{os.getpid()}"
            )
            receipt_dir = release_artifacts_path(
                args.receipt_dir or str(default_dir),
                "build receipt directory",
                must_exist=False,
            )
        except ReleaseReceiptError as error:
            print(f"build: REFUSING - {error}", file=sys.stderr)
            return 2
        stale = [
            RELEASE_DIST / name
            for name in (
                "wins-vpn-companion-chrome.zip",
                "wins-vpn-companion-edge.zip",
                "wins-vpn-companion-firefox.zip",
                "wins-vpn-companion-firefox.xpi",
            )
            if (RELEASE_DIST / name).exists() or (RELEASE_DIST / name).is_symlink()
        ]
        if stale:
            print(f"build: REFUSING - a leftover release store zip exists: {stale[0]}",
                  file=sys.stderr)
            return 2
        DIST = RELEASE_DIST
        # Child Python gates run without -I; keep their bytecode out of the
        # frozen extension root as well.
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        args.targets = list(RELEASE_RECEIPT_TARGETS)
        args.release_hardening_receipts = True

    if args.verify is not None:
        if args.targets:
            print("build: --verify does not take build targets", file=sys.stderr)
            return 2
        if args.no_zip:
            print("build: --verify cannot rebuild or restage an unpacked tree", file=sys.stderr)
            return 2
        target, archive = args.verify
        try:
            result = verify_existing_package(
                Path(archive),
                target,
                verbose=not args.quiet,
            )
        except (OSError, PackageVerifyError) as exc:
            print(f"build: VERIFY FAIL: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0

    targets = args.targets or list(TARGETS)
    for t in targets:
        if t not in TARGETS:
            print(f"build: unknown target {t!r}; expected one of {', '.join(TARGETS)}", file=sys.stderr)
            return 2

    import dev_bridge  # noqa: E402  # compiled-host contract is a build gate only

    print("gate 1/4: leakscan self-test")
    if not leakscan.selftest(verbose=not args.quiet):
        print("build: REFUSING: the address scanner failed its own self-test", file=sys.stderr)
        return 3

    print("gate 2/4: copy-honesty self-test")
    if not checks.selftest():
        print("build: REFUSING: the copy checker failed its own self-test", file=sys.stderr)
        return 3

    print("gate 3/4: the bridge contract, against both implementations")
    # The compiled host is REQUIRED here. tools/native_messaging/ is tracked, so
    # a fresh clone has the Dart source; find_real_host resolves the package
    # (dart pub get, offline first) and compiles the real host itself. A package
    # produced without the real-host cross-check is not a package this project
    # ships, so any genuine failure to produce the host REFUSES the build
    # instead of printing a NOTE and passing on the fixture half alone: the
    # 2026-08-07 nesting defect survived in exactly that quiet pass.
    try:
        real_host = dev_bridge.find_real_host(require=True)
    except dev_bridge.RealHostUnavailable as error:
        print(f"build: REFUSING: gate 3 could not produce the real compiled "
              f"host: {error}", file=sys.stderr)
        return 3
    if dev_bridge.contract_check(real_host) != 0:
        print("build: REFUSING: the stand-in bridge and the real host disagree "
              "about the wire contract", file=sys.stderr)
        return 3

    print("gate 4/4: native-messaging manifests name the store-listing extension ids")
    # Each requested target is bound to its own stable native-host identity.
    # Chrome and Edge: exact, distinct, non-placeholder template origins that
    # agree with the checked-in store record. Firefox: the Gecko id, the
    # manifest fragment and the host template agree. Safari: native messaging
    # reaches its own containing app, so no external host template applies.
    # None of these depends on an expiring owner receipt; installed-host
    # registration keeps its separate checks in tools/native_messaging/.
    identity_checks: list[tuple[str, list[str]]] = []
    if any(target in {"chrome", "edge"} for target in targets):
        identity_checks.append((
            "Chrome/Edge",
            [sys.executable, str(ROOT / "tools" / "assert_chrome_zip.py"), "--native-identities"],
        ))
    if "firefox" in targets:
        identity_checks.append((
            "Firefox",
            [sys.executable, str(ROOT / "tools" / "assert_firefox_zip.py"), "--check-host-identity"],
        ))
    if "safari" in targets:
        print("  safari: native messaging reaches its containing app; "
              "external host manifests do not apply")
    for label, identity_check in identity_checks:
        nm_check = subprocess.run(identity_check, capture_output=True, text=True)
        sys.stdout.write(nm_check.stdout or "")
        if nm_check.returncode != 0:
            sys.stderr.write(nm_check.stderr or "")
            print(f"build: REFUSING: the {label} native-host identity is a "
                  "placeholder, ambiguous, or disagrees with its recorded "
                  "store identity", file=sys.stderr)
            return 3

    begins: dict[str, Path] = {}
    if release_index is not None and receipt_dir is not None:
        print("\nbeginning dependency-freeze build receipts")
        try:
            begins = begin_release_receipts(release_index, receipt_dir)
        except (OSError, ReleaseReceiptError) as error:
            print(f"build: REFUSING - {error}", file=sys.stderr)
            return 3
        print(f"  begin receipts: {receipt_dir}")

    ok = True
    outputs: dict[str, Path] = {}
    for target in targets:
        print(f"\nbuilding {target}")
        try:
            pkg = stage(target)
        except store_js_minifier.MinifyError as error:
            print(f"build: {target} REFUSED - {error}", file=sys.stderr)
            ok = False
            continue
        if not gate(pkg, target, verbose=not args.quiet):
            print(f"build: {target} REFUSED", file=sys.stderr)
            shutil.rmtree(pkg)
            ok = False
            continue
        if args.no_zip:
            print(f"  unpacked: {pkg}")
        else:
            out = zip_package(pkg, target)
            outputs[target] = out
            print(f"  unpacked: {pkg}")
            print(f"  package:  {out} ({out.stat().st_size} bytes)")
            if target == "firefox":
                xpi = out.with_suffix(".xpi")
                print(f"  package:  {xpi} ({xpi.stat().st_size} bytes)")

    try:
        require_distinct_chromium_packages(outputs)
    except RuntimeError as error:
        print(f"build: REFUSING - {error}", file=sys.stderr)
        ok = False

    if ok and args.release_hardening_receipts:
        print("\nrecording release hardening receipts")
        try:
            record_release_hardening_receipts(outputs)
        except (OSError, RuntimeError) as error:
            print(f"build: REFUSING - {error}", file=sys.stderr)
            ok = False

    if ok and begins and release_index is not None and receipt_dir is not None:
        print("\nverifying the exact store zips and finishing build receipts")
        try:
            for browser in RELEASE_RECEIPT_TARGETS:
                verify_existing_package(outputs[browser], browser)
            receipts = finish_release_receipts(release_index, receipt_dir, begins, outputs)
        except (OSError, PackageVerifyError, ReleaseReceiptError) as error:
            print(f"build: REFUSING - {error}", file=sys.stderr)
            ok = False
        else:
            for browser, receipt in receipts.items():
                artifact = outputs[browser]
                digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
                print(f"  {RELEASE_RECEIPT_TARGETS[browser]}: {artifact} sha256={digest}")
                print(f"    receipt: {receipt} (verified)")

    print("\nbuild:", "ok" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
