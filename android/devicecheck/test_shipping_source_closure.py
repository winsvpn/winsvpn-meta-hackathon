#!/usr/bin/env python3
"""Fail-closed source-custody checks for the disabled DeviceCheck producer.

The workspace producer must not copy or compile ambient source until the
external owner controller can provide authenticated immutable compiler inputs.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import stat
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "android/devicecheck/build_devicecheck.sh"
SOURCE_CUSTODY = ROOT / "android/devicecheck/devicecheck_source_custody.py"
SOURCE_CUSTODY_TEST = ROOT / "android/devicecheck/test_devicecheck_source_custody.py"
MAX_SOURCE_BYTES = 512 * 1024

FROZEN_SOURCE_CUSTODY_SHA256 = (
    "5e3c6b8c061b60f3b8619b3a50396f42427b434536921a6d3a66c8cfd8610fa1"
)
FROZEN_SOURCE_CUSTODY_TEST_SHA256 = (
    "e3e667075a3c4cb46befe9df86d1741ce95c482a453f4ed1c0eb6953e763e881"
)

DISABLED_MARKER = "# DEVICECHECK_PRODUCER_DISABLED=immutable-compiler-input-v1"
FINAL_BLOCKER = (
    'echo "OWNER-BLOCKED: immutable compiler-input handoff is not implemented '
    'by the external controller/loader." >&2'
)
FORBIDDEN_ACTIVE_COMMAND_RE = re.compile(
    r"(?mx)^[ \t]*(?!\#)"
    r"(?:command\s+|exec\s+|env(?:\s+-[A-Za-z]+)*\s+)?"
    r"(?:[^\s;|&]+/)?"
    r"(?:cp|ditto|find|git|go|gradle|gradlew|adb|sdkmanager|avdmanager|"
    r"ndk-build|cmake|ninja|make|clang|clang\+\+|gcc|g\+\+|ld|ar|"
    r"jar|zip|tar|rsync|install|ln|link|python(?:3(?:\.\d+)?)?|"
    r"kotlinc|javac|xcodebuild|codesign)"
    r"(?:\s|$)"
)
FORBIDDEN_SUCCESS_RE = re.compile(
    r"(?m)^[ \t]*(?!\#)(?:exit|return)\s+0(?:\s|$)"
)
FORBIDDEN_SHELL_ESCAPE_RE = re.compile(
    r"(?m)^[ \t]*(?!\#)(?:eval\b|source\b|\.\s+|(?:bash|sh|zsh)\s+-c\b)"
)
FORBIDDEN_COPY_BODY_RE = re.compile(
    r"(?m)^[ \t]*(?!\#)(?:FILES\s*=\s*\(|"
    r"for\s+name\s+in\s+\"\$\{FILES\[@\]\}\")"
)
FORBIDDEN_RECEIPT_RECORD_RE = re.compile(
    r"(?m)^[ \t]*(?!\#).*?/dev/fd/16\s+record(?:\s|$)"
)
FORBIDDEN_ARTIFACT_HASH_SUBSTITUTION_RE = re.compile(
    r"(?mi)^[ \t]*(?!\#)"
    r"[A-Z0-9_]*(?:APK|ARTIFACT)[A-Z0-9_]*SHA256[ \t]*=[ \t]*"
    r"[\"']?\$\{?[A-Z0-9_]*(?:SOURCE|CLOSURE|MANIFEST)"
    r"[A-Z0-9_]*SHA256\}?[\"']?"
)
INERT_PATH_VARIABLES = ("SRC", "DST", "JNI", "GO_MODULE", "ADB_SERIAL")

EXACT_CONTRACT_DECLARATIONS = (
    'SOURCE_AUTHORITY_ROOT="/Library/WinsVPN/ReleaseAndroidSource/devicecheck-v3"',
    'SOURCE_SNAPSHOT_BASE="${SOURCE_AUTHORITY_ROOT}/snapshots/sha256"',
    'SOURCE_MANIFEST_BASE="${SOURCE_AUTHORITY_ROOT}/manifests/sha256"',
    'RELEASE_LOADER="${SOURCE_AUTHORITY_ROOT}/loader.py"',
    'RELEASE_CONTROLLER="${SOURCE_AUTHORITY_ROOT}/controller.py"',
    'OWNER_AUTHORITY="${SOURCE_AUTHORITY_ROOT}.authority.json"',
    'BUILD_WORKSPACE_ROOT="/private/var/winsvpn-devicecheck-build"',
    'BUILD_CACHE_ROOT="/private/var/winsvpn-devicecheck-cache"',
    'SOURCE_CUSTODY_CONTRACT="winsvpn-devicecheck-source-custody-v2"',
    'OWNER_AUTHORITY_CONTRACT="winsvpn-devicecheck-owner-authority-v4"',
    'BUILD_HANDOFF_CONTRACT="winsvpn-devicecheck-private-build-handoff-v1"',
    'ATOMIC_PUBLICATION_CONTRACT="winsvpn-devicecheck-content-addressed-publication-v1"',
    'SOURCE_CONSUMER_STATUS="unintegrated"',
)


def _active_lines(source: str) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def validate_disabled_producer(build_script: str) -> None:
    """Reject any workspace build path while immutable inputs are unavailable."""
    if build_script.count(DISABLED_MARKER) != 1:
        raise AssertionError(
            "DeviceCheck disabled-producer marker is missing or ambiguous"
        )
    if build_script.count(FINAL_BLOCKER) != 1:
        raise AssertionError(
            "DeviceCheck immutable-input owner blocker is missing or ambiguous"
        )

    active = _active_lines(build_script)
    if not active or active[-1] != "exit 1":
        raise AssertionError("DeviceCheck producer does not end fail closed with exit 1")
    if FORBIDDEN_SUCCESS_RE.search(build_script):
        raise AssertionError("DeviceCheck producer contains an active success exit")
    if FORBIDDEN_SHELL_ESCAPE_RE.search(build_script):
        raise AssertionError("DeviceCheck producer contains an ambient shell escape")
    if FORBIDDEN_COPY_BODY_RE.search(build_script):
        raise AssertionError("DeviceCheck producer contains a legacy ambient copy body")
    if FORBIDDEN_ACTIVE_COMMAND_RE.search(build_script):
        raise AssertionError("DeviceCheck producer contains an active compiler or copy command")
    if FORBIDDEN_RECEIPT_RECORD_RE.search(build_script):
        raise AssertionError("DeviceCheck producer can record a successful build receipt")
    if FORBIDDEN_ARTIFACT_HASH_SUBSTITUTION_RE.search(build_script):
        raise AssertionError(
            "DeviceCheck producer substitutes a source hash for built APK custody"
        )
    if "devicecheck-v2" in build_script:
        raise AssertionError("DeviceCheck producer contains a stale v2 authority path")
    if "sudo" in build_script:
        raise AssertionError("DeviceCheck producer contains a rejected sudo helper")

    for declaration in EXACT_CONTRACT_DECLARATIONS:
        if build_script.count(declaration) != 1:
            raise AssertionError(
                "DeviceCheck v3 source/authority/private-workspace declaration "
                f"is missing or ambiguous: {declaration}"
            )

    for variable in INERT_PATH_VARIABLES:
        if len(re.findall(rf"(?m)^{variable}=", build_script)) != 1:
            raise AssertionError(f"DeviceCheck {variable} declaration is missing or ambiguous")
        if re.search(rf"\$\{{{variable}\}}", build_script):
            raise AssertionError(
                f"DeviceCheck disabled producer actively consumes ambient {variable}"
            )

    required_fragments = (
        '"$(stat -f \'%l\' "${BASH_SOURCE[0]}")" != "1"',
        "DeviceCheck producer script must be a one-link regular file.",
        'if [[ "$(id -u)" == "0" ]]; then',
        '[[ -L "${PROJECT_ROOT}"',
        '/private/var/winsvpn-devicecheck-build/*)',
        'require_held_path_fd 9 "transaction ticket"',
        'require_held_path_fd 10 "ReleasePython"',
        'require_held_path_fd 11 "release loader"',
        'require_held_path_fd 12 "release controller"',
        'require_held_path_fd 14 "owner authority"',
        'require_held_path_fd 15 "owner signer certificate"',
        'require_held_path_fd 16 "authority-bound receipt tool"',
        '"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate',
        'exec "${RELEASE_PYTHON}" -I -S /dev/fd/16 selftest',
    )
    for fragment in required_fragments:
        if build_script.count(fragment) != 1:
            raise AssertionError(
                f"DeviceCheck fail-closed custody fragment is missing or ambiguous: {fragment}"
            )


class DeviceCheckDisabledProducerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw, cls.digest = read_authenticated_bytes(BUILD_SCRIPT)
        cls.build_script = _decode_source(str(BUILD_SCRIPT), cls.raw)
        validate_disabled_producer(cls.build_script)

    def test_authenticated_script_snapshot_is_stable_and_bounded(self) -> None:
        repeated_raw, repeated_digest = read_authenticated_bytes(BUILD_SCRIPT)
        self.assertEqual(repeated_raw, self.raw)
        self.assertEqual(repeated_digest, self.digest)
        self.assertRegex(self.digest, r"^[0-9a-f]{64}$")
        self.assertLessEqual(len(self.raw), MAX_SOURCE_BYTES)

    def test_frozen_source_custody_dependencies_match_two_reviewed_hashes(self) -> None:
        for path, expected in (
            (SOURCE_CUSTODY, FROZEN_SOURCE_CUSTODY_SHA256),
            (SOURCE_CUSTODY_TEST, FROZEN_SOURCE_CUSTODY_TEST_SHA256),
        ):
            with self.subTest(path=path):
                first_raw, first_digest = read_authenticated_bytes(path)
                second_raw, second_digest = read_authenticated_bytes(path)
                self.assertEqual(first_raw, second_raw)
                self.assertEqual(first_digest, second_digest)
                self.assertEqual(first_digest, expected)

    def test_disabled_workspace_producer_has_no_ambient_build_body(self) -> None:
        validate_disabled_producer(self.build_script)
        self.assertNotIn("FILES=(", self.build_script)
        self.assertNotIn('for name in "${FILES[@]}"', self.build_script)

    def test_hardlinked_or_symlinked_script_is_rejected_before_open(self) -> None:
        hardlinked = types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o444,
            st_nlink=2,
        )
        original_lstat = os.lstat

        def hostile_lstat(path: object, *args: object, **kwargs: object) -> object:
            if os.fspath(path) == os.fspath(BUILD_SCRIPT.absolute()):
                return hardlinked
            return original_lstat(path, *args, **kwargs)

        with mock.patch.object(os, "lstat", side_effect=hostile_lstat):
            with self.assertRaisesRegex(AssertionError, "one-link"):
                read_authenticated_bytes(BUILD_SCRIPT)

        symlinked = types.SimpleNamespace(
            st_mode=stat.S_IFLNK | 0o777,
            st_nlink=1,
        )

        def hostile_symlink(path: object, *args: object, **kwargs: object) -> object:
            if os.fspath(path) == os.fspath(BUILD_SCRIPT.absolute()):
                return symlinked
            return original_lstat(path, *args, **kwargs)

        with mock.patch.object(os, "lstat", side_effect=hostile_symlink):
            with self.assertRaisesRegex(AssertionError, "one-link"):
                read_authenticated_bytes(BUILD_SCRIPT)

    def test_hostile_removed_marker_or_blocker_is_rejected(self) -> None:
        for fragment in (
            DISABLED_MARKER,
            FINAL_BLOCKER,
            '"$(stat -f \'%l\' "${BASH_SOURCE[0]}")" != "1"',
        ):
            with self.subTest(fragment=fragment):
                hostile = self.build_script.replace(fragment, "", 1)
                with self.assertRaisesRegex(
                    AssertionError,
                    "marker|blocker|custody fragment",
                ):
                    validate_disabled_producer(hostile)

    def test_hostile_ambient_source_copy_and_generated_input_discovery_are_rejected(self) -> None:
        hostile_lines = (
            'cp "${SRC}/WinnV3Bridge.kt" "${DST}/WinnV3Bridge.kt"',
            'rsync -a "${SRC}/" "${DST}/"',
            'find "${PROJECT_ROOT}" -name "*.kt"',
            'git ls-files android/devicecheck',
            'git ls-files --others --ignored --exclude-standard',
            'ln "${SRC}/WinnV3Bridge.kt" "${DST}/WinnV3Bridge.kt"',
            'tar -cf staged-sources.tar android/devicecheck',
            'zip -r staged-sources.zip android/devicecheck',
            'FILES=(WinnV3Bridge.kt)',
        )
        for hostile_line in hostile_lines:
            with self.subTest(hostile_line=hostile_line):
                hostile = self.build_script + "\n" + hostile_line + "\nexit 1\n"
                with self.assertRaisesRegex(
                    AssertionError,
                    "copy|compiler|ambient",
                ):
                    validate_disabled_producer(hostile)

    def test_hostile_gradle_go_sdk_ndk_or_adb_execution_is_rejected(self) -> None:
        hostile_lines = (
            './gradlew :app:assembleRelease',
            'go build ./winn3',
            'adb install app.apk',
            'sdkmanager --list',
            'ndk-build NDK_PROJECT_PATH=.',
            'cmake --build build',
            'python3 tools/ambient_devicecheck_builder.py',
            'kotlinc WinnV3Bridge.kt',
        )
        for hostile_line in hostile_lines:
            with self.subTest(hostile_line=hostile_line):
                hostile = self.build_script + "\n" + hostile_line + "\nexit 1\n"
                with self.assertRaisesRegex(AssertionError, "compiler or copy"):
                    validate_disabled_producer(hostile)

    def test_hostile_success_receipt_or_shell_escape_is_rejected(self) -> None:
        hostile_lines = (
            "exit 0",
            "return 0",
            '"${RELEASE_PYTHON}" -I -S /dev/fd/16 record',
            'eval "${DEVICECHECK_BUILD_COMMAND}"',
            'bash -c "${DEVICECHECK_BUILD_COMMAND}"',
        )
        for hostile_line in hostile_lines:
            with self.subTest(hostile_line=hostile_line):
                hostile = self.build_script + "\n" + hostile_line + "\nexit 1\n"
                with self.assertRaises(AssertionError):
                    validate_disabled_producer(hostile)

    def test_hostile_source_hash_substitution_for_apk_custody_is_rejected(self) -> None:
        hostile_lines = (
            'TARGET_APK_SHA256="${SOURCE_CLOSURE_SHA256}"',
            'ANDROID_TEST_APK_SHA256=$MANIFEST_SHA256',
            'BUILT_ARTIFACT_SHA256="${SOURCE_SHA256}"',
        )
        for hostile_line in hostile_lines:
            with self.subTest(hostile_line=hostile_line):
                hostile = self.build_script + "\n" + hostile_line + "\nexit 1\n"
                with self.assertRaisesRegex(AssertionError, "built APK custody"):
                    validate_disabled_producer(hostile)

    def test_hostile_v2_authority_or_mutable_workspace_contract_is_rejected(self) -> None:
        hostile_mutations = (
            ("devicecheck-v3", "devicecheck-v2"),
            (
                'BUILD_WORKSPACE_ROOT="/private/var/winsvpn-devicecheck-build"',
                'BUILD_WORKSPACE_ROOT="${TMPDIR}/winsvpn-devicecheck-build"',
            ),
            (
                'BUILD_CACHE_ROOT="/private/var/winsvpn-devicecheck-cache"',
                'BUILD_CACHE_ROOT="${HOME}/.gradle"',
            ),
            (
                'SOURCE_CONSUMER_STATUS="unintegrated"',
                'SOURCE_CONSUMER_STATUS="integrated"',
            ),
        )
        for old, new in hostile_mutations:
            with self.subTest(new=new):
                hostile = self.build_script.replace(old, new)
                with self.assertRaisesRegex(
                    AssertionError,
                    "v2 authority|v3 source/authority/private-workspace",
                ):
                    validate_disabled_producer(hostile)

    def test_rejected_printed_sudo_helper_is_rejected(self) -> None:
        hostile = self.build_script + '\nprintf "%s\\n" "sudo install helper"\nexit 1\n'
        with self.assertRaisesRegex(AssertionError, "sudo helper"):
            validate_disabled_producer(hostile)

    def test_hostile_use_of_inert_source_paths_is_rejected(self) -> None:
        for variable in INERT_PATH_VARIABLES:
            with self.subTest(variable=variable):
                hostile = (
                    self.build_script
                    + f'\nprintf "%s" "${{{variable}}}"\nexit 1\n'
                )
                with self.assertRaisesRegex(AssertionError, "actively consumes ambient"):
                    validate_disabled_producer(hostile)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_authenticated_bytes(path: pathlib.Path) -> tuple[bytes, str]:
    """Read a bounded regular file without accepting path substitution."""
    root = ROOT.resolve(strict=True)
    absolute = path.absolute()
    try:
        absolute.relative_to(root)
    except ValueError as exc:
        raise AssertionError(f"source escapes repository root: {path}") from exc

    path_before = os.lstat(absolute)
    if not stat.S_ISREG(path_before.st_mode) or path_before.st_nlink != 1:
        raise AssertionError(
            f"source is not a regular one-link non-symlink file: {path}"
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(absolute, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise AssertionError(f"opened source is not regular and one-link: {path}")
        if before.st_size > MAX_SOURCE_BYTES:
            raise AssertionError(f"source exceeds read bound: {path}")
        if _identity(before) != _identity(path_before):
            raise AssertionError(f"source changed before authenticated read: {path}")

        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_SOURCE_BYTES + 1 - size),
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_SOURCE_BYTES:
                raise AssertionError(f"source exceeds read bound: {path}")

        after = os.fstat(descriptor)
        if _identity(after) != _identity(before) or size != before.st_size:
            raise AssertionError(f"source changed during authenticated read: {path}")
    finally:
        os.close(descriptor)

    path_after = os.lstat(absolute)
    if _identity(path_after) != _identity(path_before):
        raise AssertionError(f"source changed after authenticated read: {path}")

    raw = b"".join(chunks)
    if b"\x00" in raw:
        raise AssertionError(f"source contains a NUL byte: {path}")
    return raw, hashlib.sha256(raw).hexdigest()


def _decode_source(label: str, raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AssertionError(f"{label} is not UTF-8 source") from exc


if __name__ == "__main__":
    raise SystemExit(unittest.main())
