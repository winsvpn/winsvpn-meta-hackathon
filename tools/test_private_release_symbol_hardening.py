#!/usr/bin/env python3
"""Focused static regression tests for private release-symbol custody wiring."""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import re
import shlex
import shutil
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import release_obfuscation_contract as obfuscation
import release_secret_inventory as secret_inventory
import validate_release_artifact_privacy as privacy

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def _apk_signing_block(value: bytes, pair_id: int = 0x7109871A) -> bytes:
    pair = struct.pack("<I", pair_id) + value
    pair_record = struct.pack("<Q", len(pair)) + pair
    size = len(pair_record) + 24
    return (
        struct.pack("<Q", size)
        + pair_record
        + struct.pack("<Q", size)
        + APK_SIG_BLOCK_MAGIC
    )


def _insert_pre_central_directory(zip_bytes: bytes, gap: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        start_dir = archive.start_dir
    eocd = zip_bytes.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise AssertionError("fixture ZIP is missing EOCD")
    updated = bytearray(zip_bytes[:start_dir] + gap + zip_bytes[start_dir:])
    struct.pack_into("<I", updated, eocd + len(gap) + 16, start_dir + len(gap))
    return bytes(updated)


def _zstd_tar_supported() -> bool:
    return "zst" in getattr(tarfile.TarFile, "OPEN_METH", {})


# Test-only helper: token/semantic checks for Android Flutter release builds.
# Never executes a producer. Parses shell text only.
_ANDROID_FLUTTER_BUILD_KINDS = frozenset({"apk", "appbundle"})
_ANDROID_RELEASE_BOOLEAN_FLAGS = frozenset(
    {
        "--no-pub",
        "--release",
        "--obfuscate",
        "--debug",
        "--profile",
        "--pub",
    }
)
_ANDROID_RELEASE_VALUE_FLAGS = frozenset(
    {
        "--flavor",
        "--split-debug-info",
        "--dart-define",
        "--extra-gen-snapshot-options",
        "--target",
    }
)
_ANDROID_SHELL_COMMAND_BREAKS = frozenset({"&&", "||", ";", "|", "&"})
_ANDROID_HEREDOC_START = re.compile(
    r"""(?<!<)<<(?!<)\s*-?\s*(?:'([^']+)'|"([^"]+)"|\\?([A-Za-z_][A-Za-z0-9_]*))"""
)
_ANDROID_SIMPLE_VAR = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_ANDROID_BARE_VAR = re.compile(r"^\$([A-Za-z_][A-Za-z0-9_]*)$")
_ANDROID_PHONE_TV_RELEASE_BUILDS = (
    ("apk", "phone", "${STAGE_APK_SYMBOLS}"),
    ("appbundle", "phone", "${STAGE_AAB_SYMBOLS}"),
    ("apk", "tv", "${STAGE_TV_APK_SYMBOLS}"),
    ("appbundle", "tv", "${STAGE_TV_AAB_SYMBOLS}"),
)
_ANDROID_GOOGLE_PLAY_DEFINE = "WINS_GOOGLE_PLAY_BUILD=true"
_ANDROID_WINN3_DEFINE = "WINS_WINN3_ENABLED_PLATFORMS=android"
_ANDROID_BUILD_LINE = re.compile(r"(?:^|[\s;|&])build\s+(apk|appbundle)(?:\s|$)")


class AndroidReleaseInvocationContractError(AssertionError):
    """Semantic Android Flutter release-invocation contract failure."""


def assert_android_phone_tv_flutter_release_invocations(source: str) -> None:
    """Assert each Android phone/TV APK/AAB Flutter invocation independently.

    Required meaning, not substring adjacency: exact build kind, --no-pub,
    --release, correct --flavor, --obfuscate, nonempty distinct
    --split-debug-info, Google Play define, Winn v3 Android define, and no
    unflavored release invocation. Flag order, quoting, and line continuations
    may vary. Duplicates, omitted flags, wrong flavor, and reused symbol
    directories must fail. Does not execute the producer.
    """
    invocations = _android_flutter_apk_appbundle_invocations(source)
    release_invocations = []
    for invocation in invocations:
        booleans = invocation["booleans"]
        if "--debug" in booleans or "--profile" in booleans:
            if "--release" in booleans:
                raise AndroidReleaseInvocationContractError(
                    "Android Flutter invocation mixes --release with "
                    f"--debug/--profile: {invocation['kind']}"
                )
            continue
        release_invocations.append(invocation)

    if not release_invocations:
        raise AndroidReleaseInvocationContractError(
            "no Android Flutter apk/appbundle release invocations found"
        )

    seen_kind_flavor: dict[tuple[str, str | None], int] = {}
    split_owners: dict[str, tuple[str, str | None]] = {}
    observed: dict[tuple[str, str], str] = {}
    for invocation in release_invocations:
        kind = invocation["kind"]
        flavor = invocation["flavor"]
        booleans = invocation["booleans"]
        split_debug_info = invocation["split_debug_info"]
        defines = invocation["defines"]
        flavor_key = (kind, flavor)
        seen_kind_flavor[flavor_key] = seen_kind_flavor.get(flavor_key, 0) + 1
        if seen_kind_flavor[flavor_key] > 1:
            raise AndroidReleaseInvocationContractError(
                "duplicate Android Flutter release invocation: "
                f"{kind} flavor={flavor or '<missing>'}"
            )
        if flavor is None:
            raise AndroidReleaseInvocationContractError(
                f"unflavored Android Flutter release invocation: {kind}"
            )
        for required_flag in ("--no-pub", "--release", "--obfuscate"):
            if required_flag not in booleans:
                raise AndroidReleaseInvocationContractError(
                    f"missing required flag {required_flag} on {kind} flavor={flavor}"
                )
        if "--pub" in booleans:
            raise AndroidReleaseInvocationContractError(
                f"conflicting --pub on {kind} flavor={flavor}"
            )
        if not split_debug_info:
            raise AndroidReleaseInvocationContractError(
                f"empty --split-debug-info on {kind} flavor={flavor}"
            )
        if split_debug_info in split_owners:
            owner_kind, owner_flavor = split_owners[split_debug_info]
            raise AndroidReleaseInvocationContractError(
                "reused --split-debug-info value "
                f"{split_debug_info} on {kind} flavor={flavor} "
                f"(already used by {owner_kind} flavor={owner_flavor})"
            )
        split_owners[split_debug_info] = (kind, flavor)
        define_pairs = {f"{key}={value}" for key, value in defines.items()}
        if _ANDROID_GOOGLE_PLAY_DEFINE not in define_pairs:
            raise AndroidReleaseInvocationContractError(
                "missing dart-define WINS_GOOGLE_PLAY_BUILD=true on "
                f"{kind} flavor={flavor}"
            )
        if _ANDROID_WINN3_DEFINE not in define_pairs:
            raise AndroidReleaseInvocationContractError(
                "missing dart-define WINS_WINN3_ENABLED_PLATFORMS=android on "
                f"{kind} flavor={flavor}"
            )
        observed[(kind, flavor)] = split_debug_info

    expected = {
        (kind, flavor): symbols
        for kind, flavor, symbols in _ANDROID_PHONE_TV_RELEASE_BUILDS
    }
    expected_keys = set(expected)
    observed_keys = set(observed)
    missing = expected_keys - observed_keys
    extra = observed_keys - expected_keys
    if missing or extra:
        details = []
        if missing:
            details.append(
                "missing "
                + ", ".join(
                    f"{kind} flavor={flavor}" for kind, flavor in sorted(missing)
                )
            )
        if extra:
            details.append(
                "unexpected "
                + ", ".join(
                    f"{kind} flavor={flavor}" for kind, flavor in sorted(extra)
                )
            )
        raise AndroidReleaseInvocationContractError(
            "Android Flutter release invocations must be exactly phone/TV "
            "apk/appbundle: " + "; ".join(details)
        )
    for (kind, flavor), symbols in expected.items():
        actual = observed[(kind, flavor)]
        if actual != symbols:
            raise AndroidReleaseInvocationContractError(
                f"wrong --split-debug-info on {kind} flavor={flavor}: "
                f"expected {symbols}, found {actual}"
            )


def _android_flutter_apk_appbundle_invocations(source: str) -> list[dict[str, object]]:
    invocations: list[dict[str, object]] = []
    for command in _android_logical_shell_commands(source):
        if not _ANDROID_BUILD_LINE.search(command):
            continue
        try:
            tokens = shlex.split(command, posix=True, comments=True)
        except ValueError as error:
            raise AndroidReleaseInvocationContractError(
                f"Android Flutter build command could not be tokenized: {error}"
            ) from error
        for group in _android_split_command_groups(tokens):
            argv = _android_build_argv(group)
            if argv is None:
                continue
            invocations.append(_android_parse_build_argv(argv))
    return invocations


def _android_logical_shell_commands(source: str) -> list[str]:
    without_heredocs = _android_strip_heredoc_bodies(source)
    joined = _android_join_backslash_continuations(without_heredocs.splitlines())
    commands: list[str] = []
    for line in joined:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        commands.append(stripped)
    return commands


def _android_strip_heredoc_bodies(source: str) -> str:
    lines = source.splitlines()
    kept: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _ANDROID_HEREDOC_START.search(_android_strip_unquoted_comment(line))
        if match is None:
            kept.append(line)
            index += 1
            continue
        kept.append(line[: match.start()].rstrip())
        terminator = next(group for group in match.groups() if group)
        index += 1
        while index < len(lines):
            candidate = lines[index].rstrip("\r")
            if candidate == terminator or candidate.lstrip("\t") == terminator:
                index += 1
                break
            index += 1
    return "\n".join(kept)


def _android_strip_unquoted_comment(line: str) -> str:
    in_single = False
    in_double = False
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and in_double:
            index += 2
            continue
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index].rstrip()
        index += 1
    return line.rstrip()


def _android_join_backslash_continuations(lines: list[str]) -> list[str]:
    joined: list[str] = []
    buffer = ""
    for line in lines:
        stripped = line.rstrip()
        continued = stripped.endswith("\\") and not stripped.endswith("\\\\")
        piece = stripped[:-1] if continued else stripped
        if buffer:
            buffer = buffer.rstrip() + " " + piece.lstrip()
        else:
            buffer = piece
        if continued:
            continue
        if buffer:
            joined.append(buffer)
        buffer = ""
    if buffer:
        joined.append(buffer)
    return joined


def _android_split_command_groups(tokens: list[str]) -> list[list[str]]:
    groups: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in _ANDROID_SHELL_COMMAND_BREAKS:
            if current:
                groups.append(current)
                current = []
            continue
        current.append(token)
    if current:
        groups.append(current)
    return groups


def _android_build_argv(tokens: list[str]) -> list[str] | None:
    for index, token in enumerate(tokens):
        if (
            token == "build"
            and index + 1 < len(tokens)
            and tokens[index + 1] in _ANDROID_FLUTTER_BUILD_KINDS
        ):
            return tokens[index:]
    return None


def _android_parse_build_argv(argv: list[str]) -> dict[str, object]:
    kind = argv[1]
    booleans: set[str] = set()
    flavor: str | None = None
    split_debug_info: str | None = None
    defines: dict[str, str] = {}
    seen_value_flags: set[str] = set()
    index = 2
    while index < len(argv):
        token = argv[index]
        name = token
        value: str | None = None
        if token.startswith("--") and "=" in token:
            name, value = token.split("=", 1)
        if name in _ANDROID_RELEASE_BOOLEAN_FLAGS:
            if value is not None:
                raise AndroidReleaseInvocationContractError(
                    f"boolean flag {name} must not take a value on {kind}"
                )
            if name in booleans:
                raise AndroidReleaseInvocationContractError(
                    f"duplicate flag {name} on {kind}"
                )
            booleans.add(name)
            index += 1
            continue
        if name in _ANDROID_RELEASE_VALUE_FLAGS:
            if value is None:
                index += 1
                if index >= len(argv) or argv[index].startswith("--"):
                    raise AndroidReleaseInvocationContractError(
                        f"missing value for {name} on {kind}"
                    )
                value = argv[index]
            if name != "--dart-define" and name in seen_value_flags:
                raise AndroidReleaseInvocationContractError(
                    f"duplicate flag {name} on {kind}"
                )
            seen_value_flags.add(name)
            normalized = _android_normalize_shell_value(value)
            if name == "--flavor":
                flavor = normalized or None
            elif name == "--split-debug-info":
                split_debug_info = normalized
            elif name == "--dart-define":
                if not normalized or "=" not in normalized:
                    raise AndroidReleaseInvocationContractError(
                        f"malformed --dart-define on {kind}: {value}"
                    )
                define_key, define_value = normalized.split("=", 1)
                if define_key in defines:
                    raise AndroidReleaseInvocationContractError(
                        f"duplicate dart-define {define_key} on {kind}"
                    )
                defines[define_key] = define_value
            index += 1
            continue
        index += 1
    if flavor == "":
        flavor = None
    return {
        "kind": kind,
        "flavor": flavor,
        "split_debug_info": split_debug_info,
        "booleans": frozenset(booleans),
        "defines": defines,
    }


def _android_normalize_shell_value(value: str) -> str:
    stripped = value.strip()
    match = _ANDROID_SIMPLE_VAR.fullmatch(stripped) or _ANDROID_BARE_VAR.fullmatch(
        stripped
    )
    if match:
        return "${" + match.group(1) + "}"
    return stripped


def _canonical_android_phone_tv_release_fragment() -> str:
    rendered = []
    for kind, flavor, symbols in _ANDROID_PHONE_TV_RELEASE_BUILDS:
        rendered.append(
            "run_flutter_release_build build "
            f"{kind} --no-pub --release --flavor {flavor} --obfuscate "
            f'--split-debug-info="{symbols}" '
            f"--dart-define={_ANDROID_GOOGLE_PLAY_DEFINE} "
            f"--dart-define={_ANDROID_WINN3_DEFINE}"
        )
    return "\n".join(rendered) + "\n"


class PrivateSymbolHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        loaded = secret_inventory.SecretInventory(
            "private-symbol-hardening-fixture-v1",
            {"TEST_RELEASE_SECRET": "synthetic-release-secret-123456"},
            digest="a" * 64,
            identity=(1, 2, 3, 4, 5, 6, 7),
        )
        authorization = secret_inventory._InventoryAuthorization(
            revision=loaded.revision,
            labels=loaded.labels,
            inventory_digest=loaded.digest,
            inventory_identity=loaded.identity,
            inventory_path=pathlib.Path("/nonexistent/wins-release-secret-inventory.json"),
            repository_root=ROOT,
        )
        self._test_inventory = secret_inventory._make_authenticated_inventory(
            loaded, authorization
        )
        self._inventory_patches = (
            mock.patch.object(
                secret_inventory,
                "load_authenticated_secret_inventory",
                return_value=self._test_inventory,
            ),
        )
        for patcher in self._inventory_patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self._inventory_patches):
            patcher.stop()

    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_android_custodies_r8_and_native_symbols(self) -> None:
        script = self.read("tools/build_android_release.ps1")
        for required in (
            "mapping\\phoneRelease\\mapping.txt",
            "native-debug-symbols\\phoneRelease\\native-debug-symbols.zip",
            "mapping\\tvRelease\\mapping.txt",
            "native-debug-symbols\\tvRelease\\native-debug-symbols.zip",
            "android-tv-aab",
            "proguard-mapping.txt",
            "private_release_symbol_custody.py",
            "Initialize-PrivateSymbolDirectory",
        ):
            self.assertIn(required, script)

    def test_default_secret_scan_includes_apk_and_aab(self) -> None:
        scanner = self.read("tools/validate_release_artifact_privacy.py")
        defaults = scanner.split("STATIC_PATHS", 1)[0]
        self.assertIn('"flutter-apk" / "app-release.apk"', defaults)
        self.assertIn('"bundle" / "release" / "app-release.aab"', defaults)

    def test_static_privacy_scan_covers_wear_and_extension_sources(self) -> None:
        scanner = self.read("tools/validate_release_artifact_privacy.py")
        static = scanner.split("STATIC_PATHS", 1)[1].split("IGNORED_STATIC_PARTS", 1)[0]
        self.assertIn('ROOT / "wear_os" / "app" / "src" / "main"', static)
        self.assertIn('ROOT / "extension" / "src"', static)
        self.assertIn('ROOT / "extension" / "manifest"', static)
        self.assertNotIn('ROOT / "extension" / "tools"', static)

    def test_vendor_binary_privacy_approvals_match_current_release_inputs(self) -> None:
        expected_by_abi = {
            "arm64-v8a": "30772382fcee4fe18b6c31a3daf9a53878b5bfa775e05ea3f3c8cb0b0ec73b2b",
            "armeabi-v7a": "35e5256bce15bc30bd3dbf7ba82c7ac6b138782eae811e0ae4ab535fbedec1b9",
            "x86_64": "82885af5bc2c89eb10201af08049d865c398025fe89f2b8cd02178fc275876b4",
        }
        expected_inputs = {
            f"android/app/src/{source_set}/jniLibs/{abi}/libxray.so": digest
            for source_set in ("main", "debug", "profile", "release")
            for abi, digest in expected_by_abi.items()
        }
        expected_inputs["installer/windows/dependencies/xray.exe"] = (
            "fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224"
        )
        actual_inputs = {
            relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for relative in expected_inputs
        }
        self.assertEqual(expected_inputs, actual_inputs)

        expected_approvals = set(expected_inputs.values()) | {
            "78ecc9ebaf6e0cd43132fb0f72b7915e0ad7970f7868e2454f7308151797c6f6",
            "26e2688e76e15bc96fdbdbbbbbd98b26090e88cacf51936569f9400f2e55188b",
            "9c2045c1e201128916bc2bac5cee65fdd8de35520a31d601c71cdbd51e202032",
            "09e63d5420f26db2bc6144f6d047601909541acf21792878d3859e4fc4980a12",
            "868fcabbf9a08d1e453bc6dc82dd8ca27cfcf8cdb2b3a8ff31b824361966964b",
        }
        self.assertEqual(expected_approvals, privacy.APPROVED_VENDOR_BINARY_SHA256)

    def test_linux_split_debug_contract_is_fail_closed(self) -> None:
        script = self.read("tools/build_linux_release.sh")
        for required in (
            "objcopy --only-keep-debug",
            "strip --strip-unneeded",
            "objcopy --add-gnu-debuglink",
            "[.]note[.]gnu[.]build-id",
            "[.]debug_info",
            "LINUX OWNED BINARY USER-HOME PATH SCAN: PASS",
            "private_release_symbol_custody.py",
        ):
            self.assertIn(required, script)
        cmake = self.read("linux/runner/CMakeLists.txt")
        self.assertIn("-Wl,--build-id=sha1", cmake)
        self.assertIn("$<$<CONFIG:Release>:-g>", cmake)
        workflow = self.read(".github/workflows/build-linux-release.yml")
        self.assertIn("Reject symbol-losing CI rebuilds", workflow)
        self.assertIn("exit 64", workflow)

    def test_linux_wsl_builds_use_a_verified_neutral_stage(self) -> None:
        script = self.read("tools/build_linux_release.sh")
        for required in (
            "run_from_neutral_wsl_stage",
            "WINS_RELEASE_INPUT_INDEX",
            "WINS_LINUX_REVIEWED_UNTRACKED_MANIFEST",
            "create_cross_machine_source_archive.ps1",
            "extract_cross_machine_source_archive.sh",
            "WINS_LINUX_NEUTRAL_STAGE_ACTIVE=1",
            "env -u PSModulePath powershell.exe",
            'verify-index',
            'Neutral WSL release build completed and reverified',
        ):
            self.assertIn(required, script)
        self.assertIn('[[ "${ROOT}" == /mnt/* ]] || return 1', script)
        self.assertIn('if [[ "${ROOT}" == /mnt/* ]]; then', script)
        self.assertNotIn('if run_from_neutral_wsl_stage; then', script)

    def test_windows_hardens_acl_and_records_custody(self) -> None:
        script = self.read("installer/windows/build_installer.ps1")
        self.assertIn("Initialize-PrivateSymbolDirectory", script)
        self.assertIn("Get-WindowsPayloadDebugSymbolFiles", script)
        self.assertIn("Move-WindowsPayloadDebugSymbolsToPrivateCustody", script)
        self.assertIn("Assert-WindowsPayloadContainsNoDebugSymbols", script)
        self.assertIn("private_release_symbol_custody.py", script)
        self.assertIn("Add-DartPluginRegistrantVirtualPackage", script)
        self.assertIn("rootUri = 'flutter_build/'", script)
        self.assertIn("$script:FlutterCommand = $flutterCommand.Source", script)
        self.assertIn(
            "& $script:FlutterCommand build windows --release --no-pub --obfuscate",
            script,
        )
        acl = self.read("tools/private_symbol_custody.ps1")
        self.assertIn("SetAccessRuleProtection($true, $false)", acl)
        self.assertIn("S-1-5-18", acl)
        self.assertIn("FileSystemAclExtensions", acl)
        self.assertNotIn("Set-Acl -LiteralPath", acl)

    def test_android_strip_gate_covers_every_delivery_native_library(self) -> None:
        stripped = obfuscation._minimal_elf64(".text", ".dynsym")
        debug = obfuscation._minimal_elf64(".text", ".debug_info")
        with tempfile.TemporaryDirectory() as temp_name:
            apk = pathlib.Path(temp_name) / "app-release.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", stripped)
                archive.writestr("lib/arm64-v8a/libflutter.so", stripped)
                archive.writestr("lib/arm64-v8a/libam-go.so", debug)
            with self.assertRaises(obfuscation.ObfuscationError):
                obfuscation.verify_delivery_native_payload_is_stripped("android-apk", [apk])
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", stripped)
                archive.writestr("lib/arm64-v8a/libflutter.so", stripped)
                archive.writestr("lib/arm64-v8a/libam-go.so", stripped)
                archive.writestr("lib/arm64-v8a/libwinnengine.so", stripped)
                archive.writestr("lib/arm64-v8a/libxray.so", stripped)
            obfuscation.verify_delivery_native_payload_is_stripped("android-apk", [apk])

    def test_linux_and_ios_artifacts_reject_unstripped_non_flutter_natives(self) -> None:
        stripped = obfuscation._minimal_elf64(".text")
        debug = obfuscation._minimal_elf64(".debug_abbrev")
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            archive_path = root / "wins-vpn-linux-x64.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, payload in (
                    ("lib/libapp.so", stripped),
                    ("amneziawg-go", debug),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            with self.assertRaises(obfuscation.ObfuscationError):
                obfuscation.verify_delivery_native_payload_is_stripped("linux", [archive_path])
            ipa = root / "WinsVPN.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr(
                    "Payload/Runner.app/Frameworks/Flutter.framework/Flutter",
                    obfuscation._minimal_macho64(dwarf=False),
                )
                archive.writestr(
                    "Payload/Runner.app/Frameworks/libwg-go.dylib",
                    obfuscation._minimal_macho64(dwarf=True),
                )
            with self.assertRaises(obfuscation.ObfuscationError):
                obfuscation.verify_delivery_native_payload_is_stripped("ios", [ipa])
            windows_dir = root / "Release"
            windows_dir.mkdir()
            (windows_dir / "wins_vpn.exe").write_bytes(obfuscation._minimal_pe(".text"))
            (windows_dir / "winnengine.dll").write_bytes(obfuscation._minimal_pe(".debug"))
            with self.assertRaises(obfuscation.ObfuscationError):
                obfuscation.verify_delivery_native_payload_is_stripped("windows", [windows_dir])

    def test_privacy_scan_rejects_native_library_secrets_and_debug_sections(self) -> None:
        stripped = obfuscation._minimal_elf64(".text")
        debug = obfuscation._minimal_elf64(".debug_line")
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            secret_apk = root / "secret.apk"
            with zipfile.ZipFile(secret_apk, "w") as archive:
                archive.writestr(
                    "lib/arm64-v8a/libxray.so",
                    stripped + b"-----BEGIN OPENSSH PRIVATE KEY-----",
                )
            with self.assertRaises(privacy.PrivacyError):
                privacy.validate_artifacts((secret_apk,), {})
            debug_apk = root / "debug.apk"
            with zipfile.ZipFile(debug_apk, "w") as archive:
                archive.writestr("lib/x86_64/libam-go.so", debug)
            with self.assertRaises(privacy.PrivacyError):
                privacy.validate_artifacts((debug_apk,), {})
            clean = root / "clean.apk"
            with zipfile.ZipFile(clean, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", stripped)
                archive.writestr("lib/arm64-v8a/libxray.so", stripped)
            privacy.validate_artifacts((clean,), {})

    def test_static_contract_covers_macos_android_obfuscation_producer(self) -> None:
        contract = self.read("tools/release_obfuscation_contract.py")
        self.assertIn('"tools/build_android_release_macos.sh"', contract)
        self.assertIn(
            "tools/build_android_release_macos.sh pre-strips libapp.so", contract
        )
        script = self.read("tools/build_android_release_macos.sh")
        assert_android_phone_tv_flutter_release_invocations(script)
        self.assertNotIn("--extra-gen-snapshot-options=--strip", script)

    def test_android_release_invocation_parser_accepts_quoting_multiline_and_order(
        self,
    ) -> None:
        canonical = _canonical_android_phone_tv_release_fragment()
        assert_android_phone_tv_flutter_release_invocations(canonical)

        reordered_phone_apk = (
            "run_flutter_release_build build apk --obfuscate --flavor phone "
            "--split-debug-info=${STAGE_APK_SYMBOLS} --no-pub --release "
            "--dart-define=WINS_WINN3_ENABLED_PLATFORMS=android "
            "--dart-define=WINS_GOOGLE_PLAY_BUILD=true"
        )
        remaining = "\n".join(canonical.strip().splitlines()[1:])
        assert_android_phone_tv_flutter_release_invocations(
            reordered_phone_apk + "\n" + remaining + "\n"
        )

        equals_and_separate_values = """
IFS= read -r winn3_define_line <<<"${WINN3_DEFINE_LINES}"
run_flutter_release_build build apk --release --no-pub --flavor=phone --obfuscate --split-debug-info "${STAGE_APK_SYMBOLS}" --dart-define WINS_GOOGLE_PLAY_BUILD=true --dart-define=WINS_WINN3_ENABLED_PLATFORMS=android
run_flutter_release_build build appbundle --no-pub --obfuscate --release --flavor "phone" --split-debug-info="$STAGE_AAB_SYMBOLS" --dart-define=WINS_GOOGLE_PLAY_BUILD=true --dart-define=WINS_WINN3_ENABLED_PLATFORMS=android
run_flutter_release_build build apk \\
  --no-pub \\
  --release \\
  --flavor tv \\
  --obfuscate \\
  --split-debug-info="${STAGE_TV_APK_SYMBOLS}" \\
  --dart-define=WINS_GOOGLE_PLAY_BUILD=true \\
  --dart-define=WINS_WINN3_ENABLED_PLATFORMS=android
run_flutter_release_build build appbundle --no-pub --release --flavor tv --obfuscate --split-debug-info="${STAGE_TV_AAB_SYMBOLS}" --dart-define=WINS_GOOGLE_PLAY_BUILD=true --dart-define=WINS_WINN3_ENABLED_PLATFORMS=android
"""
        assert_android_phone_tv_flutter_release_invocations(equals_and_separate_values)

    def test_android_release_invocation_parser_rejects_contract_mutations(self) -> None:
        canonical_lines = _canonical_android_phone_tv_release_fragment().strip().splitlines()
        phone_apk, phone_aab, tv_apk, tv_aab = canonical_lines
        mutations = (
            (
                "duplicate invocation",
                "duplicate Android Flutter release invocation: apk flavor=phone",
                "\n".join((phone_apk, phone_apk, phone_aab, tv_apk, tv_aab)),
            ),
            (
                "omitted --no-pub",
                "missing required flag --no-pub on apk flavor=phone",
                "\n".join(
                    (
                        phone_apk.replace(" --no-pub", "", 1),
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "omitted --obfuscate",
                "missing required flag --obfuscate on apk flavor=phone",
                "\n".join(
                    (
                        phone_apk.replace(" --obfuscate", "", 1),
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "omitted --release",
                "missing required flag --release on apk flavor=phone",
                "\n".join(
                    (
                        phone_apk.replace(" --release", "", 1),
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "unflavored release",
                "unflavored Android Flutter release invocation: apk",
                "\n".join(
                    (
                        phone_apk.replace(" --flavor phone", "", 1),
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "wrong flavor",
                "unexpected apk flavor=wearable",
                "\n".join(
                    (
                        phone_apk.replace("--flavor phone", "--flavor wearable", 1),
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "extra unflavored release",
                "unflavored Android Flutter release invocation: apk",
                "\n".join(
                    (
                        phone_apk,
                        phone_aab,
                        tv_apk,
                        tv_aab,
                        "run_flutter_release_build build apk --no-pub --release "
                        "--obfuscate --split-debug-info=${STAGE_EXTRA_SYMBOLS} "
                        "--dart-define=WINS_GOOGLE_PLAY_BUILD=true "
                        "--dart-define=WINS_WINN3_ENABLED_PLATFORMS=android",
                    )
                ),
            ),
            (
                "reused symbols dir",
                r"reused --split-debug-info value \$\{STAGE_APK_SYMBOLS\}",
                "\n".join(
                    (
                        phone_apk,
                        phone_aab.replace(
                            "${STAGE_AAB_SYMBOLS}", "${STAGE_APK_SYMBOLS}", 1
                        ),
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "empty split-debug-info",
                "empty --split-debug-info on apk flavor=phone",
                "\n".join(
                    (
                        phone_apk.replace(
                            '--split-debug-info="${STAGE_APK_SYMBOLS}"',
                            '--split-debug-info=""',
                            1,
                        ),
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "omitted Google Play define",
                "missing dart-define WINS_GOOGLE_PLAY_BUILD=true on apk flavor=phone",
                "\n".join(
                    (
                        phone_apk.replace(
                            " --dart-define=WINS_GOOGLE_PLAY_BUILD=true", "", 1
                        ),
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "omitted Winn v3 Android define",
                "missing dart-define WINS_WINN3_ENABLED_PLATFORMS=android on apk flavor=phone",
                "\n".join(
                    (
                        phone_apk.replace(
                            " --dart-define=WINS_WINN3_ENABLED_PLATFORMS=android",
                            "",
                            1,
                        ),
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "duplicate --flavor flag",
                "duplicate flag --flavor on apk",
                "\n".join(
                    (
                        phone_apk.replace(
                            "--flavor phone", "--flavor phone --flavor tv", 1
                        ),
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
            (
                "missing tv appbundle",
                "missing appbundle flavor=tv",
                "\n".join((phone_apk, phone_aab, tv_apk)),
            ),
            (
                "contiguous adjacency without --no-pub is not sufficient",
                "missing required flag --no-pub on apk flavor=phone",
                "\n".join(
                    (
                        "run_flutter_release_build build apk --release --flavor phone --obfuscate "
                        '--split-debug-info="${STAGE_APK_SYMBOLS}" '
                        "--dart-define=WINS_GOOGLE_PLAY_BUILD=true "
                        "--dart-define=WINS_WINN3_ENABLED_PLATFORMS=android",
                        phone_aab,
                        tv_apk,
                        tv_aab,
                    )
                ),
            ),
        )
        for label, pattern, mutated in mutations:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    AndroidReleaseInvocationContractError, pattern
                ):
                    assert_android_phone_tv_flutter_release_invocations(mutated)

    def test_native_strip_rejects_elf_symbol_tables(self) -> None:
        stripped = obfuscation._minimal_elf64(".text", ".dynsym")
        unstripped = obfuscation._minimal_elf64(".text", ".symtab")
        with tempfile.TemporaryDirectory() as temp_name:
            apk = pathlib.Path(temp_name) / "app-release.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", stripped)
                archive.writestr("lib/arm64-v8a/libxray.so", unstripped)
            with self.assertRaises(obfuscation.ObfuscationError):
                obfuscation.verify_delivery_native_payload_is_stripped("android-apk", [apk])

    def test_native_strip_rejects_compressed_and_legacy_debug_indexes(self) -> None:
        for section in (
            ".debug",
            ".rel.debug_info",
            ".rela.debug_info",
            ".gnu_debugdata",
            ".gdb_index",
            ".stab",
            ".stabstr",
        ):
            with self.subTest(section=section):
                payload = obfuscation._minimal_elf64(".text", section)
                self.assertEqual(
                    obfuscation.inspect_native_debug_sections(payload),
                    ("elf", (section,)),
                )

    def test_elf_symbol_type_and_extended_section_numbering_fail_closed(self) -> None:
        renamed_symtab = bytearray(obfuscation._minimal_elf64(".renamed-symbols"))
        shoff = int.from_bytes(renamed_symtab[40:48], "little")
        renamed_symtab[shoff + 64 + 4 : shoff + 64 + 8] = (2).to_bytes(4, "little")
        self.assertEqual(
            obfuscation.inspect_native_debug_sections(bytes(renamed_symtab)),
            ("elf", ("SHT_SYMTAB:.renamed-symbols",)),
        )

        extended = bytearray(obfuscation._minimal_elf64(".text", ".debug_info"))
        shoff = int.from_bytes(extended[40:48], "little")
        section_count = int.from_bytes(extended[60:62], "little")
        string_index = int.from_bytes(extended[62:64], "little")
        extended[60:62] = b"\0\0"
        extended[62:64] = b"\xff\xff"
        extended[shoff + 32 : shoff + 40] = section_count.to_bytes(8, "little")
        extended[shoff + 40 : shoff + 44] = string_index.to_bytes(4, "little")
        self.assertEqual(
            obfuscation.inspect_native_debug_sections(bytes(extended)),
            ("elf", (".debug_info",)),
        )

    def test_pe_debug_directory_and_coff_symbols_fail_closed(self) -> None:
        codeview = obfuscation._minimal_pe_with_debug_directory(2)
        self.assertEqual(
            obfuscation.inspect_native_debug_sections(codeview),
            ("pe", ("PE_DEBUG_DIRECTORY_TYPE_2",)),
        )
        reproducible = obfuscation._minimal_pe_with_debug_directory(16)
        self.assertEqual(
            obfuscation.inspect_native_debug_sections(reproducible),
            ("pe", ()),
        )
        coff = bytearray(obfuscation._minimal_pe(".text"))
        e_lfanew = int.from_bytes(coff[60:64], "little")
        coff_symbol_pointer = len(coff)
        coff.extend(b"\0" * 18 + (4).to_bytes(4, "little"))
        coff[e_lfanew + 12 : e_lfanew + 16] = coff_symbol_pointer.to_bytes(4, "little")
        coff[e_lfanew + 16 : e_lfanew + 20] = (1).to_bytes(4, "little")
        self.assertEqual(
            obfuscation.inspect_native_debug_sections(bytes(coff)),
            ("pe", ("COFF_SYMTAB",)),
        )

    def test_macho_local_and_stab_symbols_fail_but_exports_remain(self) -> None:
        self.assertEqual(
            obfuscation.inspect_native_debug_sections(
                obfuscation._minimal_macho64_with_symbol(0x0F)
            ),
            ("macho", ()),
        )
        self.assertEqual(
            obfuscation.inspect_native_debug_sections(
                obfuscation._minimal_macho64_with_symbol(0x0E)
            ),
            ("macho", ("LC_SYMTAB_LOCAL",)),
        )
        self.assertEqual(
            obfuscation.inspect_native_debug_sections(
                obfuscation._minimal_macho64_with_symbol(0xE0)
            ),
            ("macho", ("LC_SYMTAB_STAB",)),
        )

    def test_macho_single_local_is_allowed_only_when_it_is_the_marker(self) -> None:
        def macho(n_type: int, name: bytes, nlocalsym: int) -> bytes:
            symtab_size, dysymtab_size = 24, 80
            commands = symtab_size + dysymtab_size
            symbol_offset = 32 + commands
            strings = b"\0" + name + b"\0"
            string_offset = symbol_offset + 16
            data = bytearray(string_offset + len(strings))
            data[0:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<IIIII", data, 4, 0x0100000C, 0, 6, 2, commands)
            struct.pack_into(
                "<IIIIII", data, 32, 0x2, symtab_size, symbol_offset, 1, string_offset, len(strings)
            )
            struct.pack_into("<IIII", data, 56, 0xB, dysymtab_size, 0, nlocalsym)
            struct.pack_into("<I", data, symbol_offset, 1)
            data[symbol_offset + 4] = n_type
            data[string_offset:] = strings
            return bytes(data)

        marker = obfuscation.APPLE_LINKER_STRIP_MARKER
        n_opt = obfuscation.MACHO_N_OPT
        self.assertEqual(obfuscation.inspect_native_debug_sections(macho(n_opt, marker, 1)), ("macho", ()))
        for n_type, name, nlocalsym, expected in (
            (n_opt, marker, 2, ("LC_DYSYMTAB_LOCAL",)),
            (n_opt, b"radr://5614543", 1, ("LC_SYMTAB_STAB", "LC_DYSYMTAB_LOCAL")),
            (0x0E, marker, 1, ("LC_SYMTAB_LOCAL", "LC_DYSYMTAB_LOCAL")),
        ):
            with self.subTest(n_type=hex(n_type), name=name, nlocalsym=nlocalsym):
                self.assertEqual(
                    obfuscation.inspect_native_debug_sections(macho(n_type, name, nlocalsym)),
                    ("macho", expected),
                )

    def test_macho_strip_marker_is_allowed_once(self) -> None:
        # ld64 leaves exactly one marker; more than one passed at HEAD when
        # LC_DYSYMTAB was absent or claimed a single local.
        def macho(markers: int, dysymtab_locals: int | None) -> bytes:
            symtab_size = 24
            dysymtab_size = 80 if dysymtab_locals is not None else 0
            commands = symtab_size + dysymtab_size
            symbol_offset = 32 + commands
            name = obfuscation.APPLE_LINKER_STRIP_MARKER
            strings = b"\0" + name + b"\0"
            string_offset = symbol_offset + (16 * markers)
            data = bytearray(string_offset + len(strings))
            data[0:4] = b"\xcf\xfa\xed\xfe"
            ncmds = 2 if dysymtab_locals is not None else 1
            struct.pack_into("<IIIII", data, 4, 0x0100000C, 0, 6, ncmds, commands)
            struct.pack_into(
                "<IIIIII", data, 32, 0x2, symtab_size, symbol_offset, markers,
                string_offset, len(strings),
            )
            if dysymtab_locals is not None:
                struct.pack_into("<IIII", data, 56, 0xB, dysymtab_size, 0, dysymtab_locals)
            for index in range(markers):
                at = symbol_offset + (16 * index)
                struct.pack_into("<I", data, at, 1)
                data[at + 4] = obfuscation.MACHO_N_OPT
                struct.pack_into("<Q", data, at + 8, 0x4141414141414141 + index)
            data[string_offset:] = strings
            return bytes(data)

        for dysymtab_locals in (None, 1):
            with self.subTest(markers=1, dysymtab_locals=dysymtab_locals):
                self.assertEqual(
                    obfuscation.inspect_native_debug_sections(macho(1, dysymtab_locals)),
                    ("macho", ()),
                )
            for markers in (2, 5):
                with self.subTest(markers=markers, dysymtab_locals=dysymtab_locals):
                    self.assertEqual(
                        obfuscation.inspect_native_debug_sections(
                            macho(markers, dysymtab_locals)
                        ),
                        ("macho", ("LC_SYMTAB_STAB",)),
                    )

    def test_macho_linker_strip_marker_is_the_only_allowed_stab(self) -> None:
        # Every stripped Apple executable keeps ld64's N_OPT "radr://5614542".
        marker = obfuscation.APPLE_LINKER_STRIP_MARKER
        self.assertEqual(
            obfuscation.inspect_native_debug_sections(
                obfuscation._minimal_macho64_with_symbol(obfuscation.MACHO_N_OPT, marker)
            ),
            ("macho", ()),
        )
        for n_type, name in (
            (obfuscation.MACHO_N_OPT, b"radr://5614543"),
            (obfuscation.MACHO_N_OPT, b"fixture_symbol"),
            (0x24, marker),
            (0x64, marker),
        ):
            with self.subTest(n_type=hex(n_type), name=name):
                self.assertEqual(
                    obfuscation.inspect_native_debug_sections(
                        obfuscation._minimal_macho64_with_symbol(n_type, name)
                    ),
                    ("macho", ("LC_SYMTAB_STAB",)),
                )

    def test_private_maps_and_source_map_references_never_ship(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            for name, payload in (
                ("assets/app.js.map", b"{}"),
                ("assets/private.pdb", b"PDB fixture"),
                ("assets/app.js", b"//# sourceMappingURL=data:application/json;base64,e30="),
            ):
                with self.subTest(name=name):
                    artifact = root / (pathlib.PurePosixPath(name).name + ".zip")
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr(name, payload)
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError, "source[- ]map|private symbol"
                    ):
                        obfuscation.verify_release_artifact_hardening(
                            "windows", [artifact]
                        )

    def test_android_aab_allows_only_store_scoped_symbol_metadata(self) -> None:
        stripped = obfuscation._minimal_elf64(".text", ".dynsym")
        debug = obfuscation._minimal_elf64(".text", ".debug_info")
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            aab = root / "app-release.aab"
            with zipfile.ZipFile(aab, "w") as archive:
                archive.writestr("base/lib/arm64-v8a/libapp.so", stripped)
                archive.writestr(
                    "BUNDLE-METADATA/com.android.tools.build.debugsymbols/"
                    "arm64-v8a/libapp.so.sym",
                    debug,
                )
                archive.writestr(
                    "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
                    b"fixture -> a:\n",
                )
            obfuscation.verify_release_artifact_hardening("android-aab", [aab])
            with zipfile.ZipFile(aab, "a") as archive:
                archive.writestr("assets/proguard.map", b"fixture -> b:\n")
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "private symbol"):
                obfuscation.verify_release_artifact_hardening("android-aab", [aab])

    def test_direct_contract_rejects_long_lived_credentials(self) -> None:
        fixtures = (
            b"GEMINI_API_KEY=AIza" + (b"A" * 35),
            b"PrivateKey=" + (b"A" * 44),
            ("client_secret=" + ("B" * 32)).encode("utf-16-le"),
            b"https://operator:reusable-password-value@example.invalid/api",
        )
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            for index, payload in enumerate(fixtures):
                with self.subTest(index=index):
                    artifact = root / f"credential-{index}.zip"
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr("assets/config.bin", payload)
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError, "remove the credential"
                    ):
                        obfuscation.verify_release_artifact_hardening(
                            "windows", [artifact]
                        )

    def test_internal_identifier_probe_rejects_ascii_and_utf16_artifact_tokens(self) -> None:
        for payload in (
            b"prefix WinnV3StagedStart suffix",
            "prefix protectOrRollback suffix".encode("utf-16-le"),
            b"wins_vpn/winn3_internal",
        ):
            with self.subTest(payload=payload[:32]):
                with self.assertRaisesRegex(
                    obfuscation.ObfuscationError, "sensitive internal"
                ):
                    obfuscation.reject_sensitive_internal_identifiers(
                        "windows", "payload.bin", payload
                    )

    def test_internal_identifier_probe_rejects_unaligned_utf16_both_endiannesses(self) -> None:
        for encoding in ("utf-16-le", "utf-16-be"):
            payload = b"X" + ("prefix WinnV3StagedStart suffix").encode(encoding)
            with self.subTest(encoding=encoding):
                with self.assertRaisesRegex(
                    obfuscation.ObfuscationError, "sensitive internal class identifier"
                ):
                    obfuscation.reject_sensitive_internal_identifiers(
                        "windows", "unaligned.bin", payload
                    )

    def test_nested_archives_are_recursively_scanned_for_internal_identifiers(self) -> None:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("assets/runtime.bin", b"WinnV3StagedStart")
        with tempfile.TemporaryDirectory() as temp_name:
            outer = pathlib.Path(temp_name) / "outer.zip"
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr("payload/inner.zip", inner.getvalue())
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "sensitive internal class identifier"
            ):
                obfuscation.verify_release_artifact_hardening("windows", [outer])

            nested_tar = io.BytesIO()
            with tarfile.open(fileobj=nested_tar, mode="w:gz") as archive:
                payload = b"protectOrRollback"
                info = tarfile.TarInfo("assets/runtime.bin")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr("payload/opaque.bin", nested_tar.getvalue())
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "sensitive internal method identifier"
            ):
                obfuscation.verify_release_artifact_hardening("windows", [outer])

    def test_zip_and_tar_member_filenames_are_scanned_for_internal_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            zip_artifact = root / "filename.zip"
            with zipfile.ZipFile(zip_artifact, "w") as archive:
                archive.writestr("assets/WinnV3StagedStart.txt", b"clean")
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "sensitive internal class identifier"
            ):
                obfuscation.verify_release_artifact_hardening(
                    "windows", [zip_artifact]
                )

            tar_artifact = root / "filename.tar"
            with tarfile.open(tar_artifact, "w") as archive:
                payload = b"clean"
                info = tarfile.TarInfo("assets/WinnV3StagedStart.txt")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "sensitive internal class identifier"
            ):
                obfuscation.verify_release_artifact_hardening(
                    "windows", [tar_artifact]
                )

    def test_zip_comments_extra_and_tar_link_names_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            fixtures: list[pathlib.Path] = []

            member_comment = root / "member-comment.zip"
            with zipfile.ZipFile(member_comment, "w") as archive:
                info = zipfile.ZipInfo("clean.bin")
                info.comment = b"WinnV3StagedStart"
                archive.writestr(info, b"clean")
            fixtures.append(member_comment)

            member_extra = root / "member-extra.zip"
            with zipfile.ZipFile(member_extra, "w") as archive:
                payload = b"WinnV3StagedStart"
                info = zipfile.ZipInfo("clean.bin")
                info.extra = b"\xfe\xca" + len(payload).to_bytes(2, "little") + payload
                archive.writestr(info, b"clean")
            fixtures.append(member_extra)

            local_extra = root / "local-extra.zip"
            with zipfile.ZipFile(local_extra, "w") as archive:
                payload = b"WinnV3StagedStart"
                info = zipfile.ZipInfo("clean.bin")
                info.extra = b"\xfe\xca" + len(payload).to_bytes(2, "little") + payload
                archive.writestr(info, b"clean")
            raw = bytearray(local_extra.read_bytes())
            central_token = raw.rfind(payload)
            self.assertGreater(central_token, raw.find(payload))
            raw[central_token : central_token + len(payload)] = b"X" * len(payload)
            local_extra.write_bytes(raw)
            fixtures.append(local_extra)

            tar_link = root / "linkname.tar"
            with tarfile.open(tar_link, "w") as archive:
                info = tarfile.TarInfo("clean-link")
                info.type = tarfile.SYMTYPE
                info.linkname = "WinnV3StagedStart"
                archive.addfile(info)
            fixtures.append(tar_link)

            for artifact in fixtures:
                with self.subTest(artifact=artifact.name):
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError,
                        "sensitive internal class identifier",
                    ):
                        obfuscation.verify_release_artifact_hardening(
                            "windows", [artifact]
                        )

    def test_tar_owner_and_group_names_are_scanned_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            for field in ("uname", "gname"):
                with self.subTest(field=field):
                    artifact = root / f"{field}.tar"
                    with tarfile.open(artifact, "w") as archive:
                        info = tarfile.TarInfo("a")
                        info.size = 5
                        setattr(info, field, "WinnV3StagedStart")
                        archive.addfile(info, io.BytesIO(b"clean"))
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError,
                        "sensitive internal class identifier",
                    ):
                        obfuscation.verify_release_artifact_hardening(
                            "windows", [artifact]
                        )

            for field in ("uname", "gname"):
                with self.subTest(bound=field):
                    bounded = root / f"bounded-{field}.tar"
                    with tarfile.open(bounded, "w") as archive:
                        info = tarfile.TarInfo("a")
                        info.size = 5
                        setattr(info, field, "12345")
                        archive.addfile(info, io.BytesIO(b"clean"))
                    with mock.patch.object(
                        obfuscation, "MAX_ARCHIVE_METADATA_FIELD_BYTES", 4
                    ):
                        with self.assertRaisesRegex(
                            obfuscation.ObfuscationError,
                            rf"metadata field exceeds.*<tar-member-0-{field}>",
                        ):
                            list(obfuscation.iter_artifact_blobs(bounded))

    def test_zip_prefix_and_post_eocd_trailer_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            clean = root / "clean.zip"
            with zipfile.ZipFile(clean, "w") as archive:
                archive.writestr("clean.bin", b"clean")
            clean_bytes = clean.read_bytes()

            prefixed = root / "prefixed.zip"
            prefixed.write_bytes(b"WinnV3StagedStart" + clean_bytes)
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "noncanonical prefix"
            ):
                list(obfuscation.iter_artifact_blobs(prefixed))

            trailed = root / "trailed.zip"
            trailed.write_bytes(clean_bytes + b"WinnV3StagedStart")
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "trailing bytes after EOCD"
            ):
                list(obfuscation.iter_artifact_blobs(trailed))

    def test_apk_signing_block_is_scanned_and_unexplained_gaps_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            clean = root / "clean.zip"
            with zipfile.ZipFile(clean, "w") as archive:
                archive.writestr("clean.bin", b"clean")
            clean_bytes = clean.read_bytes()

            clean_block = root / "clean-signing.apk"
            clean_block.write_bytes(
                _insert_pre_central_directory(
                    clean_bytes, _apk_signing_block(b"ok-signature")
                )
            )
            obfuscation.verify_release_artifact_hardening("windows", [clean_block])
            labels = [label for label, _ in obfuscation.iter_artifact_blobs(clean_block)]
            self.assertTrue(
                any(label.endswith("!/<apk-signing-block>") for label in labels)
            )

            leaked = root / "leaked-signing.apk"
            leaked.write_bytes(
                _insert_pre_central_directory(
                    clean_bytes, _apk_signing_block(b"WinnV3StagedStart")
                )
            )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "sensitive internal class identifier"
            ):
                obfuscation.verify_release_artifact_hardening("windows", [leaked])

            credential = root / "credential-signing.apk"
            credential.write_bytes(
                _insert_pre_central_directory(
                    clean_bytes, _apk_signing_block(b"AIza" + b"A" * 35)
                )
            )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "google_api_key"
            ):
                obfuscation.verify_release_artifact_hardening(
                    "windows", [credential]
                )

            gapped = root / "interior-gap.zip"
            gapped.write_bytes(
                _insert_pre_central_directory(
                    clean_bytes, b"not-an-apk-signing-block"
                )
            )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "unexplained interior"
            ):
                list(obfuscation.iter_artifact_blobs(gapped))

    def test_tar_post_end_nonzero_bytes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = pathlib.Path(temp_name) / "trailed.tar"
            with tarfile.open(artifact, "w") as archive:
                info = tarfile.TarInfo("clean.bin")
                info.size = 5
                archive.addfile(info, io.BytesIO(b"clean"))
            with artifact.open("ab") as handle:
                handle.write(b"WinnV3StagedStart")
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "non-zero data after its end marker",
            ):
                list(obfuscation.iter_artifact_blobs(artifact))

    def test_bzip2_and_xz_tar_aliases_scan_clean_and_reject_trailers(self) -> None:
        aliases = (
            (".tar.bz2", "w:bz2"),
            (".tbz2", "w:bz2"),
            (".tar.xz", "w:xz"),
            (".txz", "w:xz"),
        )
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            for suffix, mode in aliases:
                with self.subTest(suffix=suffix):
                    clean = root / f"clean{suffix}"
                    with tarfile.open(clean, mode) as archive:
                        payload = b"clean"
                        info = tarfile.TarInfo("a")
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
                    list(obfuscation.iter_artifact_blobs(clean))
                    obfuscation.verify_release_artifact_hardening("linux", [clean])

                    contaminated = root / f"contaminated{suffix}"
                    with tarfile.open(contaminated, mode) as archive:
                        payload = b"WinnV3StagedStart"
                        info = tarfile.TarInfo("a")
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError,
                        "sensitive internal class identifier",
                    ):
                        obfuscation.verify_release_artifact_hardening(
                            "linux", [contaminated]
                        )

                    trailed = root / f"trailed{suffix}"
                    trailed.write_bytes(clean.read_bytes() + b"WinnV3StagedStart")
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError,
                        "trailing bytes after its compressed stream",
                    ):
                        list(obfuscation.iter_artifact_blobs(trailed))

    def test_malformed_zstandard_named_tar_archives_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            for suffix in (".tar.zst", ".tzst"):
                with self.subTest(suffix=suffix):
                    artifact = root / f"malformed{suffix}"
                    artifact.write_bytes(b"not a zstandard TAR archive")
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError,
                        "Invalid release tar archive",
                    ):
                        list(obfuscation.iter_artifact_blobs(artifact))

    def test_zstd_named_tar_archives_are_scanned_or_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            supported = _zstd_tar_supported()
            for suffix in (".tar.zst", ".tzst"):
                with self.subTest(suffix=suffix, supported=supported):
                    clean = root / f"clean{suffix}"
                    if not supported:
                        clean.write_bytes(b"(\xb5/\xfdnot a supported zstd tar")
                        with self.assertRaisesRegex(
                            obfuscation.ObfuscationError,
                            "Invalid release tar archive|cannot be inspected",
                        ):
                            list(obfuscation.iter_artifact_blobs(clean))
                        continue
                    with tarfile.open(clean, "w:zst") as archive:
                        payload = b"clean"
                        info = tarfile.TarInfo("a")
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
                    list(obfuscation.iter_artifact_blobs(clean))
                    obfuscation.verify_release_artifact_hardening("linux", [clean])

                    contaminated = root / f"contaminated{suffix}"
                    with tarfile.open(contaminated, "w:zst") as archive:
                        payload = b"WinnV3StagedStart"
                        info = tarfile.TarInfo("a")
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError,
                        "sensitive internal class identifier",
                    ):
                        obfuscation.verify_release_artifact_hardening(
                            "linux", [contaminated]
                        )

                    trailed = root / f"trailed{suffix}"
                    trailed.write_bytes(clean.read_bytes() + b"WinnV3StagedStart")
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError,
                        "trailing bytes after its compressed stream",
                    ):
                        list(obfuscation.iter_artifact_blobs(trailed))

    def test_zip_comment_and_nested_tar_pax_reject_google_credentials(self) -> None:
        google_key = b"AIza" + (b"A" * 35)
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            zip_artifact = root / "archive-comment.zip"
            with zipfile.ZipFile(zip_artifact, "w") as archive:
                archive.comment = google_key
                archive.writestr("clean.bin", b"clean")
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "google_api_key"
            ):
                obfuscation.verify_release_artifact_hardening(
                    "windows", [zip_artifact]
                )

            nested_tar = io.BytesIO()
            with tarfile.open(
                fileobj=nested_tar, mode="w:gz", format=tarfile.PAX_FORMAT
            ) as archive:
                payload = b"clean"
                info = tarfile.TarInfo("clean.bin")
                info.size = len(payload)
                info.pax_headers = {"comment": google_key.decode("ascii")}
                archive.addfile(info, io.BytesIO(payload))
            outer = root / "nested-pax.zip"
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr("payload/opaque.bin", nested_tar.getvalue())
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "google_api_key"
            ):
                obfuscation.verify_release_artifact_hardening("windows", [outer])

            global_pax = root / "global-pax.tar"
            with tarfile.open(
                global_pax,
                "w",
                format=tarfile.PAX_FORMAT,
                pax_headers={"comment": google_key.decode("ascii")},
            ) as archive:
                payload = b"clean"
                info = tarfile.TarInfo("clean.bin")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "google_api_key"
            ):
                obfuscation.verify_release_artifact_hardening(
                    "windows", [global_pax]
                )

    def test_nested_tar_in_zip_archive_comment_is_scanned_and_depth_bounded(self) -> None:
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode="w:gz") as archive:
            payload = b"WinnV3StagedStart"
            info = tarfile.TarInfo("clean.bin")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = pathlib.Path(temp_name) / "comment.zip"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.comment = inner.getvalue()
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "sensitive internal class identifier"
            ):
                obfuscation.verify_release_artifact_hardening("windows", [artifact])
            with mock.patch.object(
                obfuscation, "MAX_ARCHIVE_RECURSION_DEPTH", 0
            ):
                with self.assertRaisesRegex(
                    obfuscation.ObfuscationError, "recursion limit"
                ):
                    list(obfuscation.iter_artifact_blobs(artifact))

    def test_zip_trailing_slash_member_with_payload_is_inspected(self) -> None:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("clean.bin", b"WinnV3StagedStart")
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = pathlib.Path(temp_name) / "slash-payload.zip"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("hidden/", inner.getvalue())
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "sensitive internal class identifier"
            ):
                obfuscation.verify_release_artifact_hardening("windows", [artifact])

    def test_metadata_only_zip_and_tar_members_consume_member_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            zip_artifact = root / "directories.zip"
            with zipfile.ZipFile(zip_artifact, "w") as archive:
                archive.mkdir("one/")
                archive.mkdir("two/")

            tar_artifact = root / "directories.tar"
            with tarfile.open(tar_artifact, "w") as archive:
                for name in ("one/", "two/"):
                    info = tarfile.TarInfo(name)
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)

            pax_artifact = root / "pax-metadata.tar"
            with tarfile.open(
                pax_artifact, "w", format=tarfile.PAX_FORMAT
            ) as archive:
                payload = b"clean"
                info = tarfile.TarInfo("clean.bin")
                info.size = len(payload)
                info.pax_headers = {"comment": "clean metadata"}
                archive.addfile(info, io.BytesIO(payload))

            for artifact in (zip_artifact, tar_artifact, pax_artifact):
                with self.subTest(artifact=artifact.name):
                    with mock.patch.object(
                        obfuscation, "MAX_ARCHIVE_MEMBER_COUNT", 1
                    ):
                        with self.assertRaisesRegex(
                            obfuscation.ObfuscationError, "member-count limit"
                        ):
                            list(obfuscation.iter_artifact_blobs(artifact))

    def test_top_level_directory_files_consume_member_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            (root / "one.bin").write_bytes(b"one")
            (root / "two.bin").write_bytes(b"two")
            with mock.patch.object(obfuscation, "MAX_ARCHIVE_MEMBER_COUNT", 1):
                with self.assertRaisesRegex(
                    obfuscation.ObfuscationError, "member-count limit"
                ):
                    list(obfuscation.iter_artifact_blobs(root))

    def test_archive_metadata_fields_are_size_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = pathlib.Path(temp_name) / "comment.zip"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.comment = b"12345"
                archive.writestr("clean.bin", b"clean")
            with mock.patch.object(
                obfuscation, "MAX_ARCHIVE_METADATA_FIELD_BYTES", 4
            ):
                with self.assertRaisesRegex(
                    obfuscation.ObfuscationError, "metadata field exceeds"
                ):
                    list(obfuscation.iter_artifact_blobs(artifact))

    def test_malformed_named_top_level_archives_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            for suffix in (
                *obfuscation.ZIP_ARCHIVE_SUFFIXES,
                *obfuscation.TAR_ARCHIVE_SUFFIXES,
            ):
                with self.subTest(suffix=suffix):
                    artifact = root / f"malformed{suffix}"
                    artifact.write_bytes(b"not an archive")
                    expected = (
                        "zip archive"
                        if suffix in obfuscation.ZIP_ARCHIVE_SUFFIXES
                        else "tar archive"
                    )
                    with self.assertRaisesRegex(
                        obfuscation.ObfuscationError, f"Invalid release {expected}"
                    ):
                        list(obfuscation.iter_artifact_blobs(artifact))

            ordinary = root / "notes.txt"
            ordinary.write_bytes(b"not an archive")
            self.assertEqual(
                list(obfuscation.iter_artifact_blobs(ordinary)),
                [("notes.txt", b"not an archive")],
            )

    def test_static_contract_preserves_readable_chrome_extension_sources(self) -> None:
        contract = self.read("tools/release_obfuscation_contract.py")
        for required in (
            '"extension/build.py"',
            "byte-identical copy of",
            "No dependencies",
            "javascript-obfuscator",
            "--minify",
            "Chrome forbids",
        ):
            self.assertIn(required, contract)
        extension_builder = self.read("extension/build.py")
        for forbidden in (
            "javascript-obfuscator",
            "--minify",
            "--obfuscate",
        ):
            self.assertNotIn(forbidden, extension_builder)

    def test_archive_walk_is_bounded_by_input_member_expansion_and_ratio(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)

            oversized_archive = root / "oversized.zip"
            with zipfile.ZipFile(oversized_archive, "w") as archive:
                archive.writestr("clean.txt", b"clean")
            with mock.patch.object(
                obfuscation, "MAX_ARCHIVE_INPUT_BYTES", oversized_archive.stat().st_size - 1
            ):
                with self.assertRaisesRegex(obfuscation.ObfuscationError, "input-size limit"):
                    list(obfuscation.iter_artifact_blobs(oversized_archive))

            too_many = root / "too-many.zip"
            with zipfile.ZipFile(too_many, "w") as archive:
                archive.writestr("one.txt", b"1")
                archive.writestr("two.txt", b"2")
            with mock.patch.object(obfuscation, "MAX_ARCHIVE_MEMBER_COUNT", 1):
                with self.assertRaisesRegex(obfuscation.ObfuscationError, "member-count limit"):
                    list(obfuscation.iter_artifact_blobs(too_many))

            oversized_member = root / "oversized-member.zip"
            with zipfile.ZipFile(oversized_member, "w") as archive:
                archive.writestr("member.bin", b"12345")
            with mock.patch.object(
                obfuscation, "MAX_ARCHIVE_MEMBER_EXPANDED_BYTES", 4
            ):
                with self.assertRaisesRegex(obfuscation.ObfuscationError, "expanded-size limit"):
                    list(obfuscation.iter_artifact_blobs(oversized_member))

            oversized_total = root / "oversized-total.zip"
            with zipfile.ZipFile(oversized_total, "w") as archive:
                archive.writestr("one.bin", b"123456")
                archive.writestr("two.bin", b"123456")
            with mock.patch.object(
                obfuscation, "MAX_ARCHIVE_TOTAL_EXPANDED_BYTES", 10
            ):
                with self.assertRaisesRegex(
                    obfuscation.ObfuscationError, "cumulative expanded-size limit"
                ):
                    list(obfuscation.iter_artifact_blobs(oversized_total))

            compressed = root / "compressed.zip"
            with zipfile.ZipFile(
                compressed, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                archive.writestr("compressible.bin", b"A" * 4096)
            with mock.patch.object(obfuscation, "MAX_ARCHIVE_COMPRESSION_RATIO", 2):
                with self.assertRaisesRegex(obfuscation.ObfuscationError, "compression-ratio limit"):
                    list(obfuscation.iter_artifact_blobs(compressed))

    def test_archive_walk_rejects_excessive_nested_recursion(self) -> None:
        payload = b"clean"
        for index in range(3):
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr(f"level-{index}.zip", payload)
            payload = nested.getvalue()
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = pathlib.Path(temp_name) / "outer.zip"
            artifact.write_bytes(payload)
            with mock.patch.object(obfuscation, "MAX_ARCHIVE_RECURSION_DEPTH", 1):
                with self.assertRaisesRegex(obfuscation.ObfuscationError, "recursion limit"):
                    list(obfuscation.iter_artifact_blobs(artifact))

    def test_internal_identifier_probe_preserves_public_abi_and_token_boundaries(self) -> None:
        clean = b"\x00".join(sorted(obfuscation.REQUIRED_PUBLIC_PLATFORM_SYMBOLS))
        obfuscation.reject_sensitive_internal_identifiers(
            "android-aab", "base/dex/classes.dex", clean
        )
        for payload in (
            b"PrefixWinnV3StagedStartSuffix",
            b"protectOrRollback2",
            b"_WinnV3Keys_private",
        ):
            with self.subTest(payload=payload):
                obfuscation.reject_sensitive_internal_identifiers(
                    "windows", "payload.bin", payload
                )

    def test_android_store_only_mapping_metadata_is_not_customer_blob_scanned(self) -> None:
        obfuscation.reject_sensitive_internal_identifiers(
            "android-aab",
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            b"WinnV3StagedStart -> a",
        )

    def test_artifact_and_directory_member_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            real = root / "real.zip"
            with zipfile.ZipFile(real, "w") as archive:
                archive.writestr("assets/clean.txt", b"clean")
            linked = root / "linked.zip"
            linked.symlink_to(real)
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "symlink"):
                obfuscation.inspect_artifacts([linked])

            payload = root / "payload"
            payload.mkdir()
            (payload / "real.bin").write_bytes(b"clean")
            (payload / "linked.bin").symlink_to(payload / "real.bin")
            with self.assertRaisesRegex(obfuscation.ObfuscationError, "symlink"):
                list(obfuscation.iter_artifact_blobs(payload))

    def test_v2_receipt_binds_contract_path_and_all_hardening_claims(self) -> None:
        stripped = obfuscation._minimal_elf64(".text", ".dynsym")
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            private_root = (root / "private-release-symbols").resolve()
            symbols = private_root / "android-apk" / "1.0.15+30"
            symbols.mkdir(parents=True)
            (symbols / "app.android-arm64.symbols").write_bytes(b"s" * 128)
            (symbols / "proguard-mapping.txt").write_bytes(
                b"# compiler: R8\n" + (b"com.example.Keep -> a:\n" * 160)
            )
            artifact = root / "app-release.apk"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", stripped)
            manifest = symbols / "manifest.json"
            with mock.patch.object(obfuscation, "PRIVATE_SYMBOL_ROOT", private_root):
                obfuscation.record("android-apk", symbols, manifest, [artifact])
                payload = json.loads(manifest.read_text(encoding="utf-8"))
                self.assertEqual(payload["schema_version"], 2)
                self.assertEqual(
                    payload["contract"],
                    "winsvpn-release-obfuscation-and-secret-free-v2",
                )
                self.assertEqual(
                    payload["contract_sha256"],
                    obfuscation.sha256_file(obfuscation.CONTRACT_PATH),
                )
                self.assertEqual(
                    payload["verification"],
                    obfuscation._receipt_verification("android-apk"),
                )
                self.assertTrue(payload["verification"]["android_r8_minify_required"])
                self.assertTrue(payload["verification"]["private_r8_mapping_verified"])
                self.assertTrue(payload["verification"]["split_debug_info_flag_required"])
                obfuscation.verify("android-apk", manifest, symbols, [artifact])

                # The artifact identity is the ordered size and SHA-256 tuple;
                # the recorded path is provenance only, so a byte-identical
                # copy verifies and a different valid archive is refused.
                copied = root / "copied-release.apk"
                shutil.copyfile(artifact, copied)
                obfuscation.verify("android-apk", manifest, symbols, [copied])
                altered = root / "altered-release.apk"
                with zipfile.ZipFile(altered, "w") as archive:
                    archive.writestr("lib/arm64-v8a/libapp.so", stripped)
                    archive.writestr("assets/clean.txt", b"clean")
                with self.assertRaisesRegex(
                    obfuscation.ObfuscationError, "Exact artifact"
                ):
                    obfuscation.verify("android-apk", manifest, symbols, [altered])

                same_size = root / "same-size-release.apk"
                with zipfile.ZipFile(artifact) as original:
                    info = original.getinfo("lib/arm64-v8a/libapp.so")
                info.external_attr ^= 0o100 << 16
                with zipfile.ZipFile(same_size, "w") as archive:
                    archive.writestr(info, stripped)
                self.assertEqual(same_size.stat().st_size, artifact.stat().st_size)
                self.assertNotEqual(
                    obfuscation.sha256_file(same_size),
                    obfuscation.sha256_file(artifact),
                )
                with self.assertRaisesRegex(
                    obfuscation.ObfuscationError, "Exact artifact"
                ):
                    obfuscation.verify("android-apk", manifest, symbols, [same_size])

                payload["schema_version"] = 1
                manifest.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(
                    obfuscation.ObfuscationError, "schema is invalid"
                ):
                    obfuscation.verify("android-apk", manifest, symbols, [artifact])

    def test_reusable_secret_rejection_requires_distributable_removal(self) -> None:
        stripped = obfuscation._minimal_elf64(".text")
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            secret_apk = root / "secret.apk"
            with zipfile.ZipFile(secret_apk, "w") as archive:
                archive.writestr(
                    "lib/arm64-v8a/libxray.so",
                    stripped + b"-----BEGIN OPENSSH PRIVATE KEY-----",
                )
            with self.assertRaises(privacy.PrivacyError) as raised:
                privacy.validate_artifacts((secret_apk,), {})
            message = str(raised.exception)
            self.assertIn("private_key_material", message)
            self.assertIn("remove the credential", message)
            token_apk = root / "token.apk"
            with zipfile.ZipFile(token_apk, "w") as archive:
                archive.writestr(
                    "assets/config.bin",
                    b"glpat-" + b"B" * 20,
                )
            with self.assertRaises(privacy.PrivacyError) as raised:
                privacy.validate_artifacts((token_apk,), {})
            self.assertIn("remove the credential", str(raised.exception))



if __name__ == "__main__":
    unittest.main()
