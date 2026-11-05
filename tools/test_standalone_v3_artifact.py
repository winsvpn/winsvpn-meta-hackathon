#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
import base64
import hashlib


ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tools" / "verify_standalone_v3_artifact.py"
ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")
ENGINES = ("libam-go.so", "libwinnengine.so")
ELF_ABIS = {
    "arm64-v8a": (2, 183),
    "armeabi-v7a": (1, 40),
    "x86_64": (2, 62),
}
V1_ENGINE_STARTS = ("startWinnEngineThread(", "startAwgEngineThread(")


def _brace_block(source: str, start: int) -> str:
    open_at = source.index("{", start)
    depth = 0
    for index, char in enumerate(source[open_at:], open_at):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise ValueError("unbalanced braces")


def android_on_start_command(service: str) -> str:
    start = service.index("override fun onStartCommand(")
    end = service.index("\n    private fun persistRestartConfig(", start)
    return service[start:end]


def android_v3_first_errors(service: str) -> list[str]:
    errors: list[str] = []
    try:
        on_start = android_on_start_command(service)
    except ValueError:
        return ["onStartCommand is missing"]
    call_at = on_start.find("startWinnV3EngineThread(")
    if call_at < 0:
        return ["onStartCommand does not call startWinnV3EngineThread"]
    branch_at = on_start.rfind("if (winn3Requested) {", 0, call_at)
    if branch_at < 0:
        return ["startWinnV3EngineThread is not inside if (winn3Requested)"]
    try:
        branch = _brace_block(on_start, branch_at)
    except ValueError as exc:
        return [str(exc)]
    if "return START_STICKY" not in branch:
        errors.append("v3 branch does not return START_STICKY before v1")
    sticky_at = branch.find("return START_STICKY")
    for v1 in V1_ENGINE_STARTS:
        if v1 in branch:
            errors.append(f"v3 branch starts {v1[:-1]}")
        v1_at = on_start.find(v1)
        if v1_at >= 0 and v1_at < call_at:
            errors.append(f"{v1[:-1]} precedes startWinnV3EngineThread")
        if sticky_at >= 0 and v1_at >= 0 and v1_at < branch_at + sticky_at:
            errors.append(f"{v1[:-1]} precedes v3 return START_STICKY")
    identity_at = on_start.find(
        "winn3StartToken <= 0L || winn3StartGeneration <= 0L"
    )
    if identity_at < 0:
        errors.append("v3 identity fail-closed check is missing")
    elif identity_at > call_at:
        errors.append("v3 identity check no longer precedes startWinnV3EngineThread")
    return errors


WEAR_JNI_PAYLOAD_MARKERS = (
    "jniLibs.srcDirs",
    "jniLibs.srcDir(",
    "src/main/jniLibs",
    "src/debug/jniLibs",
    "src/release/jniLibs",
    "src/profile/jniLibs",
)
WEAR_ENGINE_BINARY_NAMES = (
    "libwinnengine.so",
    "libam-go.so",
    "libam.so",
    "libam-quick.so",
    "libxray.so",
    "amneziawg.aar",
    "amneziawg.exe",
    "xray.exe",
)
_WEAR_PLAY_16KIB_JNI = re.compile(
    r"packaging\s*\{\s*jniLibs\s*\{\s*useLegacyPackaging\s*=\s*false\s*\}\s*\}",
    re.DOTALL,
)
_WEAR_FILES_PAYLOAD = re.compile(
    r"""files\s*\(\s*['"](?:[^'"]*[\\/])?(?P<name>%s)['"]"""
    % "|".join(re.escape(name) for name in WEAR_ENGINE_BINARY_NAMES)
)
NESTED_WINN3_GATEWAY_IGNORE_RULES = (
    "/winn_protocol_experimental/winn3-gateway",
    "/winn_protocol_experimental/winn3-gateway.exe",
)
NESTED_WINN3_GATEWAY_IGNORED_PATHS = (
    "winn_protocol_experimental/winn3-gateway",
    "winn_protocol_experimental/winn3-gateway.exe",
)
NESTED_WINN3_GATEWAY_TRACKED_PATHS = (
    "winn_protocol_experimental/cmd/winn3-gateway/main.go",
    "winn_protocol_experimental/cmd/winn3-gateway",
    "winn_protocol_experimental/deploy/systemd/winn3-gateway.service",
    "winn_protocol_experimental/winn3-gateway.sha256",
    "winn_protocol_experimental/winn3-gateway.provenance.json",
    "winn_protocol_experimental/winn3-gateway.exe.sha256",
    "winn_protocol_experimental/winn3-gateway.exe.provenance.json",
    "winn_protocol_experimental/dist/winn3-gateway-linux-amd64",
    "winn_protocol_experimental/winn-auto-e2e.source.sha256",
)
_OVERBROAD_GATEWAY_IGNORE = re.compile(
    r"^(?:\*\*/)?winn3-gateway(?:\.exe)?(?:\*.*)?$"
    r"|^/?winn_protocol_experimental/winn3-gateway\*"
)


def wear_has_play_16kib_jni_packaging(gradle: str) -> bool:
    return _WEAR_PLAY_16KIB_JNI.search(gradle) is not None


def wear_jni_payload_errors(gradle: str) -> list[str]:
    errors: list[str] = []
    for marker in WEAR_JNI_PAYLOAD_MARKERS:
        if marker in gradle:
            errors.append(f"native-library payload path {marker}")
    for name in WEAR_ENGINE_BINARY_NAMES:
        if re.search(rf"jniLibs/(?:[A-Za-z0-9._-]+/)*{re.escape(name)}", gradle):
            errors.append(f"jniLibs payload {name}")
        if f"**/{name}" in gradle:
            errors.append(f"native include payload {name}")
    for match in _WEAR_FILES_PAYLOAD.finditer(gradle):
        errors.append(f"files() payload {match.group('name')}")
    return errors


def wear_engine_payload_files(wear_root: pathlib.Path) -> list[str]:
    names = set(WEAR_ENGINE_BINARY_NAMES)
    hits: list[str] = []
    for relative in ("app/src", "app/libs"):
        base = wear_root / relative
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix == ".so" or path.name in names:
                hits.append(path.relative_to(wear_root).as_posix())
    return hits


def nested_winn3_gateway_ignore_errors(text: str) -> list[str]:
    active = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        active.append(stripped)
    present = set(active)
    errors: list[str] = []
    for rule in NESTED_WINN3_GATEWAY_IGNORE_RULES:
        if rule not in present:
            errors.append(f"missing exact anchored rule {rule}")
    for stripped in active:
        if stripped in NESTED_WINN3_GATEWAY_IGNORE_RULES:
            continue
        if stripped == "/winn3-gateway":
            continue
        if _OVERBROAD_GATEWAY_IGNORE.match(stripped):
            errors.append(f"over-broad ignore {stripped}")
    return errors


def git_check_ignore(relpath: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "check-ignore",
            "-v",
            "--no-index",
            "--",
            relpath,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def android_elf(
    abi: str,
    *,
    machine: int | None = None,
    alignment: int | None = None,
) -> bytes:
    elf_class, expected_machine = ELF_ABIS[abi]
    machine = expected_machine if machine is None else machine
    alignment = alignment if alignment is not None else (0x4000 if elf_class == 2 else 0x1000)
    if elf_class == 2:
        data = bytearray(64 + 56)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", data, 16, 3)
        struct.pack_into("<H", data, 18, machine)
        struct.pack_into("<I", data, 20, 1)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<H", data, 52, 64)
        struct.pack_into("<H", data, 54, 56)
        struct.pack_into("<H", data, 56, 1)
        struct.pack_into("<I", data, 64, 1)
        struct.pack_into("<I", data, 68, 5)
        struct.pack_into("<Q", data, 64 + 48, alignment)
    else:
        data = bytearray(52 + 32)
        data[:7] = b"\x7fELF\x01\x01\x01"
        struct.pack_into("<H", data, 16, 3)
        struct.pack_into("<H", data, 18, machine)
        struct.pack_into("<I", data, 20, 1)
        struct.pack_into("<I", data, 28, 52)
        struct.pack_into("<H", data, 40, 52)
        struct.pack_into("<H", data, 42, 32)
        struct.pack_into("<H", data, 44, 1)
        struct.pack_into("<I", data, 52, 1)
        struct.pack_into("<I", data, 52 + 28, alignment)
    return bytes(data)


class StandaloneV3ArtifactTest(unittest.TestCase):
    def run_gate(self, *artifacts: pathlib.Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VERIFIER), *(str(path) for path in artifacts)],
            check=False,
            capture_output=True,
            text=True,
        )

    def write_android(
        self,
        path: pathlib.Path,
        *,
        omit: tuple[str, str] | None = None,
        empty: tuple[str, str] | None = None,
        wrong_machine: tuple[str, str] | None = None,
        page_alignment: tuple[str, str, int] | None = None,
        extra_member: str | None = None,
    ) -> None:
        prefix = "base/lib" if path.suffix == ".aab" else "lib"
        with zipfile.ZipFile(path, "w") as archive:
            for abi in ABIS:
                for engine in ENGINES:
                    if omit == (abi, engine):
                        continue
                    if empty == (abi, engine):
                        payload = b""
                    else:
                        machine = 62 if wrong_machine == (abi, engine) else None
                        alignment = (
                            page_alignment[2]
                            if page_alignment and page_alignment[:2] == (abi, engine)
                            else None
                        )
                        payload = android_elf(abi, machine=machine, alignment=alignment)
                    archive.writestr(f"{prefix}/{abi}/{engine}", payload)
            if extra_member:
                archive.writestr(extra_member, b"unexpected")

    def test_accepts_clean_android_apk_and_aab(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            apk, aab = root / "app.apk", root / "app.aab"
            self.write_android(apk)
            self.write_android(aab)
            self.assertEqual(self.run_gate(apk, aab).returncode, 0)

    def test_requires_every_android_engine_for_every_declared_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for abi in ABIS:
                for engine in ENGINES:
                    with self.subTest(abi=abi, engine=engine):
                        artifact = root / f"missing-{abi}-{engine}.apk"
                        self.write_android(artifact, omit=(abi, engine))
                        result = self.run_gate(artifact)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(f"lib/{abi}/{engine}", result.stderr)

    def test_rejects_empty_duplicate_and_out_of_inventory_android_engines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            empty = root / "empty.apk"
            self.write_android(empty, empty=("arm64-v8a", "libam-go.so"))
            empty_result = self.run_gate(empty)
            self.assertNotEqual(empty_result.returncode, 0)
            self.assertIn("lib/arm64-v8a/libam-go.so", empty_result.stderr)

            duplicate = root / "duplicate.apk"
            self.write_android(duplicate)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate, "a") as archive:
                    archive.writestr("lib/arm64-v8a/libam-go.so", b"duplicate")
            duplicate_result = self.run_gate(duplicate)
            self.assertNotEqual(duplicate_result.returncode, 0)
            self.assertIn("copies=2", duplicate_result.stderr)

            extra = root / "extra-abi.apk"
            self.write_android(extra, extra_member="lib/x86/libwinnengine.so")
            extra_result = self.run_gate(extra)
            self.assertNotEqual(extra_result.returncode, 0)
            self.assertIn("lib/x86/libwinnengine.so", extra_result.stderr)

    def test_rejects_obsolete_android_engine_variants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            # libxray.so is forbidden too: Android refuses Xray mode and the
            # Gradle packaging excludes it, so a package carrying it is wrong.
            for engine in ("libam-quick.so", "libam.so", "libxray.so"):
                with self.subTest(engine=engine):
                    artifact = root / f"forbidden-{engine}.apk"
                    self.write_android(
                        artifact,
                        extra_member=f"lib/arm64-v8a/{engine}",
                    )
                    result = self.run_gate(artifact)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(engine, result.stderr)

    def test_rejects_wrong_elf_abi_and_64_bit_page_alignment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            wrong_abi = root / "wrong-abi.apk"
            self.write_android(
                wrong_abi,
                wrong_machine=("arm64-v8a", "libwinnengine.so"),
            )
            wrong_abi_result = self.run_gate(wrong_abi)
            self.assertNotEqual(wrong_abi_result.returncode, 0)
            self.assertIn("e_machine 62", wrong_abi_result.stderr)
            self.assertIn("requires 183", wrong_abi_result.stderr)

            four_k_page = root / "four-k-page.apk"
            self.write_android(
                four_k_page,
                page_alignment=("x86_64", "libam-go.so", 0x1000),
            )
            four_k_result = self.run_gate(four_k_page)
            self.assertNotEqual(four_k_result.returncode, 0)
            self.assertIn("not compatible with 16 KB Android pages", four_k_result.stderr)

    def test_android_inventory_reports_all_engine_hashes_and_sizes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = pathlib.Path(temporary) / "app.apk"
            self.write_android(artifact)
            result = self.run_gate(artifact)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [
                line
                for line in result.stdout.splitlines()
                if line.startswith("ANDROID ENGINE INVENTORY:")
            ]
            self.assertEqual(len(rows), len(ABIS) * len(ENGINES))
            for abi in ABIS:
                for engine in ENGINES:
                    matching = [row for row in rows if f"abi={abi} engine={engine}" in row]
                    self.assertEqual(len(matching), 1)
                    self.assertRegex(matching[0], r" bytes=[1-9][0-9]* sha256=[0-9a-f]{64}$")

    def test_apple_gate_requires_primary_and_fallback_frameworks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            frameworks = (
                "WinsAmneziaWGPacketEngine",
                "WinsWinnPacketEngine",
                "WinsXrayVlessWsTransport",
            )
            clean = root / "clean.ipa"
            with zipfile.ZipFile(clean, "w") as archive:
                for framework in frameworks:
                    archive.writestr(
                        "Payload/Runner.app/Frameworks/"
                        f"{framework}.framework/{framework}",
                        framework.encode("ascii"),
                    )
            self.assertEqual(self.run_gate(clean).returncode, 0)

            for missing in frameworks:
                with self.subTest(missing=missing):
                    bad = root / f"missing-{missing}.ipa"
                    with zipfile.ZipFile(bad, "w") as archive:
                        for framework in frameworks:
                            if framework == missing:
                                continue
                            archive.writestr(
                                "Payload/Runner.app/Frameworks/"
                                f"{framework}.framework/{framework}",
                                framework.encode("ascii"),
                            )
                    result = self.run_gate(bad)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"{missing}.framework", result.stderr)

    def test_release_producers_package_dual_engines_and_content_gate(self) -> None:
        gradle = (ROOT / "android/app/build.gradle.kts").read_text()
        macos_builder = (ROOT / "tools/build_android_release_macos.sh").read_text()
        windows_builder = (ROOT / "tools/build_android_release.ps1").read_text()
        packaging = gradle[gradle.index("packaging {") : gradle.index("lint {")]
        self.assertNotIn('"**/libam-go.so"', packaging)
        # Android refuses Xray mode (VpnTunnelService.kt), so libxray.so is
        # excluded from packaging and the release engine inputs are Winn v3
        # plus the bulk tun reader. The artifact gates require exactly
        # libwinnengine.so and libam-go.so and forbid libxray.so.
        self.assertIn('"**/libxray.so"', packaging)
        self.assertIn('listOf("libwinnengine.so", "libwinn_tun_bulk.so")', gradle)
        self.assertIn('"jni/$abi/libam-go.so"', gradle)
        self.assertIn("verifyAndroidReleaseEngineInputs()", gradle)
        # OI-13 (Round 36 treaty): the gate must validate the source-set
        # WINNER (src/release shadows src/main, resolved without following
        # links), not accept any safe candidate.
        gate_body = gradle[gradle.index("fun verifyAndroidReleaseEngineInputs()") : gradle.index("fun verifyAndroidReleaseAwgArchive") if "fun verifyAndroidReleaseAwgArchive" in gradle else gradle.index("fun verifyAndroidReleaseEngineInputs()") + 3000]
        self.assertIn("NOFOLLOW_LINKS", gate_body)
        self.assertNotIn("candidates.none(::isSafeNonEmptyReleaseInput)", gate_body)
        self.assertIn("selected", gate_body)
        self.assertNotIn("WINS_STANDALONE_V3_RELEASE=1", macos_builder)
        self.assertIn('"${WINN_ENGINE_SOURCE_GATE}" --verify', macos_builder)
        self.assertIn("verify_standalone_v3_artifact.py", macos_builder)
        self.assertNotIn("$env:WINS_STANDALONE_V3_RELEASE = '1'", windows_builder)
        self.assertIn("'--verify'", windows_builder)
        self.assertIn("verify_standalone_v3_artifact.py", windows_builder)

    def test_wear_release_is_a_non_standalone_remote_control_not_a_second_vpn(self) -> None:
        manifest = (ROOT / "wear_os/app/src/main/AndroidManifest.xml").read_text()
        gradle = (ROOT / "wear_os/app/build.gradle.kts").read_text()
        phone_gradle = (ROOT / "android/app/build.gradle.kts").read_text()

        self.assertIn('android:name="com.google.android.wearable.standalone"', manifest)
        self.assertIn('android:value="false"', manifest)
        self.assertNotIn('android.permission.INTERNET', manifest)
        self.assertTrue(wear_has_play_16kib_jni_packaging(gradle))
        self.assertIn("jniLibs", gradle)
        self.assertEqual(wear_jni_payload_errors(gradle), [])
        self.assertEqual(wear_engine_payload_files(ROOT / "wear_os"), [])
        self.assertIn('applicationId = "org.winsvpn.app"', gradle)
        self.assertIn('applicationId = "org.winsvpn.app"', phone_gradle)

    def test_wear_jni_packaging_policy_is_not_an_engine_payload(self) -> None:
        gradle = (ROOT / "wear_os/app/build.gradle.kts").read_text()
        self.assertTrue(wear_has_play_16kib_jni_packaging(gradle))
        self.assertEqual(wear_jni_payload_errors(gradle), [])

        no_policy = gradle.replace(
            "            useLegacyPackaging = false\n",
            "            useLegacyPackaging = true\n",
            1,
        )
        self.assertNotEqual(no_policy, gradle)
        self.assertFalse(wear_has_play_16kib_jni_packaging(no_policy))
        self.assertEqual(wear_jni_payload_errors(no_policy), [])

        src_dirs = gradle + '\n            jniLibs.srcDirs += files("src/main/jniLibs")\n'
        src_dir_errors = wear_jni_payload_errors(src_dirs)
        self.assertIn("native-library payload path jniLibs.srcDirs", src_dir_errors)
        self.assertIn("native-library payload path src/main/jniLibs", src_dir_errors)

        src_dir = gradle + '\n            jniLibs.srcDir("src/debug/jniLibs")\n'
        src_dir_only = wear_jni_payload_errors(src_dir)
        self.assertIn("native-library payload path jniLibs.srcDir(", src_dir_only)
        self.assertIn("native-library payload path src/debug/jniLibs", src_dir_only)

        engine_path = gradle + '\n            jniLibs/arm64-v8a/libwinnengine.so\n'
        self.assertIn("jniLibs payload libwinnengine.so", wear_jni_payload_errors(engine_path))

        include_xray = gradle + '\n            include("**/libxray.so")\n'
        self.assertIn("native include payload libxray.so", wear_jni_payload_errors(include_xray))

        files_aar = gradle + '\n    implementation(files("libs/amneziawg.aar"))\n'
        self.assertIn("files() payload amneziawg.aar", wear_jni_payload_errors(files_aar))

        with tempfile.TemporaryDirectory() as temporary:
            wear_root = pathlib.Path(temporary)
            payload = wear_root / "app/src/main/jniLibs/arm64-v8a/libwinnengine.so"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"elf")
            aar = wear_root / "app/libs/amneziawg.aar"
            aar.parent.mkdir(parents=True)
            aar.write_bytes(b"aar")
            self.assertEqual(
                sorted(wear_engine_payload_files(wear_root)),
                [
                    "app/libs/amneziawg.aar",
                    "app/src/main/jniLibs/arm64-v8a/libwinnengine.so",
                ],
            )

    def test_nested_winn3_gateway_binaries_are_exactly_gitignored(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text()
        self.assertEqual(nested_winn3_gateway_ignore_errors(gitignore), [])
        for rule in NESTED_WINN3_GATEWAY_IGNORE_RULES:
            self.assertRegex(gitignore, rf"(?m)^{re.escape(rule)}$")

        # git check-ignore needs a repository; an exported tree reports the git
        # half as skipped instead of failing (or passing) for that reason
        # (R22 Y3-12).
        in_repository = (ROOT / ".git").exists()
        for relpath, rule in zip(
            NESTED_WINN3_GATEWAY_IGNORED_PATHS,
            NESTED_WINN3_GATEWAY_IGNORE_RULES,
        ):
            if not in_repository:
                break
            result = git_check_ignore(relpath)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f":{rule}\t", result.stdout)
            self.assertTrue(result.stdout.rstrip().endswith(relpath))

        for relpath in NESTED_WINN3_GATEWAY_TRACKED_PATHS:
            if not in_repository:
                break
            result = git_check_ignore(relpath)
            # 1 is "not ignored"; 128 is a git error and proves nothing.
            self.assertEqual(
                result.returncode,
                1,
                f"must remain unignored: {relpath}\n{result.stdout}{result.stderr}",
            )

        missing = "\n".join(
            line
            for line in gitignore.splitlines()
            if line not in NESTED_WINN3_GATEWAY_IGNORE_RULES
        )
        missing_errors = nested_winn3_gateway_ignore_errors(missing)
        self.assertEqual(len(missing_errors), 2)
        self.assertTrue(all(error.startswith("missing exact anchored rule ") for error in missing_errors))

        globbed = gitignore + "\n/winn_protocol_experimental/winn3-gateway*\n"
        self.assertIn(
            "over-broad ignore /winn_protocol_experimental/winn3-gateway*",
            nested_winn3_gateway_ignore_errors(globbed),
        )
        unanchored = gitignore + "\nwinn3-gateway\n"
        self.assertIn(
            "over-broad ignore winn3-gateway",
            nested_winn3_gateway_ignore_errors(unanchored),
        )
        if not in_repository:
            self.skipTest("git check-ignore half needs a git repository (exported tree)")

    def test_packaging_both_engines_does_not_open_an_implicit_v3_downgrade(self) -> None:
        service = (
            ROOT / "android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt"
        ).read_text()
        plan = (
            ROOT / "android/app/src/main/kotlin/org/winsvpn/app/WinnV3SessionPlan.kt"
        ).read_text()
        v1_builder = (
            ROOT / "android/app/src/main/kotlin/org/winsvpn/app/WinnEngineConfig.kt"
        ).read_text()

        selector = (
            "val winn3Requested = winnEnabled && "
            "WinnV3SessionPlan.isRequested(winnSection)"
        )
        self.assertIn(selector, service)
        on_start = android_on_start_command(service)
        call_at = on_start.index("startWinnV3EngineThread(")
        branch_at = on_start.rfind("if (winn3Requested) {", 0, call_at)
        v3_branch = _brace_block(on_start, branch_at)
        self.assertIn("startWinnV3EngineThread(", v3_branch)
        self.assertIn("return START_STICKY", v3_branch)
        self.assertNotIn("startWinnEngineThread(", v3_branch)
        self.assertNotIn("startAwgEngineThread(", v3_branch)
        self.assertLess(call_at, on_start.index("startWinnEngineThread("))
        self.assertLess(call_at, on_start.index("startAwgEngineThread("))
        self.assertLess(
            v3_branch.index("startWinnV3EngineThread("),
            v3_branch.index("return START_STICKY"),
        )
        self.assertEqual(android_v3_first_errors(service), [])
        self.assertIn(
            'if (raw.isEmpty() || raw == PROTOCOL_V3 || raw == "1") return null',
            plan,
        )
        self.assertIn("require(!WinnV3SessionPlan.isRequested(section))", v1_builder)
        self.assertIn("WinnV3SessionPlan.refuseUnknownProtocol(section)?.let", v1_builder)

    def test_v3_first_and_fail_closed_mutations_are_rejected(self) -> None:
        service = (
            ROOT / "android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt"
        ).read_text()
        self.assertEqual(android_v3_first_errors(service), [])

        no_return = service.replace(
            "            persistRestartConfig(config)\n            return START_STICKY\n        }\n\n        try {",
            "            persistRestartConfig(config)\n        }\n\n        try {",
            1,
        )
        self.assertNotEqual(no_return, service)
        self.assertTrue(android_v3_first_errors(no_return))

        v1_first = service.replace(
            "            startWinnV3EngineThread(",
            "            startWinnEngineThread(\n"
            "                winnSection, awgConfig, tunPfd, clientIp, dnsServer, mtu, 0,\n"
            "            )\n            startWinnV3EngineThread(",
            1,
        )
        self.assertNotEqual(v1_first, service)
        self.assertTrue(android_v3_first_errors(v1_first))

        no_v3 = service.replace("startWinnV3EngineThread(", "startWinnEngineThread(", 1)
        self.assertNotEqual(no_v3, service)
        self.assertTrue(android_v3_first_errors(no_v3))

        no_identity = service.replace(
            "            if (winn3StartToken <= 0L || winn3StartGeneration <= 0L) {\n",
            "            if (false) {\n",
            1,
        )
        self.assertNotEqual(no_identity, service)
        self.assertTrue(android_v3_first_errors(no_identity))

    def test_rollout_platform_and_key_gates_are_fail_closed(self) -> None:
        android_builder = (ROOT / "tools/build_android_release_macos.sh").read_text()
        self.assertIn('if [[ "${#defines[@]}" -gt 0 ]]', android_builder)
        self.assertIn('return 65', android_builder)

        ios_provider = (ROOT / "ios/PacketTunnel/PacketTunnelProvider.swift").read_text()
        carrier_guard = re.search(
            r"if !carrier\.isEmpty, carrier != WinsTunnelConfig\.supportedWinnCarrier \{"
            r"(.*?)guard let availableBytes",
            ios_provider,
            re.DOTALL,
        )
        self.assertIsNotNone(carrier_guard)
        self.assertIn("supportedWinnCarrierWinn3", carrier_guard.group(1))
        self.assertNotIn("#if DEBUG", carrier_guard.group(1))

        windows_builder = (ROOT / "installer/windows/build_installer.ps1").read_text()
        self.assertIn(
            "--dart-define=WINS_WINN3_ENABLED_PLATFORMS=windows",
            windows_builder,
        )
        windows_store_builder = (
            ROOT / "installer/windows/build_store_msix.ps1"
        ).read_text()
        self.assertIn(
            "--dart-define=WINS_WINN3_ENABLED_PLATFORMS=windows",
            windows_store_builder,
        )

        linux_builder = (ROOT / "tools/build_linux_release.sh").read_text()
        self.assertIn("WINS_WINN3_ENABLED_PLATFORMS=linux", linux_builder)

    def test_ring_identity_and_artifact_attestation_are_deterministic(self) -> None:
        raw = bytes(range(32))
        encoded = base64.b64encode(raw).decode("ascii")
        define = f"--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_G1={encoded}"
        expected = hashlib.sha256(f"g1={raw.hex()}\n".encode("ascii")).hexdigest()
        identity = subprocess.run(
            [sys.executable, str(ROOT / "tools/winn3_descriptor_ring_identity.py"), define],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(identity.returncode, 0, identity.stderr)
        self.assertEqual(identity.stdout.strip(), expected)

        with tempfile.TemporaryDirectory() as temporary:
            artifact = pathlib.Path(temporary) / "app.so"
            artifact.write_bytes(b"prefix" + expected.encode() + b"suffix")
            verified = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/verify_winn3_ring_artifact.py"),
                    expected,
                    str(artifact),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_ring_attestation_handles_raw_file_chunk_boundaries(self) -> None:
        identity = "0123456789abcdef" * 4
        verifier = ROOT / "tools/verify_winn3_ring_artifact.py"
        chunk_size = 1024 * 1024
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for offset in (
                chunk_size - len(identity),
                chunk_size - len(identity) + 1,
                chunk_size - 5,
                chunk_size,
                chunk_size + 1,
            ):
                with self.subTest(offset=offset):
                    artifact = root / f"app-{offset}.so"
                    artifact.write_bytes(
                        b"x" * offset + identity.encode("ascii") + b"suffix"
                    )
                    result = subprocess.run(
                        [sys.executable, str(verifier), identity, str(artifact)],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

            absent = root / "app-absent.so"
            absent.write_bytes(
                b"x" * (chunk_size - 5)
                + identity[:-1].encode("ascii")
                + b"Xsuffix"
            )
            absent_result = subprocess.run(
                [sys.executable, str(verifier), identity, str(absent)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(absent_result.returncode, 0)

    def test_ring_attestation_rejects_sidecar_only_directory_and_archive(self) -> None:
        identity = "a" * 64
        verifier = ROOT / "tools/verify_winn3_ring_artifact.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "app.so").write_bytes(b"compiled payload without identity")
            (root / "winn3-descriptor-ring-attestation.json").write_text(identity)
            directory_result = subprocess.run(
                [sys.executable, str(verifier), identity, str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(directory_result.returncode, 0)

            apk = root / "sidecar.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", b"compiled payload")
                archive.writestr("assets/ring-attestation.txt", identity)
            archive_result = subprocess.run(
                [sys.executable, str(verifier), identity, str(apk)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(archive_result.returncode, 0)

            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr(
                    "lib/arm64-v8a/libapp.so", b"compiled " + identity.encode()
                )
                archive.writestr("assets/ring-attestation.txt", b"not authoritative")
            compiled_result = subprocess.run(
                [sys.executable, str(verifier), identity, str(apk)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compiled_result.returncode, 0, compiled_result.stderr)

    def test_all_apple_build_configs_link_primary_and_fallback_engines(self) -> None:
        projects = (
            (ROOT / "ios/Runner.xcodeproj/project.pbxproj", "A1000000000000000000001"),
            (ROOT / "macos/Runner.xcodeproj/project.pbxproj", "B100000000000000000000"),
        )
        for path, prefix in projects:
            source = path.read_text()
            ids = {"Debug": f"{prefix}0", "Release": f"{prefix}1", "Profile": f"{prefix}2"}
            if path.parts[-3] == "macos":
                ids = {
                    "Debug": "B1000000000000000000000F",
                    "Release": "B10000000000000000000010",
                    "Profile": "B10000000000000000000011",
                }
            blocks = {}
            for configuration, identifier in ids.items():
                match = re.search(
                    rf"{identifier} /\* {configuration} \*/ = \{{(.*?)\n\t\t\}};",
                    source,
                    re.DOTALL,
                )
                self.assertIsNotNone(match, f"missing {configuration} block in {path}")
                blocks[configuration] = match.group(1)
            for fallback in ("-lWinsAmneziaWGPacketEngine", "-lWinsXrayVlessWsTransport"):
                for configuration, block in blocks.items():
                    self.assertIn(fallback, block, f"{path} {configuration}")

        stage = (ROOT / "tools/stage_apple_engine_artifacts.sh").read_text()
        candidate = (ROOT / "tools/build_apple_release_candidates.sh").read_text()
        release_components = stage.split(
            'if [[ "${WINS_APPLE_WINN3_RELEASE}" == "1" ]]; then', 1
        )[1].split("else", 1)[0]
        for component in (
            "amneziawg_packet_engine",
            "xray_vless_ws_transport",
            "winn_packet_engine",
        ):
            self.assertIn(f'"{component}"', release_components)
        self.assertIn('"${ALL_COMPONENTS[@]}"', stage)
        self.assertGreaterEqual(candidate.count("WINS_APPLE_WINN3_RELEASE=1"), 2)
        self.assertGreaterEqual(candidate.count("WINS_REQUIRE_APPLE_ENGINE=1"), 2)
        self.assertIn("verify_standalone_v3_artifact.py", candidate)


if __name__ == "__main__":
    unittest.main()
