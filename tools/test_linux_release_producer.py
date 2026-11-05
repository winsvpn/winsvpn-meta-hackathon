#!/usr/bin/env python3
"""Regression contracts for the receipt-owning Linux release producer."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import platform
import re
import shlex
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from tools.validate_release_artifact_privacy import validate_tar_metadata


SOURCE = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
INSTALLER = (ROOT / "linux/packaging/install.sh").read_text(encoding="utf-8")
PRODUCER = ROOT / "tools/build_linux_release.sh"


def synthetic_elf64(machine: int, *, elf_type: int = 2) -> bytes:
    """Return a structurally valid ELF64 fixture with an executable load segment."""

    data = bytearray(4096)
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    load_vaddr = 0x400000
    is_shared = elf_type == 3
    entry = 0 if is_shared else load_vaddr + 0x200
    phnum = 2 if is_shared else 1
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        elf_type,
        machine,
        1,
        entry,
        64,
        0,
        0,
        64,
        56,
        phnum,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        1,
        5,
        0,
        load_vaddr,
        load_vaddr,
        len(data),
        len(data),
        4096,
    )
    if is_shared:
        dynamic_offset = 0x300
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            64 + 56,
            2,
            6,
            dynamic_offset,
            load_vaddr + dynamic_offset,
            load_vaddr + dynamic_offset,
            16,
            16,
            8,
        )
        struct.pack_into("<QQ", data, dynamic_offset, 0, 0)
    if machine == 62:
        code = b"\x31\xff\xb8\x3c\x00\x00\x00\x0f\x05"
    elif machine == 183:
        code = b"\x00\x00\x80\xd2\xa8\x0b\x80\xd2\x01\x00\x00\xd4"
    else:
        code = b"\x00\x00\x00\x00"
    data[0x200 : 0x200 + len(code)] = code
    return bytes(data)


def write_executable(path: pathlib.Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o755)


def tarball_architecture_fixture(root: pathlib.Path, machine: int) -> None:
    for relative in (
        "wins_vpn",
        "winsvpn-bypass-bpf",
        "winn-datapath",
        "xray",
        "awg",
        "amneziawg-go",
        "tools/native_messaging/host/wins_bridge_host",
    ):
        write_executable(root / relative, synthetic_elf64(machine))
    write_executable(root / "awg-quick", b"#!/bin/sh\nexit 0\n")
    write_executable(root / "lib/libapp.so", synthetic_elf64(machine, elf_type=3))
    write_executable(root / "lib/libflutter_linux_gtk.so", synthetic_elf64(machine, elf_type=3))
    (root / "lib/libapp.so").chmod(0o644)
    (root / "lib/libflutter_linux_gtk.so").chmod(0o644)
    (root / "winn3-descriptor-ring-attestation.json").write_text(
        '{"identity_sha256":"' + ("a" * 64) + '","schema_version":1,'
        '"verified_artifact":"lib/libapp.so"}\n',
        encoding="ascii",
    )


def write_dual_auth_attestation_fixture(root: pathlib.Path) -> pathlib.Path:
    artifacts = {
        relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for relative in ("wins_vpn", "lib/libapp.so", "winn-datapath")
    }
    document = {
        "schema_version": 2,
        "contract": "winsvpn-linux-winn3-dual-auth-release-v2",
        "build_mode": "release",
        "dart_define": {
            "name": "WINS_WINN3_DUAL_AUTH",
            "value": "true",
            "occurrences": 1,
            "source": "flutter-cli",
        },
        "native_gates": ["linux_winn3_host_test", "linux_winn_gate_test"],
        "producer": {
            "path": "tools/build_linux_release.sh",
            "sha256": hashlib.sha256(PRODUCER.read_bytes()).hexdigest(),
        },
        "capability_proof": {
            "contract": "winsvpn-linux-compiled-capability-proof-v3",
            "source_path": "lib/winn_protocol_dispatch.dart",
            "source_sha256": "d" * 64,
            "release_input_index_sha256": "e" * 64,
            "define": "WINS_WINN3_DUAL_AUTH=true",
            "enabled_platforms_define": "WINS_WINN3_ENABLED_PLATFORMS=linux",
            "relay_enabled_platforms_define": "WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux",
            "compiled_test": "linux_dual_auth_compiled_capability_test",
            "verified_artifact": "lib/libapp.so",
            "verified_artifact_sha256": artifacts["lib/libapp.so"],
        },
        "artifacts": artifacts,
    }
    path = root / "winn3-dual-auth-release-attestation.json"
    path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n",
        encoding="ascii",
    )
    return path


def run_producer(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(PRODUCER), *args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def producer_fixture_root(root: pathlib.Path) -> pathlib.Path:
    """Copy the producer and the files it reads at start-up into a fixture root."""

    (root / "tools").mkdir(parents=True)
    for relative in ("pubspec.yaml", "tools/toolchain-pins.json", "tools/build_linux_release.sh"):
        (root / relative).write_bytes((ROOT / relative).read_bytes())
    return root / "tools/build_linux_release.sh"


def release_index_fixture(path: pathlib.Path, created_utc: str = "2026-10-09T01:02:03.456789Z") -> bytes:
    document = {
        "contract": "winsvpn-release-input-index-v1",
        "created_utc": created_utc,
        "manifest_set_complete": True,
        "platform_manifests": {},
        "publication_authorized": False,
        "release": "fixture",
        "schema_version": 1,
        "sha256_anchor": "RELEASE_INPUT_INDEX.json.sha256",
        "shared_manifest": {"path": "SHARED_INPUTS.json", "sha256": "2" * 64},
        "shared_revision": "0" * 40,
    }
    payload = (json.dumps(document, sort_keys=True) + "\n").encode("ascii")
    path.write_bytes(payload)
    path.chmod(0o644)
    return payload


def write_manifest_archive(
    path: pathlib.Path, payloads: dict[str, bytes], *, records: dict[str, str] | None = None
) -> None:
    manifest_records = records or {
        name: hashlib.sha256(payload).hexdigest() for name, payload in payloads.items()
    }
    manifest = "".join(
        f"{digest}  {name}\n" for name, digest in sorted(manifest_records.items())
    ).encode("ascii")
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in sorted({**payloads, "release-manifest.sha256": manifest}.items()):
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(payload))


def _write_authenticated_python_launcher(root: pathlib.Path) -> pathlib.Path:
    candidate = getattr(sys, "_base_executable", None) or sys.executable
    interpreter = pathlib.Path(candidate)
    if (
        not interpreter.is_absolute()
        or not interpreter.is_file()
        or not os.access(interpreter, os.X_OK)
    ):
        raise RuntimeError("authenticated Python base executable is unavailable")
    version_root = interpreter.parent.parent
    relocation = ""
    if (
        interpreter.parent.name == "bin"
        and version_root.parent.name == "Versions"
        and version_root.parent.parent.name == "Python.framework"
    ):
        framework = version_root.parent.parent
        relocation = (
            f" DYLD_FRAMEWORK_PATH={shlex.quote(str(framework.parent))}"
            f" DYLD_LIBRARY_PATH={shlex.quote(str(version_root / 'lib'))}"
        )
    launcher_dir = root / "authenticated-python"
    launcher_dir.mkdir(mode=0o700)
    launcher = launcher_dir / "python3"
    launcher.write_text(
        "#!/bin/sh\n"
        "exec /usr/bin/env -i"
        ' HOME="${HOME:?}" TMPDIR="${TMPDIR:?}"'
        " PATH=/usr/bin:/bin:/usr/sbin:/sbin"
        ' SIGN_LINUX_RELEASE="${SIGN_LINUX_RELEASE:-}"'
        ' WINS_LINUX_COSIGN_KEY="${WINS_LINUX_COSIGN_KEY:-}"'
        ' WINS_LINUX_COSIGN_PUBKEY="${WINS_LINUX_COSIGN_PUBKEY:-}"'
        ' WINS_LINUX_COSIGN_TRUST_ANCHOR="${WINS_LINUX_COSIGN_TRUST_ANCHOR:-}"'
        ' WINS_LINUX_SIGNER_IDENTITY="${WINS_LINUX_SIGNER_IDENTITY:-}"'
        ' WINS_LINUX_SIGNER_OIDC_ISSUER="${WINS_LINUX_SIGNER_OIDC_ISSUER:-}"'
        " PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1"
        f"{relocation} {shlex.quote(str(interpreter))} -S \"$@\"\n",
        encoding="utf-8",
    )
    launcher.chmod(0o500)
    return launcher_dir


class LinuxReleaseProducerTests(unittest.TestCase):
    def test_native_messaging_host_is_a_mandatory_stripped_aot_package_input(self) -> None:
        for marker in (
            "build_and_stage_linux_native_host",
            '"${dart_command}" pub get --offline --enforce-lockfile',
            '"${dart_command}" compile exe',
            "--target-os=linux",
            '--target-arch="${LINUX_RELEASE_ARCH_LABEL}"',
            '--save-debugging-info="${private_debug}"',
            '"${native_host_output}" --selftest',
            "Linux native-messaging host retains private native symbols",
            "linux-release-provenance.json",
            "org.winsvpn.bridge.chrome.json",
            "org.winsvpn.bridge.firefox.json",
            "manifests/store_ids.json",
            "install_native_host.sh",
        ):
            self.assertIn(marker, SOURCE)
        build = SOURCE.index('build_and_stage_linux_native_host "${BUNDLE_DIR}" "${tmp_dir}"')
        manifest = SOURCE.index('log "Generating exhaustive release manifest"')
        self.assertLess(build, manifest)

    def test_native_host_source_closure_pin_matches_every_declared_input(self) -> None:
        function = SOURCE.split("native_host_source_paths() {", 1)[1].split("\n}", 1)[0]
        paths = sorted(
            re.findall(r"\s+((?:extension|lib|tools)/[^ \\\n]+)", function)
        )
        self.assertEqual(len(paths), 17)
        records = []
        for relative in paths:
            payload = (ROOT / relative).read_bytes()
            records.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "bytes": len(payload),
                }
            )
        encoded = (
            json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
        expected = hashlib.sha256(encoded).hexdigest()
        pinned = re.search(
            r'^NATIVE_HOST_SOURCE_CLOSURE_SHA256="([0-9a-f]{64})"$',
            SOURCE,
            re.MULTILINE,
        )
        self.assertIsNotNone(pinned)
        # The pin is the reviewed closure of the 17 inputs as they are now.
        # A drift is a plain release refusal until the pin is updated.
        self.assertEqual(
            pinned.group(1),
            expected,
            f"re-pin NATIVE_HOST_SOURCE_CLOSURE_SHA256 to {expected} after reviewing the inputs",
        )
        self.assertIn(
            "native-host source closure changed: reviewed=",
            SOURCE,
        )
        self.assertIn('release_refused "native-host source closure changed:', SOURCE)
        self.assertNotIn("owner_blocked", SOURCE)
        self.assertRegex(
            SOURCE,
            r'(?m)^NATIVE_HOST_SOURCE_CLOSURE_SHA256="[0-9a-f]{64}"$',
        )
        self.assertNotRegex(
            SOURCE,
            r'(?m)^NATIVE_HOST_SOURCE_CLOSURE_SHA256="\$',
        )
        self.assertIn(
            '[[ "${actual}" == "${NATIVE_HOST_SOURCE_CLOSURE_SHA256}" ]]', SOURCE
        )
        self.assertNotIn(
            'NATIVE_HOST_SOURCE_CLOSURE_SHA256="${actual}"', SOURCE
        )
        mutated = bytearray(encoded)
        mutated[0] ^= 0x01
        mutated_digest = hashlib.sha256(mutated).hexdigest()
        self.assertNotEqual(mutated_digest, expected)
        for index, relative in enumerate(paths):
            changed = [dict(record) for record in records]
            payload = (ROOT / relative).read_bytes() + b"\x00"
            changed[index]["sha256"] = hashlib.sha256(payload).hexdigest()
            changed[index]["bytes"] = len(payload)
            digest = hashlib.sha256(
                (
                    json.dumps(
                        changed,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    )
                    + "\n"
                ).encode("ascii")
            ).hexdigest()
            self.assertNotEqual(digest, expected, relative)
            self.assertNotEqual(digest, pinned.group(1), relative)

    def test_native_host_registration_assets_receive_exact_release_modes(self) -> None:
        self.assertIn(
            '"$PACKAGE_ROOT/tools/native_messaging/host/wins_bridge_host"', SOURCE
        )
        self.assertIn(
            '"$PACKAGE_ROOT/tools/native_messaging/install_native_host.sh"', SOURCE
        )
        self.assertIn('find "$PACKAGE_ROOT" -type f -exec chmod 0644', SOURCE)

    def test_privacy_gate_accepts_executable_winn_datapath_metadata(self) -> None:
        datapath = tarfile.TarInfo("winn-datapath")
        datapath.type = tarfile.REGTYPE
        datapath.mode = 0o755
        datapath.uid = 0
        datapath.gid = 0
        validate_tar_metadata(pathlib.Path("release.tar.gz"), [datapath])

    def test_every_real_build_requires_the_immutable_release_index(self) -> None:
        self.assertIn(
            "Every Linux release build requires WINS_RELEASE_INPUT_INDEX.", SOURCE
        )
        self.assertIn("resolve_release_input_index", SOURCE)
        self.assertIn("RELEASE_INPUT_INDEX.json", SOURCE)
        self.assertIn("verify-index", SOURCE)

    def test_outer_producer_owns_one_begin_and_finish_receipt(self) -> None:
        for marker in (
            "LINUX_BUILD_BEGIN.json",
            "LINUX_BUILD_RECEIPT.json",
            "begin-build",
            "finish-build",
            "verify-receipt",
            "--producer tools/build_linux_release.sh",
        ):
            self.assertIn(marker, SOURCE)
        # The formal receipt's --target records whichever architecture this run
        # actually built (detect_linux_release_arch). The WSL /mnt wrapper now
        # detects before wrapping so ARM64 WSL publishes linux-arm64 outputs;
        # the :-x64 fallback only applies if a caller forgot to detect.
        self.assertIn(
            '--target "linux-${LINUX_RELEASE_ARCH_LABEL:-x64}"', SOURCE
        )

        wsl_start = SOURCE.index("run_from_neutral_wsl_stage()")
        wsl_end = SOURCE.index("run_build_lock_self_test()", wsl_start)
        wsl_block = SOURCE[wsl_start:wsl_end]
        self.assertLess(
            wsl_block.index("acquire_build_lock"),
            wsl_block.index("initialize_formal_linux_receipt"),
        )
        self.assertLess(
            wsl_block.index("initialize_formal_linux_receipt"),
            wsl_block.index("WINS_LINUX_NEUTRAL_STAGE_ACTIVE=1"),
        )
        self.assertLess(
            wsl_block.index(
                'python3 "${ROOT}/tools/release_dependency_freeze.py" verify-index',
                wsl_block.index("symbol_source="),
            ),
            wsl_block.index("complete_formal_linux_receipt"),
        )

    def test_neutral_child_verifies_inputs_but_cannot_finish_a_receipt(self) -> None:
        self.assertIn("assert_neutral_linux_stage", SOURCE)
        self.assertIn(
            'if [[ "${WINS_LINUX_NEUTRAL_STAGE_ACTIVE:-0}" == "0" ]]; then\n'
            '  complete_formal_linux_receipt "$formal_index_path" "$staged_archive"',
            SOURCE,
        )
        self.assertIn(
            'WINS_RELEASE_INPUT_INDEX="${neutral_linux_tmp}/${index_relative}/RELEASE_INPUT_INDEX.json"',
            SOURCE,
        )

    def test_receipt_is_finished_only_after_artifact_validation_and_signing(self) -> None:
        final_sign = SOURCE.rindex('sign_linux_release "$staged_archive" "$staged_bundle"')
        # verify_linux_release_inputs_unchanged runs the controller's
        # verify-index, or in remote-attested mode the stdlib manifest check.
        post_verify = SOURCE.index(
            'verify_linux_release_inputs_unchanged "$formal_index_path"',
            final_sign,
        )
        finish = SOURCE.index(
            'complete_formal_linux_receipt "$formal_index_path" "$staged_archive"',
            post_verify,
        )
        self.assertLess(final_sign, post_verify)
        self.assertLess(post_verify, finish)

    def test_receipt_directory_is_new_private_and_repository_contained(self) -> None:
        for marker in (
            '"${ROOT}"/.artifacts/*',
            "Linux build receipt directory must be a new immutable path",
            'mkdir -m 0700 -- "${formal_receipt_dir}"',
        ):
            self.assertIn(marker, SOURCE)

    def test_receipts_live_outside_the_immutable_freeze_directory(self) -> None:
        self.assertIn(
            'namespace="${ROOT}/.artifacts/release-build-receipts/linux/${index_hash}"',
            SOURCE,
        )
        self.assertIn(
            "Linux build receipts must stay outside the immutable release-manifest directory",
            SOURCE,
        )
        self.assertIn('index_hash="$(sha256sum "${index_path}"', SOURCE)
        self.assertNotIn(
            'requested="$(dirname "${index_path}")/linux-build-', SOURCE
        )

    def test_canonical_publication_is_one_atomic_immutable_generation(self) -> None:
        self.assertIn('| gzip -n >&${publication_writer_fd}', SOURCE)
        self.assertNotIn('| gzip -n > "$ARCHIVE"', SOURCE)
        self.assertIn(
            'open_linux_publication_output_under_custody "${staged_archive}"',
            SOURCE,
        )
        final_package = SOURCE.rindex('log "Packaging release bundle"')
        final_block = SOURCE[final_package:]
        self.assertLess(
            final_block.index(
                'validate_release_artifact_privacy.py" --artifacts'
            ),
            final_block.index("commit_linux_publication"),
        )
        self.assertLess(
            final_block.index(
                '--target "linux-${LINUX_RELEASE_ARCH_LABEL}-package"'
            ),
            final_block.index("commit_linux_publication"),
        )
        self.assertLess(
            final_block.index('--artifact "$staged_archive"'),
            final_block.index("commit_linux_publication"),
        )
        self.assertLess(
            final_block.index('complete_formal_linux_receipt "$formal_index_path" "$staged_archive"'),
            final_block.index("commit_linux_publication"),
        )
        for marker in (
            ".artifacts/private-release-generations/linux",
            "private-symbols/manifest.json",
            "immutable generations are never replaced",
            "renameat2(RENAME_NOREPLACE)",
            "publication_committed",
            "fsync_tree_fd(stage_child_fd)",
            "Linux publication stage child does not match the retained stage descriptor",
            "published Linux generation is not the retained stage inode",
            "publication_uncommitted_identity",
            'publication_uncommitted_identity="${publish_identity}"',
            "hostile partial-commit failure after no-replace rename",
            "remove_uncommitted_linux_generation",
            "os.fsync(generation_root_fd)",
            "os.fsync(stage_parent_fd)",
            "stage_linux_private_symbols",
            "did not atomically retain private symbols with each generation",
        ):
            self.assertIn(marker, SOURCE)
        self.assertNotIn("publish_staged_linux_archive", final_block)

    def test_signing_self_test_covers_local_key_only_contract(self) -> None:
        secure_tmp_parent = pathlib.Path(
            os.environ.get("TMPDIR", tempfile.gettempdir())
        ).resolve()
        with tempfile.TemporaryDirectory(
            prefix=".wins-linux-signing-", dir=secure_tmp_parent
        ) as name:
            environment = os.environ.copy()
            environment["TMPDIR"] = name
            launcher_dir = _write_authenticated_python_launcher(pathlib.Path(name))
            environment["PATH"] = (
                f"{launcher_dir}{os.pathsep}/usr/bin:/bin:/usr/sbin:/sbin"
            )
            completed = subprocess.run(
                [
                    "bash",
                    str(ROOT / "tools/build_linux_release.sh"),
                    "--self-test-signing",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("LINUX SIGSTORE SIGNING SELF-TEST: PASS", completed.stdout)
        self.assertIn("accepted retired remote-signing environment input", SOURCE)
        self.assertIn("accepted a cosign executable outside ${COSIGN_PATH}", SOURCE)
        self.assertIn("accepted a repository-local signing key", SOURCE)

    def test_winn_datapath_is_mandatory_in_the_producer(self) -> None:
        self.assertIn("Building mandatory Winn Protocol v3 engine", SOURCE)
        self.assertIn(
            "Winn Protocol v3 datapath is required for a Linux release", SOURCE
        )
        self.assertNotIn("Building optional Winn Protocol v3 engine", SOURCE)

    def test_winn3_core_and_relay_are_matching_host_and_scratch_only(self) -> None:
        stage = SOURCE[
            SOURCE.index("stage_linux_engine_payloads() {") : SOURCE.index(
                "acquire_build_lock() {"
            )
        ]
        for marker in (
            "assert_linux_release_matching_host || return 65",
            'winn_target="datapath-linux-${LINUX_RELEASE_GOARCH}"',
            'relay_target="winn3-gateway-linux-${LINUX_RELEASE_GOARCH}"',
            'Building mandatory Winn Protocol v3 engine (core; target',
            'Building mandatory Winn Protocol v3 relay (target',
            '"${winn_target}"',
            '"${relay_target}"',
            "verify_linux_winn3_datapath_contract",
            "verify_linux_winn3_gateway_role",
            "winn3-core-relay-provenance.json",
            "disposable-scratch-only",
            "Winn Protocol source changed while the core/relay pair was being built.",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin bash",
        ):
            self.assertIn(marker, stage)
        self.assertNotIn('"$dest_abs/winn3-gateway"', stage)
        self.assertLess(
            stage.index("assert_linux_release_matching_host || return 65"),
            stage.index("Building mandatory Winn Protocol v3 engine"),
        )
        self.assertLess(
            stage.index("Building mandatory Winn Protocol v3 engine"),
            stage.index("Building mandatory Winn Protocol v3 relay"),
        )

    def test_hostile_linux_bundle_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-bundle-hostile-") as raw:
            bundle = pathlib.Path(raw)
            tarball_architecture_fixture(bundle, 62)

            (bundle / "winn-datapath").write_bytes(synthetic_elf64(183))
            (bundle / "winn-datapath").chmod(0o755)
            wrong_arch = subprocess.run(
                [
                    "bash",
                    str(PRODUCER),
                    "--self-test-bundle-architecture",
                    str(bundle),
                    "x64",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(wrong_arch.returncode, 65, wrong_arch.stderr)
            self.assertIn("winn-datapath targets ELF machine 183", wrong_arch.stderr)

            write_executable(bundle / "winn-datapath", synthetic_elf64(62))
            write_executable(bundle / "winn3-gateway", synthetic_elf64(62))
            server_role = subprocess.run(
                [
                    "bash",
                    str(PRODUCER),
                    "--self-test-bundle-architecture",
                    str(bundle),
                    "x64",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(server_role.returncode, 65, server_role.stderr)
            self.assertIn("server-role winn3-gateway", server_role.stderr)

            (bundle / "winn3-gateway").unlink()
            write_executable(bundle / "winn-datapath", b"#!/bin/sh\nexit 0\n")
            non_elf = subprocess.run(
                [
                    "bash",
                    str(PRODUCER),
                    "--self-test-bundle-architecture",
                    str(bundle),
                    "x64",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(non_elf.returncode, 65, non_elf.stderr)
            self.assertIn("winn-datapath is not a supported little-endian ELF64 executable", non_elf.stderr)

            write_executable(
                bundle / "winn-datapath", synthetic_elf64(62, elf_type=3)
            )
            entry_zero = subprocess.run(
                [
                    "bash",
                    str(PRODUCER),
                    "--self-test-bundle-architecture",
                    str(bundle),
                    "x64",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(entry_zero.returncode, 65, entry_zero.stderr)
            self.assertIn(
                "winn-datapath is not a supported little-endian ELF64 executable",
                entry_zero.stderr,
            )

            incongruent = bytearray(synthetic_elf64(62))
            struct.pack_into("<Q", incongruent, 64 + 16, 0x400001)
            write_executable(bundle / "winn-datapath", bytes(incongruent))
            rejected = subprocess.run(
                [
                    "bash",
                    str(PRODUCER),
                    "--self-test-bundle-architecture",
                    str(bundle),
                    "x64",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(rejected.returncode, 65, rejected.stderr)

            self.assertIn("winn-datapath is not a supported little-endian ELF64 executable", rejected.stderr)

    def test_native_elf_fixture_is_runnable_when_host_is_linux(self) -> None:
        machine_name = platform.machine().lower()
        if sys.platform != "linux" or machine_name not in {
            "x86_64",
            "amd64",
            "aarch64",
            "arm64",
        }:
            # The arm64 physical-execution receipt gate is retired; the
            # producer verifies ELF structure and the pinned sha256 only.
            self.assertNotIn("--linux-execution-receipt", SOURCE)
            self.assertNotIn("--linux-execution-bundle", SOURCE)
            self.assertNotIn("LINUX_PHYSICAL_EXECUTION_RECEIPT_ROOT", SOURCE)
            return
        machine = 62 if machine_name in {"x86_64", "amd64"} else 183
        with tempfile.TemporaryDirectory(prefix="winsvpn-runnable-elf-") as raw:
            path = pathlib.Path(raw) / "fixture"
            write_executable(path, synthetic_elf64(machine))
            completed = subprocess.run([str(path)], stdin=subprocess.DEVNULL, check=False)
            self.assertEqual(completed.returncode, 0)

    def test_bundle_gate_rejects_trap_entry_and_et_dyn_without_dynamic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-elf-hostile-") as raw:
            bundle = pathlib.Path(raw)
            tarball_architecture_fixture(bundle, 62)
            trap = bytearray(synthetic_elf64(62))
            trap[0x200:0x202] = b"\x0f\x0b"
            write_executable(bundle / "winn-datapath", bytes(trap))
            command = [
                "bash", str(PRODUCER), "--self-test-bundle-architecture",
                str(bundle), "x64",
            ]
            rejected = subprocess.run(
                command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(rejected.returncode, 65, rejected.stderr)

            missing_dynamic = bytearray(synthetic_elf64(62))
            struct.pack_into("<H", missing_dynamic, 16, 3)
            write_executable(bundle / "winn-datapath", bytes(missing_dynamic))
            rejected = subprocess.run(
                command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(rejected.returncode, 65, rejected.stderr)

    def test_bundle_and_direct_elf_gates_reject_misaligned_aarch64_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-aarch64-entry-") as raw:
            bundle = pathlib.Path(raw) / "bundle"
            bundle.mkdir()
            tarball_architecture_fixture(bundle, 183)
            misaligned = bytearray(synthetic_elf64(183))
            struct.pack_into("<Q", misaligned, 24, 0x400201)
            write_executable(bundle / "winn-datapath", bytes(misaligned))
            rejected = subprocess.run(
                [
                    "bash",
                    str(PRODUCER),
                    "--self-test-bundle-architecture",
                    str(bundle),
                    "arm64",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(rejected.returncode, 65, rejected.stderr)

            direct = pathlib.Path(raw) / "misaligned"
            write_executable(direct, bytes(misaligned))
            rejected = subprocess.run(
                ["bash", str(PRODUCER), "--self-test-elf-machine", str(direct), "183"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
            self.assertNotIn("PASS", rejected.stdout + rejected.stderr)

    def test_contract_probe_rejects_duplicate_json_keys(self) -> None:
        self.assertIn("object_pairs_hook=reject_duplicate_keys", SOURCE)
        self.assertIn("duplicate contract JSON key", SOURCE)
        self.assertIn("invalid Winn Protocol datapath contract", SOURCE)

    def test_dual_auth_attestation_rejects_duplicate_and_nonfinite_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-dual-auth-json-") as raw:
            bundle = pathlib.Path(raw)
            tarball_architecture_fixture(bundle, 62)
            attestation = write_dual_auth_attestation_fixture(bundle)
            command = [
                "bash",
                str(PRODUCER),
                "--self-test-winn3-dual-auth-attestation",
                str(bundle),
            ]
            accepted = subprocess.run(
                command,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            original = attestation.read_text(encoding="ascii")
            attestation.write_text(
                '{"schema_version":1,' + original[1:], encoding="ascii"
            )
            duplicate = subprocess.run(
                command,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertIn("duplicate Linux dual-auth attestation key", duplicate.stderr)

            attestation.write_text(
                original.replace('"schema_version":2', '"schema_version":NaN', 1),
                encoding="ascii",
            )
            nonfinite = subprocess.run(
                command,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(nonfinite.returncode, 0)
            self.assertIn("non-finite Linux dual-auth attestation number", nonfinite.stderr)

    def test_current_native_host_closure_matches_the_reviewed_pin(self) -> None:
        completed = run_producer("--self-test-native-host-closure")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("LINUX NATIVE-HOST SOURCE CLOSURE: PASS", completed.stdout)
        self.assertNotIn("OWNER-BLOCKED", completed.stdout + completed.stderr)

    def test_native_host_closure_drift_is_a_plain_refusal(self) -> None:
        function = SOURCE.split("native_host_source_paths() {", 1)[1].split("\n}", 1)[0]
        paths = sorted(re.findall(r"\s+((?:extension|lib|tools)/[^ \\\n]+)", function))
        with tempfile.TemporaryDirectory(prefix="winsvpn-closure-drift-") as raw:
            producer = producer_fixture_root(pathlib.Path(raw))
            fixture = pathlib.Path(raw)
            for relative in paths:
                target = fixture / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            host_lib = fixture / "tools/native_messaging/host/lib"
            host_lib.mkdir(parents=True, exist_ok=True)
            for link in sorted((ROOT / "tools/native_messaging/host/lib").iterdir()):
                (host_lib / link.name).symlink_to(os.readlink(link))
            unchanged = subprocess.run(
                ["bash", str(producer), "--self-test-native-host-closure"],
                cwd=fixture, text=True, capture_output=True, check=False,
            )
            self.assertEqual(unchanged.returncode, 0, unchanged.stderr)
            drifted = fixture / "tools/native_messaging/host/bin/wins_bridge_host.dart"
            drifted.write_bytes(drifted.read_bytes() + b"\n")
            changed = subprocess.run(
                ["bash", str(producer), "--self-test-native-host-closure"],
                cwd=fixture, text=True, capture_output=True, check=False,
            )
        self.assertEqual(changed.returncode, 65, changed.stderr)
        self.assertIn("RELEASE REFUSED: native-host source closure changed", changed.stderr)
        self.assertNotIn("PASS", changed.stdout)
        self.assertNotIn("OWNER-BLOCKED", changed.stderr)

    def test_compiler_tree_custody_executes_with_pinned_tree_digests(self) -> None:
        completed = run_producer("--self-test-linux-tree-custody")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("LINUX COMPILER TREE CUSTODY SELF-TEST: PASS", completed.stdout)
        custody = SOURCE[
            SOURCE.index("run_with_linux_tree_custody() {") : SOURCE.index(
                "run_with_reviewed_flutter_pub_custody() {"
            )
        ]
        self.assertNotIn("pathname copy/hash custody is retired", custody)
        self.assertNotIn("owner_blocked", custody)
        self.assertIn('record = f"file {opened.st_size} {file_digest.hexdigest()} {relative}\\n"', custody)
        self.assertIn("authenticated compiler tree changed after compiler execution", custody)
        self.assertIn("authenticated compiler tree changed while the compiler was running", custody)

    def test_flutter_and_pub_custody_tolerates_only_tool_runtime_state(self) -> None:
        wrapper = SOURCE[
            SOURCE.index("run_with_reviewed_flutter_pub_custody() {") : SOURCE.index(
                "prepare_linux_reviewed_go_for_engines() {"
            )
        ]
        self.assertIn('"--flutter-sdk-root=${WINS_LINUX_FLUTTER_TREE_ROOT:?}"', wrapper)
        self.assertIn('"--pub-cache-root=${PUB_CACHE:?}"', wrapper)
        self.assertIn('"${WINS_LINUX_FLUTTER_TREE_SHA256:?}=${WINS_LINUX_FLUTTER_TREE_ROOT:?}"', wrapper)
        self.assertIn('"${WINS_LINUX_PUB_CACHE_TREE_SHA256:?}=${PUB_CACHE:?}"', wrapper)
        custody = SOURCE[
            SOURCE.index("run_with_linux_tree_custody() {") : SOURCE.index(
                "run_with_reviewed_flutter_pub_custody() {"
            )
        ]
        state = re.search(r"FLUTTER_SDK_RUNTIME_STATE = \((.*?)\n\)", custody, re.DOTALL)
        self.assertIsNotNone(state)
        linux_state = set(re.findall(r'"([^"]+)"', state.group(1)))
        android = (ROOT / "tools/build_android_release_macos.sh").read_text(encoding="utf-8")
        android_state = re.search(r"HOME_FLUTTER_RUNTIME_STATE = \((.*?)\n\)", android, re.DOTALL)
        self.assertIsNotNone(android_state)
        # The reviewed Android runtime-mutable set, plus only the files the
        # bin/flutter wrapper and the tool rewrite on every Linux invocation.
        self.assertEqual(
            linux_state - set(re.findall(r'"([^"]+)"', android_state.group(1))),
            {"bin/cache/engine.stamp", "bin/cache/engine.realm", "bin/cache/flutter.version.json", "version"},
        )
        self.assertIn('PUB_CACHE_RUNTIME_STATE = ("active_roots", "_temp", "log")', custody)
        self.assertIn('FLUTTER_SDK_TRANSIENT_PREFIX = "bin/cache/engine.stamp.tmp."', custody)
        # The Go toolchain and the store module cache get no runtime state.
        go_run = SOURCE[SOURCE.index("wins_release_go_run() {") : SOURCE.index("export -f wins_release_go_verify")]
        self.assertNotIn("-root=", go_run)

    @unittest.skipUnless(sys.platform == "linux", "the custody watch needs Linux inotify")
    def test_custody_ancestor_watch_ignores_child_attribute_changes_only(self) -> None:
        # Real Linux inotify. The IPC tests chmod temporary directories under
        # TMPDIR and `dart compile exe` chmods its output next to the toolchain
        # extraction; both are children of an ancestor of the custody roots and
        # must not stop the build, while a change to the ancestor itself or to
        # anything in the authenticated tree still must.
        custody = SOURCE[
            SOURCE.index("run_with_linux_tree_custody() {") : SOURCE.index(
                "run_with_reviewed_flutter_pub_custody() {"
            )
        ]
        marker = "<<'PY'\n"
        first = custody.index(marker) + len(marker)
        script = custody[first : custody.index("\nPY\n", first) + 1]
        payload = b"reviewed-toolchain-byte\n"
        record = f"file {len(payload)} {hashlib.sha256(payload).hexdigest()} tool\n"
        pin = hashlib.sha256(record.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as raw:
            base = pathlib.Path(raw) / "tmp.fixture"
            tree = base / "linux-flutter-toolchain" / "flutter"
            tree.mkdir(parents=True)
            (tree / "tool").write_bytes(payload)

            def run(shell: str, *arguments: pathlib.Path) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, "-I", "-", "0", f"{pin}={tree}", "--", "/bin/sh", "-c", shell, "sh",
                     *map(str, arguments)],
                    input=script,
                    capture_output=True,
                    text=True,
                    check=False,
                )

            refusal = "authenticated compiler tree changed while the compiler was running"
            # A child of the ancestor chmod-ed: tolerated.
            child = run('mkdir "$1/ipc" && chmod 0700 "$1/ipc" && : > "$1/out" && chmod 0755 "$1/out"', base)
            self.assertEqual(child.returncode, 0, child.stderr)
            # The ancestor itself chmod-ed: refused.
            ancestor = run('chmod 0750 "$1"', base)
            self.assertNotEqual(ancestor.returncode, 0)
            self.assertIn(refusal, ancestor.stderr)
            base.chmod(0o700)
            # The next component toward the root chmod-ed: refused through its own watch.
            component = run('chmod 0750 "$1"', base / "linux-flutter-toolchain")
            self.assertNotEqual(component.returncode, 0)
            self.assertIn(refusal, component.stderr)
            (base / "linux-flutter-toolchain").chmod(0o700)
            # A member of the authenticated tree chmod-ed: refused.
            member = run('chmod 0600 "$1/tool"', tree)
            self.assertNotEqual(member.returncode, 0)
            self.assertIn(refusal, member.stderr)

    def test_store_stage_clears_the_binder_go_custody_before_the_producer_derives_its_own(self) -> None:
        binder = (ROOT / "linux/packaging/store_engine_bind.py").read_text(encoding="utf-8")
        returned = binder[binder.index("def bind_go_archive") :]
        returned = returned[returned.index("    return {") : returned.index("\n    }\n", returned.index("    return {"))]
        emitted = set(re.findall(r'"((?:LINUX_REVIEWED_GO|WINS_RELEASE_GO)[A-Z_0-9]*)":', returned))
        self.assertIn("LINUX_REVIEWED_GO_BIN", emitted)
        stage = SOURCE[SOURCE.index("stage_linux_engine_payloads() {") :]
        sourced = stage.index('source "${tmp_dir}/store-engine.env"')
        guarded = stage.index("prepare_linux_reviewed_go_for_engines || return $?")
        window = re.sub(r"\\\n\s*", " ", stage[sourced:guarded])
        unset_line = re.search(r"^\s*unset ([A-Z_0-9 ]+)$", window, re.MULTILINE)
        self.assertIsNotNone(unset_line, "the binder's Go custody is not cleared after the store env is sourced")
        cleared = set(unset_line.group(1).split())
        # prepare_linux_reviewed_go_for_engines refuses any of these that is already set.
        guard = SOURCE[SOURCE.index("prepare_linux_reviewed_go_for_engines() {") :]
        guard = guard[: guard.index("return 65")]
        for name in emitted:
            if name in guard:
                self.assertIn(name, cleared, name)

    def test_producer_go_extraction_does_not_reuse_the_store_binder_directory(self) -> None:
        binder = (ROOT / "linux/packaging/store_engine_bind.py").read_text(encoding="utf-8")
        binder_dir = re.search(r'\n    dest = tmp / "([A-Za-z0-9_-]+)"', binder[binder.index("def bind_go_archive") :]).group(1)
        prepare = SOURCE[SOURCE.index("prepare_linux_reviewed_go_for_engines() {") :]
        prepare = prepare[: prepare.index("wins_release_go_verify() {")]
        extraction = re.search(r'winsvpn_extract_snapshot "\$\{go_snapshot\}" "\$tmp_dir/([A-Za-z0-9_-]+)" tar\.gz', prepare)
        self.assertIsNotNone(extraction)
        # Both run in the same tmp_dir in store mode; the extractor opens files O_EXCL.
        self.assertNotEqual(extraction.group(1), binder_dir)
        self.assertIn(f'go_root="$tmp_dir/{extraction.group(1)}/go"', prepare)

    @unittest.skipUnless(pathlib.Path("/proc/self/fd").is_dir(), "held descriptors need /proc")
    def test_sha256_bind_hashes_a_held_descriptor_path_and_still_refuses_other_links(self) -> None:
        start = SOURCE.index("winsvpn_sha256_bind_file() {")
        function = SOURCE[start : SOURCE.index("\n}\n", start)]
        marker = "<<'PY'\n"
        first = function.index(marker) + len(marker)
        script = function[first : function.index("\nPY", first) + 1]

        def digest(path: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "-I", "-", path], input=script, capture_output=True, text=True, check=False
            )

        with tempfile.TemporaryDirectory() as raw:
            target = pathlib.Path(raw) / "go"
            target.write_bytes(b"reviewed go executable bytes")
            expected = hashlib.sha256(b"reviewed go executable bytes").hexdigest()
            self.assertEqual(digest(str(target)).stdout.strip(), expected)
            fd = os.open(target, os.O_RDONLY)
            try:
                held = digest(f"/proc/{os.getpid()}/fd/{fd}")
                self.assertEqual(held.returncode, 0, held.stderr)
                self.assertEqual(held.stdout.strip(), expected)
            finally:
                os.close(fd)
            link = pathlib.Path(raw) / "link"
            link.symlink_to(target)
            refused = digest(str(link))
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("must be a regular file", refused.stderr)

    def test_datapath_role_probe_field_set_is_the_engines_contract_struct(self) -> None:
        source = (ROOT / "winn_protocol_experimental/cmd/winn-datapath/main.go").read_text(encoding="utf-8")
        struct = source[source.index("type Contract struct {") :]
        struct = struct[: struct.index("\n}\n")]
        engine_fields = set(re.findall(r'`json:"([a-z0-9_]+)"`', struct))
        function = SOURCE[SOURCE.index("verify_linux_winn3_datapath_contract() {") :]
        function = function[: function.index("verify_linux_winn3_gateway_role() {")]
        identity = set(re.findall(r'^    "([a-z0-9_]+)": ', function[function.index("expected = {") :], re.MULTILINE))
        extra_block = function[function.index("banner_fields = {") :]
        extra = set(re.findall(r'"([a-z0-9_]+)"', extra_block[: extra_block.index("}")]))
        self.assertEqual(identity | extra, engine_fields)

    def test_sibling_importing_tools_run_with_the_script_directory_on_sys_path(self) -> None:
        # `python3 -I` drops the script directory from sys.path, and these two
        # tools import release_obfuscation_contract, release_secret_scan_policy and
        # friends by plain name, so under the isolated wrapper they die at import.
        wrapper = re.search(r"python3_tool\(\) \{\n  \"\$\{LINUX_SYSTEM_PYTHON\}\" ([^\n]+) \"\$@\"\n\}", SOURCE)
        self.assertIsNotNone(wrapper)
        self.assertNotIn("-I", wrapper.group(1).split())
        self.assertEqual(sorted(wrapper.group(1).split()), ["-E", "-s"])
        isolated = "\"${LINUX_SYSTEM_PYTHON}\" -I"
        self.assertIn(isolated, SOURCE)
        for script in ("validate_release_artifact_privacy.py", "release_obfuscation_contract.py"):
            calls = re.findall(r"(?m)^\s*(python3(?:_tool)?) \"\$\{?ROOT\}?/tools/" + re.escape(script) + '"', SOURCE)
            # The staged-archive invocations run under file custody with the same
            # interpreter flags (-E -s keeps the script directory on sys.path).
            calls.extend(
                "python3_tool" for _ in re.finditer(
                    r'(?m)^\s*"\$\{LINUX_SYSTEM_PYTHON\}" -E -s "\$\{?ROOT\}?/tools/'
                    + re.escape(script) + '"', SOURCE
                )
            )
            self.assertTrue(calls, script)
            self.assertEqual(set(calls), {"python3_tool"}, script)
        # Behavior: the same invocation shape works from a directory that is not on
        # sys.path, and the isolated shape fails exactly as in the producer.
        for flags, ok in (("-E -s", True), ("-I", False)):
            with self.subTest(flags=flags):
                completed = subprocess.run(
                    [
                        "bash", "-c",
                        f'"{sys.executable}" {flags} "{ROOT}/tools/release_obfuscation_contract.py" static',
                    ],
                    cwd="/",
                    capture_output=True,
                    text=True,
                    check=False,
                    env={"HOME": os.environ.get("HOME", "/"), "PATH": "/usr/bin:/bin", "LANG": "C"},
                )
                if ok:
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn("RELEASE OBFUSCATION STATIC CONTRACT: PASS", completed.stdout)
                else:
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("ModuleNotFoundError", completed.stderr)

    def test_release_tools_get_real_staged_paths_and_custody_is_reasserted_around_them(self) -> None:
        start = SOURCE.index('verify_linux_winn3_dual_auth_archive "${staged_archive_read}"\n')
        end = SOURCE.index('sign_linux_release "$staged_archive" "$staged_bundle"\n', start)
        tail = SOURCE[start:end]
        logical = re.sub(r"[ \t]*\\\n\s*", " ", tail).splitlines()
        tools = ("validate_release_artifact_privacy.py", "release_obfuscation_contract.py", "private_release_symbol_custody.py")
        calls = [line for line in logical if any(f"/tools/{name}" in line for name in tools)]
        self.assertEqual(len(calls), 7, calls)
        archive_prefix = 'run_with_linux_tree_custody "${staged_archive_tree_custody}" -- '
        symbols_prefix = (
            'run_with_linux_tree_custody "--publication-directory-root=${LINUX_SYMBOL_DIR}" '
            '"${staged_archive_tree_custody}" "${staged_symbols_tree_custody}" -- '
        )
        # The two final invocations also authenticate and watch the canonical symbols
        # directory against the digest sealed for the staged copy.
        self.assertEqual(sum(line.strip().startswith(symbols_prefix) for line in calls), 2)
        self.assertIn('staged_symbols_tree_custody="${custody_sha256}=${LINUX_SYMBOL_DIR}"', tail)
        for line in calls:
            # The held-descriptor path is a symbolic link by construction.
            self.assertNotIn("_read", line, line)
            # Every invocation is bound to the digest sealed for the staged archive,
            # so a substituted archive cannot be shown to a tool while the held one
            # is put aside.
            self.assertTrue(line.strip().startswith((archive_prefix, symbols_prefix)), line)
            self.assertIn('"${LINUX_SYSTEM_PYTHON}" -', line)
        self.assertIn('custody_kind}" == "sealed-file"', tail)
        self.assertIn('staged_archive_tree_custody="${custody_sha256}=${staged_archive}"', tail)
        order = [
            "assert_linux_signed_publication_custody" if line.strip() == "assert_linux_signed_publication_custody"
            else ("tool" if line in calls else "")
            for line in logical
        ]
        order = [item for item in order if item]
        # assert, 5 tool calls, assert, (stage symbols), 2 tool calls, assert.
        # The two tool calls after staging verify the canonical immutable symbol
        # directory (an exact target refuses any other), and the staged copy is
        # compared to it with diff.
        self.assertIn('diff -rq --no-dereference -- "$LINUX_SYMBOL_DIR" "$staged_private_symbols"', tail)
        self.assertNotIn('--symbols-dir "$staged_private_symbols"', tail)
        self.assertEqual(
            order,
            ["assert_linux_signed_publication_custody"] + ["tool"] * 5
            + ["assert_linux_signed_publication_custody"] + ["tool"] * 2
            + ["assert_linux_signed_publication_custody"],
        )
        # Why the held path cannot be used: the privacy scan refuses a symbolic link.
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            import validate_release_artifact_privacy as privacy
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as raw:
            real = pathlib.Path(raw) / "wins-vpn-linux-x64.tar.gz"
            real.write_bytes(b"not an archive")
            link = pathlib.Path(raw) / "fd-21"
            link.symlink_to(real)
            with self.assertRaisesRegex(privacy.PrivacyError, "regular non-symlink file"):
                privacy._scan_artifacts([link], {})

    def _custody_driver(self) -> str:
        """The producer's own tree custody and publication digest functions, extracted."""

        parts = []
        for name in ("run_with_linux_tree_custody", "publication_custody_digest"):
            start = SOURCE.index(f"{name}() {{\n")
            end = SOURCE.index("\n}\n", start) + 3
            parts.append(SOURCE[start:end])
        return (
            'python3() { "${CUSTODY_PYTHON}" -I "$@"; }\n'
            'release_refused() { echo "$*" >&2; return 65; }\n'
            + "\n".join(parts)
            + '\nseal_digest() { local dir="$1" fd=61 value; exec 61<"${dir}"; '
            'value="$(publication_custody_digest "${fd}" directory "${dir}")"; exec 61<&-; '
            'printf "%s" "${value}"; }\n'
        )

    def _custody_run(self, script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", self._custody_driver() + script],
            capture_output=True, text=True, check=False,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "CUSTODY_PYTHON": sys.executable,
                "WINS_LINUX_CUSTODY_PORTABLE_TEST": "1",
            },
        )

    def test_publication_directory_custody_binds_the_canonical_symbols_to_the_sealed_copy(self) -> None:
        # D02-07. The canonical symbols directory the final tools read was only compared
        # once with its staged copy, so it could be substituted for the comparison and put
        # back for the tools. Now it must equal the sealed digest when each tool starts
        # and stay unchanged while the tool reads it.
        with tempfile.TemporaryDirectory() as raw:
            base = pathlib.Path(raw)
            sealed, canonical = base / "staged", base / "canonical"
            for directory, mark in ((sealed, b"authentic"), (canonical, b"authentic")):
                (directory / "nested").mkdir(parents=True)
                (directory / "manifest.json").write_bytes(b'{"symbols": 2}\n')
                (directory / "nested" / "libapp.so.symbols").write_bytes(mark + b" symbols")
            seal = lambda directory: f'"$(seal_digest {shlex.quote(str(directory))})"'  # noqa: E731
            custody = lambda arguments: (  # noqa: E731
                f'expected={seal(sealed)}; run_with_linux_tree_custody '
                f'--publication-directory-root={shlex.quote(str(canonical))} '
                f'"${{expected}}={shlex.quote(str(canonical))}" -- {arguments}'
            )
            unchanged = self._custody_run(custody("/bin/sh -c 'cat \"$1\"/manifest.json >/dev/null' sh " + shlex.quote(str(canonical))))
            self.assertEqual(unchanged.returncode, 0, unchanged.stderr)
            # private_release_symbol_custody.py verify ends by chmod-ing the symbols tree and
            # the directories above it to their private modes, even when they already are:
            # that raises attribute events and changes no name or byte, so it must pass.
            normalized = self._custody_run(
                custody(
                    "/bin/sh -c 'chmod 700 \"$1\" \"$1\"/nested \"$(dirname \"$1\")\"; "
                    "chmod 600 \"$1\"/manifest.json \"$1\"/nested/libapp.so.symbols' sh "
                    + shlex.quote(str(canonical))
                )
            )
            self.assertEqual(normalized.returncode, 0, normalized.stderr)
            # The reported attack: staged copy made from substituted symbols (diff passes), the
            # authentic canonical directory put back before the final tools run.
            (sealed / "nested" / "libapp.so.symbols").write_bytes(b"substituted symbols")
            restored = self._custody_run(custody("/bin/sh -c 'exit 0'"))
            self.assertNotEqual(restored.returncode, 0)
            self.assertIn("authenticated compiler tree digest mismatch", restored.stderr)
            (sealed / "nested" / "libapp.so.symbols").write_bytes(b"authentic symbols")
            if sys.platform == "linux":
                swapped = self._custody_run(
                    custody(
                        "/bin/sh -c 'f=\"$1\"/nested/libapp.so.symbols; cp \"$f\" \"$f.keep\"; "
                        "printf substituted > \"$f\"; cat \"$f\" >/dev/null; "
                        "cat \"$f.keep\" > \"$f\"; rm \"$f.keep\"' sh " + shlex.quote(str(canonical))
                    )
                )
                self.assertNotEqual(swapped.returncode, 0, swapped.stdout)
            # A directory not named as authenticated, or authenticated twice, is refused.
            stray = self._custody_run(
                f'run_with_linux_tree_custody --publication-directory-root={shlex.quote(str(canonical))} '
                f'"$(printf "%064d" 0)={shlex.quote(str(sealed))}" -- /bin/sh -c "exit 0"'
            )
            self.assertNotEqual(stray.returncode, 0)
            self.assertIn("not an authenticated tree", stray.stderr)

    def test_the_sealed_directory_digest_frames_every_file_by_its_length(self) -> None:
        # Without a length, one file whose bytes spell the next record equals two files.
        with tempfile.TemporaryDirectory() as raw:
            base = pathlib.Path(raw)
            two, one = base / "two", base / "one"
            two.mkdir()
            one.mkdir()
            (two / "a").write_bytes(b"AAA")
            (two / "b").write_bytes(b"BBB")
            (one / "a").write_bytes(b"AAA" + b"f\0b\0" + b"BBB")
            digests = self._custody_run(f'seal_digest {shlex.quote(str(two))}; echo; seal_digest {shlex.quote(str(one))}')
            self.assertEqual(digests.returncode, 0, digests.stderr)
            first, second = digests.stdout.strip().splitlines()
            self.assertEqual(len(first), 64)
            self.assertNotEqual(first, second)
        # The seal, the assertion, the atomic-publish commit and the tree custody all read it.
        self.assertEqual(SOURCE.count('digest.update(str(child.st_size).encode("ascii") + b"\\0")'), 4)

    def test_shipped_text_files_carry_no_literal_local_user_home_path(self) -> None:
        # The archive scan refuses any member that matches the local-user-home
        # pattern. install.sh once spelled a self-test fixture as
        # "$remove/home/.local/lib/wins-vpn", which matched as "/home/.local/".
        from tools.validate_release_artifact_privacy import LOCAL_USER_HOME_PATH_RE

        shipped = [
            "linux/packaging/install.sh",
            "linux/packaging/RECOVERY.md",
            "linux/packaging/winsvpn-recover",
            "linux/packaging/winsvpn-recover.service",
            "linux/packaging/org.winsvpn.app.desktop",
            "linux/packaging/org.winsvpn.app.metainfo.xml",
            "docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md",
            "tools/native_messaging/install_native_host.sh",
        ]
        for relative in shipped:
            with self.subTest(file=relative):
                text = (ROOT / relative).read_text(encoding="utf-8", errors="replace")
                match = LOCAL_USER_HOME_PATH_RE.search(text)
                self.assertIsNone(match, None if match is None else match.group(0))

    def test_awg_symbol_table_exemption_is_the_same_two_digests_in_every_gate(self) -> None:
        producer_pins = {
            re.search(rf'^{name}="([0-9a-f]{{64}})"$', SOURCE, re.MULTILINE).group(1)
            for name in ("AWG_BINARY_SHA256", "AWG_BINARY_SHA256_ARM64")
        }
        gate = (ROOT / "tools/linux_cross_store_artifact_gate.py").read_text(encoding="utf-8")
        block = gate[gate.index("APPROVED_AWG_SYMBOL_TABLE_SHA256 = frozenset(") :]
        gate_digests = set(re.findall(r'"([0-9a-f]{64})"', block[: block.index("\n)\n")]))
        privacy = (ROOT / "tools/validate_release_artifact_privacy.py").read_text(encoding="utf-8")
        awg = privacy[privacy.index('    "awg": frozenset('):]
        privacy_digests = set(re.findall(r'"([0-9a-f]{64})"', awg[: awg.index("}")]))
        self.assertEqual(gate_digests, producer_pins)
        self.assertEqual(privacy_digests, producer_pins)
        # The gate exemption is only for the member named awg, only for a bare
        # .symtab, and only for those exact bytes.
        self.assertIn('pathlib.PurePosixPath(label).name == "awg"', gate)
        self.assertIn('tuple(inspected[1]) == (".symtab",)', gate)
        self.assertIn('parsed["sha256"] in APPROVED_AWG_SYMBOL_TABLE_SHA256', gate)

    def test_packaged_store_ids_are_the_recorded_file_byte_for_byte(self) -> None:
        function = SOURCE[SOURCE.index("build_and_stage_linux_native_host() {") :]
        function = function[: function.index("\n}\n")]
        self.assertIn(
            'install -D -m 0644 "${ROOT}/tools/native_messaging/manifests/store_ids.json"',
            function,
        )
        # No re-serialization of the ids anywhere in the staging function.
        self.assertNotIn('separators=(",", ":")', function)
        self.assertNotIn('{"chrome": sys.argv[2], "edge": sys.argv[3]}', function)
        # And the gate compares exactly these bytes (the record is a closure input).
        gate = (ROOT / "tools/linux_cross_store_artifact_gate.py").read_text(encoding="utf-8")
        self.assertIn('"tools/native_messaging/manifests/store_ids.json"', gate)
        closure = SOURCE[SOURCE.index("native_host_source_paths() {") :]
        closure = closure[: closure.index("\n}\n")]
        self.assertIn("tools/native_messaging/manifests/store_ids.json", closure)

    def test_every_flutter_sdk_or_pub_cache_custody_carries_its_runtime_root(self) -> None:
        # One shell command per logical line (backslash continuations joined).
        logical = re.sub(r"[ \t]*\\\n\s*", " ", SOURCE).splitlines()
        designations = {
            "WINS_LINUX_FLUTTER_TREE_ROOT": '"--flutter-sdk-root=${WINS_LINUX_FLUTTER_TREE_ROOT:?}"',
            "PUB_CACHE": '"--pub-cache-root=${PUB_CACHE:?}"',
        }
        bindings = 0
        for line in logical:
            for root, designation in designations.items():
                # A custody spec "<pin>=<root>" for the Flutter SDK or Pub cache.
                if re.search(r"\$\{[A-Za-z0-9_]+(?::\?)?\}=\$\{" + root + r"(?::\?)?\}", line):
                    bindings += 1
                    with self.subTest(root=root, line=line.strip()):
                        self.assertIn("run_with_linux_tree_custody", line)
                        self.assertIn(designation, line)
        # Anti-vacuity: run_with_reviewed_flutter_pub_custody binds both trees.
        self.assertGreaterEqual(bindings, 2)

    def test_final_flutter_release_build_runs_through_reviewed_flutter_pub_custody(self) -> None:
        logical = re.sub(r"[ \t]*\\\n\s*", " ", SOURCE).splitlines()
        calls = [line.strip() for line in logical if '"${flutter_release_command[@]}"' in line]
        self.assertEqual(len(calls), 1, calls)
        self.assertTrue(
            calls[0].startswith(
                "run_with_reviewed_flutter_pub_custody /bin/bash -c "
                "'run_with_retained_release_source_custody_at_root \"$@\"' _ "
                '"${ROOT}" "${formal_index_path}" "${flutter_release_command[@]}"'
            ),
            calls[0],
        )
        # The portable self-test drives bin/flutter's engine.stamp.tmp.<pid>
        # replace through that wrapper and through an undesignated SDK root.
        runtime_self_test = SOURCE[
            SOURCE.index("run_linux_tree_custody_runtime_state_self_test() {") : SOURCE.index(
                "verify_linux_winn3_datapath_contract() {"
            )
        ]
        self.assertIn("run_with_reviewed_flutter_pub_custody /bin/sh -c '", runtime_self_test)
        self.assertEqual(runtime_self_test.count('>"$1/bin/cache/engine.stamp.tmp.$$"'), 2)
        self.assertIn("engine.stamp replace in an undesignated Flutter SDK", runtime_self_test)

    def test_snapshot_extractor_needs_no_data_filter_and_skips_only_reviewed_links(self) -> None:
        start = SOURCE.index("winsvpn_extract_snapshot() {\n  python3 -I - \"$@\" <<'PY'\n")
        body_start = SOURCE.index("\n", SOURCE.index("<<'PY'", start)) + 1
        extractor = SOURCE[body_start:SOURCE.index("\nPY\n}", body_start) + 1]
        self.assertNotIn("data_filter", extractor)
        self.assertNotIn("extractall(dest, filter", extractor)
        self.assertIn('"${LINUX_FLUTTER_ARCHIVE_EXCLUDED_LINKS[@]}" || return 65', SOURCE)
        excluded = re.search(
            r"(?ms)^LINUX_FLUTTER_ARCHIVE_EXCLUDED_LINKS=\(\n(.*?)^\)$", SOURCE
        )
        self.assertIsNotNone(excluded)
        self.assertEqual(
            re.findall(r'^  "([^"]+)"$', excluded.group(1), re.M),
            [
                "flutter/.claude/skills=../.agents/skills",
                "flutter/engine/src/flutter/lib/web_ui/test/ui/paragraph_performance_test.dart"
                "=../webparagraph/paragraph_performance_test.dart",
            ],
        )

        def archive(path: pathlib.Path, *links: tuple[str, str]) -> None:
            with tarfile.open(path, "w:gz") as tar:
                for name, data, mode in (
                    ("sdk/bin/tool", b"#!/bin/sh\n", 0o755),
                    ("sdk/README", b"readme\n", 0o640),
                ):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(data), mode, 1790892169
                    tar.addfile(info, io.BytesIO(data))
                for name, target in links:
                    info = tarfile.TarInfo(name)
                    info.type, info.linkname = tarfile.SYMTYPE, target
                    tar.addfile(info)

        def extract(snapshot: pathlib.Path, dest: pathlib.Path, *skips: str):
            return subprocess.run(
                [sys.executable, "-I", "-", str(snapshot), str(dest), "tar.gz", *skips],
                input=extractor,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        with tempfile.TemporaryDirectory(prefix="winsvpn-extract-snapshot-") as raw:
            base = pathlib.Path(raw)
            plain = base / "plain.tar.gz"
            archive(plain)
            done = extract(plain, base / "plain")
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual((base / "plain/sdk/bin/tool").read_bytes(), b"#!/bin/sh\n")
            self.assertEqual((base / "plain/sdk/bin/tool").stat().st_mode & 0o777, 0o755)
            self.assertEqual((base / "plain/sdk/README").stat().st_mode & 0o777, 0o644)
            # Member mtimes survive extraction (Flutter compares pubspec.yaml
            # and pubspec.lock mtimes before deciding to rebuild its tool).
            self.assertEqual(int((base / "plain/sdk/README").stat().st_mtime), 1790892169)
            again = extract(plain, base / "plain")
            self.assertNotEqual(again.returncode, 0)
            self.assertIn("archive extraction target is unsafe", again.stderr)

            linked = base / "linked.tar.gz"
            archive(linked, ("sdk/alias", "bin/tool"))
            refused = extract(linked, base / "linked-refused")
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("archive member type is unsafe: sdk/alias", refused.stderr)
            skipped = extract(linked, base / "linked-skipped", "sdk/alias=bin/tool")
            self.assertEqual(skipped.returncode, 0, skipped.stderr)
            self.assertFalse(os.path.lexists(base / "linked-skipped/sdk/alias"))
            self.assertTrue((base / "linked-skipped/sdk/bin/tool").is_file())
            wrong = extract(linked, base / "linked-wrong", "sdk/alias=elsewhere")
            self.assertNotEqual(wrong.returncode, 0)
            self.assertIn("reviewed archive link exclusion does not match: sdk/alias", wrong.stderr)
            absent = extract(plain, base / "plain-absent", "sdk/alias=bin/tool")
            self.assertNotEqual(absent.returncode, 0)
            self.assertIn("reviewed archive link exclusions are not all present", absent.stderr)

    def test_measure_tree_sha256_prints_the_install_tree_pin_encoding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-measure-tree-") as raw:
            root = pathlib.Path(raw) / "go"
            (root / "bin").mkdir(parents=True)
            (root / "bin/go").write_bytes(b"go-binary")
            (root / "VERSION").write_bytes(b"go1.27.1\n")
            records = sorted(
                f"file {len(data)} {hashlib.sha256(data).hexdigest()} {name}\n"
                for name, data in (("bin/go", b"go-binary"), ("VERSION", b"go1.27.1\n"))
            )
            expected = hashlib.sha256("".join(records).encode("utf-8")).hexdigest()
            measured = run_producer("--measure-tree-sha256", str(root))
            self.assertEqual(measured.returncode, 0, measured.stderr)
            self.assertEqual(measured.stdout, expected + "\n")
            (root / "alias").symlink_to("bin/go")
            refused = run_producer("--measure-tree-sha256", str(root))
            self.assertEqual(refused.returncode, 65, refused.stderr)
            self.assertNotIn(expected, refused.stdout)
        relative = run_producer("--measure-tree-sha256", "go")
        self.assertEqual(relative.returncode, 64, relative.stderr)

    def test_final_aot_runtime_gate_is_retired_and_attestation_is_v2(self) -> None:
        for retired in (
            "prove_final_linux_winn3_dual_auth_aot",
            "--self-test-final-aot-dual-auth-owner-block",
            "winsvpn-linux-final-aot-capability-runtime-v1",
            "FINAL_AOT_RUNTIME_PROOF_SHA256",
            '"runtime_report"',
            "digest-only libapp.so attestation is forbidden",
        ):
            self.assertNotIn(retired, SOURCE)
        self.assertIn('"contract": "winsvpn-linux-winn3-dual-auth-release-v2"', SOURCE)
        self.assertIn('"contract": "winsvpn-linux-compiled-capability-proof-v3"', SOURCE)
        main = SOURCE[SOURCE.index('formal_index_path="$(resolve_release_input_index)"') :]
        self.assertIn('write_linux_winn3_dual_auth_attestation "${BUNDLE_DIR}"\n', main)

    def test_publication_rollback_self_test(self) -> None:
        completed = subprocess.run(
            ["bash", str(ROOT / "tools/build_linux_release.sh"), "--self-test-publication"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "LINUX RELEASE ATOMIC GENERATION PUBLICATION SELF-TEST: PASS",
            completed.stdout,
        )
        self.assertIn("Atomically published immutable Linux unsigned-rehearsal generation", completed.stdout)
        self.assertNotIn("OWNER-BLOCKED", completed.stdout + completed.stderr)
        self.assertIn("private-symbols-v1", SOURCE)
        self.assertIn("did not atomically retain private symbols with each generation", SOURCE)
        self.assertIn(
            "accepted a literal non-cryptographic Sigstore bundle", SOURCE
        )
        self.assertIn("accepted a substituted stage pathname", SOURCE)
        self.assertIn("left an exact partial-commit generation", SOURCE)
        self.assertIn("accepted a hostile archive/checksum swap", SOURCE)
        self.assertIn("retain the authentic archive descriptor", SOURCE)
        self.assertIn(
            "committed bytes mutated after the final custody assertion", SOURCE
        )
        self.assertIn("left a post-assert mutated generation", SOURCE)
        self.assertIn("accepted a same-UID Sigstore-bundle substitution", SOURCE)
        self.assertIn("retain the authentic Sigstore bundle descriptor", SOURCE)
        self.assertIn("accepted a substituted private-symbol member", SOURCE)
        self.assertIn("publication custody directory exceeds its aggregate byte bound", SOURCE)
        self.assertIn("hostile pre-custody replacement", SOURCE)
        self.assertIn("hostile during-hash mutation", SOURCE)
        self.assertIn("same-UID writable descriptor alias", SOURCE)
        self.assertIn("rejected a symlink, hardlink, or special member", SOURCE)
        # Root-only FS_IMMUTABLE_FL custody is replaced by held-digest custody
        # plus single-link and no group/other-write checks.
        self.assertNotIn("FS_IOC_SETFLAGS", SOURCE)
        self.assertNotIn("require_physical_immutable", SOURCE)
        self.assertIn("def require_sealed(", SOURCE)
        self.assertIn("accepted mutation through a pathname alias", SOURCE)
        self.assertIn("accepted a new hardlink alias", SOURCE)
        self.assertIn("accepted a group/other-writable sealed object", SOURCE)

        packaging = SOURCE[SOURCE.index('log "Packaging release bundle"') :]
        self.assertLess(
            packaging.index("begin_linux_signed_publication_custody"),
            packaging.index("LINUX ARCHIVE METADATA: PASS"),
        )
        self.assertLess(
            packaging.index("write_staged_archive_checksum"),
            packaging.index("LINUX ARCHIVE METADATA: PASS"),
        )
        commit_start = SOURCE.index("commit_linux_publication()")
        commit_end = SOURCE.index("run_publication_transaction_self_test()", commit_start)
        commit = SOURCE[commit_start:commit_end]
        self.assertIn('"${publication_custody_specs[@]}"', commit)
        self.assertLess(
            commit.index("atomic_publish_linux_generation"),
            commit.index("publication_committed=1"),
        )
        self.assertNotIn(
            "verify_linux_signature \"${ARCHIVE}\"",
            commit[commit.index("atomic_publish_linux_generation") :],
        )

    def test_retained_source_custody_accepts_every_field_the_freeze_controller_writes(self) -> None:
        controller = (ROOT / "tools/release_dependency_freeze.py").read_text(encoding="utf-8")
        state = controller[controller.index("def _state_record(") :]
        written_block = state.split("record: dict[str, object] = {", 1)[1].split("    if include_files:", 1)[0]
        written = set(re.findall(r'^ {8}"([a-z_0-9]+)": ', written_block, re.MULTILINE)) | {"files"}
        self.assertEqual(written, {"files", "file_count", "fingerprint_sha256", "git_audit", "total_bytes"})
        custody = SOURCE[
            SOURCE.index("run_with_retained_release_source_custody_at_root() {") : SOURCE.index(
                "run_with_retained_release_source_custody() {"
            )
        ]
        ceiling = re.search(r"<= set\(collection\) <= \{(.*?)\}", custody, re.DOTALL)
        self.assertIsNotNone(ceiling)
        self.assertEqual(set(re.findall(r'"([a-z_0-9]+)"', ceiling.group(1))), written)

    def test_retained_source_custody_raises_a_low_descriptor_limit_for_the_input_count(self) -> None:
        # The custody holds one descriptor per release input (about 1800 in a
        # real release) while a docker container or login shell starts with a
        # soft limit of 1024 or fewer. A soft limit below the input count made
        # the producer die with "Too many open files" at the first held input
        # past the limit.
        custody = SOURCE[
            SOURCE.index("run_with_retained_release_source_custody_at_root() {") : SOURCE.index(
                "run_with_retained_release_source_custody() {"
            )
        ]
        marker = "<<'PY'\n"
        first = custody.index(marker) + len(marker)
        script = custody[first : custody.index("\nPY\n", first) + 1]
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw) / "repo"
            index_dir = root / ".artifacts" / "index"
            index_dir.mkdir(parents=True)
            (root / "src").mkdir()
            files = []
            for number in range(400):
                payload = f"input-{number}\n".encode("ascii")
                (root / "src" / f"f{number}.txt").write_bytes(payload)
                files.append(
                    {
                        "path": f"src/f{number}.txt",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size": len(payload),
                    }
                )

            def collection(members: list[dict[str, object]]) -> dict[str, object]:
                return {
                    "file_count": len(members),
                    "files": members,
                    "fingerprint_sha256": "7" * 64,
                    "git_audit": None,
                    "total_bytes": sum(int(item["size"]) for item in members),
                }

            documents = {
                "SHARED_INPUTS.json": {
                    "contract": "winsvpn-shared-inputs-v1",
                    "created_utc": "2026-10-21T00:00:00Z",
                    "generated_outputs_excluded": True,
                    "inputs": collection(files),
                    "publication_authorized": False,
                    "release": "fixture",
                    "roots": ["."],
                    "schema_version": 1,
                    "shared_revision": "0" * 40,
                },
                "LINUX_INPUTS.json": {
                    "artifact_input_fingerprint_sha256": "1" * 64,
                    "contract": "winsvpn-platform-inputs-v1",
                    "created_utc": "2026-10-21T00:00:00Z",
                    "generated_outputs_excluded": True,
                    "native_extra_paths": [],
                    "native_inputs": collection([]),
                    "native_only_change_invalidates_only_this_platform": True,
                    "native_roots": [],
                    "platform": "linux",
                    "producer_inputs": collection([]),
                    "producer_paths": [],
                    "publication_authorized": False,
                    "release": "fixture",
                    "schema_version": 1,
                    "shared": {"path": "SHARED_INPUTS.json", "sha256": "2" * 64},
                },
                "RELEASE_INPUT_INDEX.json": {
                    "contract": "winsvpn-release-input-index-v1",
                    "created_utc": "2026-10-21T00:00:00Z",
                    "manifest_set_complete": True,
                    "platform_manifests": {
                        name: {
                            "artifact_input_fingerprint_sha256": "3" * 64,
                            "path": "LINUX_INPUTS.json",
                            "sha256": "4" * 64,
                        }
                        for name in ("android", "wear_os", "ios", "macos", "windows", "linux", "extension")
                    },
                    "publication_authorized": False,
                    "release": "fixture",
                    "schema_version": 1,
                    "sha256_anchor": "RELEASE_INPUT_INDEX.json.sha256",
                    "shared_manifest": {"path": "SHARED_INPUTS.json", "sha256": "2" * 64},
                    "shared_revision": "0" * 40,
                },
            }
            for name, document in documents.items():
                (index_dir / name).write_text(json.dumps(document, sort_keys=True) + "\n", encoding="ascii")
            # `ulimit -S` lowers only the soft limit, so the hard limit stays high.
            completed = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    'ulimit -S -n 200 && exec "$0" -I - "$@"',
                    sys.executable,
                    str(root),
                    str(index_dir / "RELEASE_INPUT_INDEX.json"),
                    "1",
                    "/bin/sh",
                    "-c",
                    "exit 0",
                ],
                input=script,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_retained_source_custody_keeps_the_localization_outputs_under_full_custody(self) -> None:
        custody = SOURCE[
            SOURCE.index("run_with_retained_release_source_custody_at_root() {") : SOURCE.index(
                "run_with_retained_release_source_custody() {"
            )
        ]
        marker = "<<'PY'\n"
        first = custody.index(marker) + len(marker)
        script = custody[first : custody.index("\nPY\n", first) + 1]
        # No input is exempt from the watch or from the retained-inode check. The
        # three generated outputs are whatever `flutter gen-l10n` writes for this
        # repository (l10n.yaml: output-localization-file plus one file per
        # template ARB locale).
        self.assertNotIn("REGENERATED_INPUTS", script)
        self.assertNotIn("file_watch", script)
        config = (ROOT / "l10n.yaml").read_text(encoding="utf-8")
        output = re.search(r"^output-localization-file:\s*(\S+)\s*$", config, re.MULTILINE).group(1)
        stem = output[: -len(".dart")]
        locales = sorted(
            path.stem[len("app_") :] for path in (ROOT / "lib/l10n").glob("app_*.arb")
        )
        regenerated = {
            f"lib/l10n/{output}",
            *(f"lib/l10n/{stem}_{locale}.dart" for locale in locales),
        }
        # Every one of them is a tracked, indexed compiler input in the fixture below.
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw) / "repo"
            index_dir = root / ".artifacts" / "index"
            index_dir.mkdir(parents=True)
            (root / "lib/l10n").mkdir(parents=True)
            (root / "src").mkdir()
            members = {name: f"generated {name}\n".encode("ascii") for name in sorted(regenerated)}
            members["src/plain.txt"] = b"plain input\n"
            files = []
            for name, payload in members.items():
                (root / name).write_bytes(payload)
                files.append({"path": name, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)})
            collection = {
                "file_count": len(files),
                "files": files,
                "fingerprint_sha256": "7" * 64,
                "git_audit": None,
                "total_bytes": sum(item["size"] for item in files),
            }
            empty = dict(collection, file_count=0, files=[], total_bytes=0)
            documents = {
                "SHARED_INPUTS.json": {
                    "contract": "winsvpn-shared-inputs-v1",
                    "created_utc": "2026-10-21T00:00:00Z",
                    "generated_outputs_excluded": True,
                    "inputs": collection,
                    "publication_authorized": False,
                    "release": "fixture",
                    "roots": ["."],
                    "schema_version": 1,
                    "shared_revision": "0" * 40,
                },
                "LINUX_INPUTS.json": {
                    "artifact_input_fingerprint_sha256": "1" * 64,
                    "contract": "winsvpn-platform-inputs-v1",
                    "created_utc": "2026-10-21T00:00:00Z",
                    "generated_outputs_excluded": True,
                    "native_extra_paths": [],
                    "native_inputs": empty,
                    "native_only_change_invalidates_only_this_platform": True,
                    "native_roots": [],
                    "platform": "linux",
                    "producer_inputs": empty,
                    "producer_paths": [],
                    "publication_authorized": False,
                    "release": "fixture",
                    "schema_version": 1,
                    "shared": {"path": "SHARED_INPUTS.json", "sha256": "2" * 64},
                },
                "RELEASE_INPUT_INDEX.json": {
                    "contract": "winsvpn-release-input-index-v1",
                    "created_utc": "2026-10-21T00:00:00Z",
                    "manifest_set_complete": True,
                    "platform_manifests": {
                        name: {
                            "artifact_input_fingerprint_sha256": "3" * 64,
                            "path": "LINUX_INPUTS.json",
                            "sha256": "4" * 64,
                        }
                        for name in ("android", "wear_os", "ios", "macos", "windows", "linux", "extension")
                    },
                    "publication_authorized": False,
                    "release": "fixture",
                    "schema_version": 1,
                    "sha256_anchor": "RELEASE_INPUT_INDEX.json.sha256",
                    "shared_manifest": {"path": "SHARED_INPUTS.json", "sha256": "2" * 64},
                    "shared_revision": "0" * 40,
                },
            }
            for name, document in documents.items():
                (index_dir / name).write_text(json.dumps(document, sort_keys=True) + "\n", encoding="ascii")
            index = str(index_dir / "RELEASE_INPUT_INDEX.json")

            def run(shell: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, "-I", "-", str(root), index, "1", "/bin/sh", "-c", shell],
                    input=script,
                    capture_output=True,
                    text=True,
                    check=False,
                )

            sealed = members["lib/l10n/app_localizations.dart"]
            generator_config = b"arb-dir: lib/l10n\ntemplate-arb-file: app_en.arb\n"
            (root / "l10n.yaml").write_bytes(generator_config)
            config_inode = (root / "l10n.yaml").stat().st_ino

            # The reported attack: replace a compiler input, read the replacement as the
            # compiler would, restore the indexed bytes. Hashing the final bytes cannot
            # show what was read, so the replacement itself must be refused.
            restored = run(
                'cp lib/l10n/app_localizations.dart saved.dart && '
                'printf "tampered\\n" > lib/l10n/app_localizations.dart && '
                'cat lib/l10n/app_localizations.dart && '
                'cat saved.dart > lib/l10n/app_localizations.dart && rm saved.dart'
            )
            self.assertIn("tampered", restored.stdout)
            self.assertNotEqual(restored.returncode, 0, restored.stdout)
            self.assertEqual((root / "lib/l10n/app_localizations.dart").read_bytes(), sealed)
            self.assertEqual((root / "l10n.yaml").read_bytes(), generator_config)

            # Even an identical in-place rewrite of an output is a rewrite of a compiler
            # input: the build must not do it, so it is refused like any other input.
            same = run('printf "generated lib/l10n/app_localizations.dart\\n" > lib/l10n/app_localizations.dart')
            self.assertNotEqual(same.returncode, 0, same.stderr)
            changed = run('printf "tampered\\n" > lib/l10n/app_localizations_en.dart')
            self.assertNotEqual(changed.returncode, 0)
            (root / "lib/l10n/app_localizations_en.dart").write_bytes(members["lib/l10n/app_localizations_en.dart"])
            plain = run('printf "plain input\\n" > src/plain.txt')
            self.assertNotEqual(plain.returncode, 0)

            # What the Flutter tool does: gen_localizations rewrites the outputs only while
            # l10n.yaml exists, and the compile then reads them. With the generator
            # configuration set aside for the run, the same command leaves every output
            # untouched, so the compile reads exactly the indexed bytes and the run passes.
            flutter_like = (
                'if [ -e l10n.yaml ]; then '
                'for f in lib/l10n/app_localizations*.dart; do c="$(cat "$f")"; printf "%s\\n" "$c" > "$f"; done; fi; '
                'cat lib/l10n/app_localizations*.dart > compiled.txt'
            )
            built = run(flutter_like)
            self.assertEqual(built.returncode, 0, built.stderr)
            self.assertEqual(
                (root / "compiled.txt").read_bytes(),
                b"".join(members[name] for name in sorted(regenerated)),
            )
            (root / "compiled.txt").unlink()
            # The configuration is back, byte for byte and on the same inode, with
            # nothing left beside it.
            self.assertEqual((root / "l10n.yaml").read_bytes(), generator_config)
            self.assertEqual((root / "l10n.yaml").stat().st_ino, config_inode)
            self.assertEqual((root / "l10n.yaml").stat().st_nlink, 1)
            self.assertEqual([item.name for item in root.iterdir() if "l10n" in item.name], ["l10n.yaml"])

            # A failing compile still gets the configuration back and keeps its status.
            failed = run('test ! -e l10n.yaml && exit 7')
            self.assertEqual(failed.returncode, 7, failed.stderr)
            self.assertEqual((root / "l10n.yaml").read_bytes(), generator_config)

            parked = root / "l10n.yaml.source-custody-suspended"

            def reset() -> int:
                for name in (parked.name, "l10n.yaml", "compiler-started"):
                    (root / name).unlink(missing_ok=True)
                (root / "l10n.yaml").write_bytes(generator_config)
                return (root / "l10n.yaml").stat().st_ino

            # D02-05. The absent name is watched for the whole compile: a configuration that
            # exists only while the compiler runs (created, read, deleted) is refused. Needs
            # inotify, so it runs on Linux.
            if sys.platform == "linux":
                with self.subTest(finding="D02-05 transient configuration"):
                    config_inode = reset()
                    transient = run('printf "arb-dir: elsewhere\\n" > l10n.yaml; cat l10n.yaml; rm l10n.yaml')
                    self.assertNotEqual(transient.returncode, 0, transient.stdout)
                    self.assertIn("arb-dir: elsewhere", transient.stdout)
                    self.assertEqual((root / "l10n.yaml").read_bytes(), generator_config)
                    self.assertEqual((root / "l10n.yaml").stat().st_ino, config_inode)

            # D02-05. The parked original is held and hashed, so rewriting it is refused and
            # the altered bytes are never restored as l10n.yaml.
            with self.subTest(finding="D02-05 parked file rewritten"):
                reset()
                modified = run('printf "altered\\n" > l10n.yaml.source-custody-suspended')
                self.assertNotEqual(modified.returncode, 0)
                self.assertFalse((root / "l10n.yaml").exists())
                self.assertEqual(parked.read_bytes(), b"altered\n")

            # D02-06. A parked original left by an interrupted run is checked before anything
            # else, with or without a live l10n.yaml, and the compiler does not run.
            with self.subTest(finding="D02-06 stale parked file"):
                reset()
                (root / "l10n.yaml").rename(parked)
                stale = run('printf "compiler must not run"')
                self.assertNotEqual(stale.returncode, 0)
                self.assertNotIn("compiler must not run", stale.stdout)
                self.assertIn("earlier run was interrupted", stale.stderr)
                self.assertEqual(parked.read_bytes(), generator_config)
                (root / "l10n.yaml").write_bytes(b"live copy beside the parked one\n")
                both = run('printf "compiler must not run"')
                self.assertNotEqual(both.returncode, 0)
                self.assertNotIn("compiler must not run", both.stdout)

            # D02-06. SIGTERM and SIGHUP unwind through the finally block: the original is back
            # (same inode) and the run fails. SIGKILL cannot, and the next run refuses.
            def interrupted(signum: int) -> subprocess.Popen:
                marker = root / "compiler-started"
                marker.unlink(missing_ok=True)

                def default_dispositions() -> None:
                    # The wrapper keeps a signal that was ignored at start ignored (F-01), so a
                    # runner started under nohup or setsid must not pass its SIG_IGN on.
                    for number in (signal.SIGTERM, signal.SIGHUP):
                        signal.signal(number, signal.SIG_DFL)

                process = subprocess.Popen(
                    [sys.executable, "-I", "-", str(root), index, "1", "/bin/sh", "-c",
                     "touch compiler-started; exec sleep 60"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    preexec_fn=default_dispositions,
                )
                process.stdin.write(script)
                process.stdin.close()
                for _attempt in range(200):
                    if marker.exists():
                        break
                    time.sleep(0.05)
                self.assertTrue(marker.exists(), "the compiler command did not start")
                process.send_signal(signum)
                process.wait(timeout=30)
                process.stdout.close()
                process.stderr.close()
                marker.unlink(missing_ok=True)
                return process

            for signum in (signal.SIGTERM, signal.SIGHUP):
                with self.subTest(finding="D02-06 interrupted by", signal=signum.name):
                    config_inode = reset()
                    process = interrupted(signum)
                    self.assertNotEqual(process.returncode, 0)
                    self.assertEqual((root / "l10n.yaml").read_bytes(), generator_config)
                    self.assertEqual((root / "l10n.yaml").stat().st_ino, config_inode)
                    self.assertFalse(parked.exists())
            with self.subTest(finding="D02-06 killed"):
                reset()
                interrupted(signal.SIGKILL)
                self.assertTrue(parked.exists() and not (root / "l10n.yaml").exists())
                after_kill = run('printf "compiler must not run"')
                self.assertNotEqual(after_kill.returncode, 0)
                self.assertNotIn("compiler must not run", after_kill.stdout)
                parked.rename(root / "l10n.yaml")
                self.assertEqual(run('exit 0').returncode, 0)

            reset()
            # A configuration recreated while it is set aside is refused, and the original
            # stays beside it for inspection instead of being overwritten.
            recreated = run('printf "arb-dir: elsewhere\\n" > l10n.yaml')
            self.assertNotEqual(recreated.returncode, 0)
            self.assertIn("recreated while it was suspended", recreated.stderr)
            self.assertEqual((root / "l10n.yaml").read_bytes(), b"arb-dir: elsewhere\n")
            self.assertEqual(
                (root / "l10n.yaml.source-custody-suspended").read_bytes(), generator_config
            )

    def test_an_ignored_hangup_stays_ignored_and_a_default_terminate_still_unwinds(self) -> None:
        # F-01. A build launched with nohup or setsid ignores SIGHUP on purpose. The custody
        # wrapper used to replace that with an unwind, so closing the terminal ended the
        # compile. A signal that was ignored at start now stays ignored, and one with its
        # default disposition still restores the generator configuration and fails.
        custody = SOURCE[
            SOURCE.index("run_with_retained_release_source_custody_at_root() {") : SOURCE.index(
                "run_with_retained_release_source_custody() {"
            )
        ]
        marker = "<<'PY'\n"
        first = custody.index(marker) + len(marker)
        script = custody[first : custody.index("\nPY\n", first) + 1]
        self.assertIn("signal.getsignal(getattr(signal, signal_name)) != signal.SIG_IGN", script)
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw) / "repo"
            index_dir = root / ".artifacts" / "index"
            index_dir.mkdir(parents=True)
            (root / "src").mkdir()
            payload = b"plain input\n"
            (root / "src" / "plain.txt").write_bytes(payload)
            config = b"arb-dir: lib/l10n\n"
            collection = {
                "file_count": 1,
                "files": [
                    {"path": "src/plain.txt", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
                ],
                "fingerprint_sha256": "7" * 64,
                "git_audit": None,
                "total_bytes": len(payload),
            }
            empty = dict(collection, file_count=0, files=[], total_bytes=0)
            documents = {
                "SHARED_INPUTS.json": {
                    "contract": "winsvpn-shared-inputs-v1", "created_utc": "2026-10-21T00:00:00Z",
                    "generated_outputs_excluded": True, "inputs": collection,
                    "publication_authorized": False, "release": "fixture", "roots": ["."],
                    "schema_version": 1, "shared_revision": "0" * 40,
                },
                "LINUX_INPUTS.json": {
                    "artifact_input_fingerprint_sha256": "1" * 64, "contract": "winsvpn-platform-inputs-v1",
                    "created_utc": "2026-10-21T00:00:00Z", "generated_outputs_excluded": True,
                    "native_extra_paths": [], "native_inputs": empty,
                    "native_only_change_invalidates_only_this_platform": True, "native_roots": [],
                    "platform": "linux", "producer_inputs": empty, "producer_paths": [],
                    "publication_authorized": False, "release": "fixture", "schema_version": 1,
                    "shared": {"path": "SHARED_INPUTS.json", "sha256": "2" * 64},
                },
                "RELEASE_INPUT_INDEX.json": {
                    "contract": "winsvpn-release-input-index-v1", "created_utc": "2026-10-21T00:00:00Z",
                    "manifest_set_complete": True,
                    "platform_manifests": {
                        name: {
                            "artifact_input_fingerprint_sha256": "3" * 64,
                            "path": "LINUX_INPUTS.json", "sha256": "4" * 64,
                        }
                        for name in ("android", "wear_os", "ios", "macos", "windows", "linux", "extension")
                    },
                    "publication_authorized": False, "release": "fixture", "schema_version": 1,
                    "sha256_anchor": "RELEASE_INPUT_INDEX.json.sha256",
                    "shared_manifest": {"path": "SHARED_INPUTS.json", "sha256": "2" * 64},
                    "shared_revision": "0" * 40,
                },
            }
            for name, document in documents.items():
                (index_dir / name).write_text(json.dumps(document, sort_keys=True) + "\n", encoding="ascii")
            index = str(index_dir / "RELEASE_INPUT_INDEX.json")

            def launch(ignored: tuple, command: str) -> subprocess.Popen:
                def child_setup() -> None:
                    for number in (signal.SIGTERM, signal.SIGHUP):
                        signal.signal(number, signal.SIG_IGN if number in ignored else signal.SIG_DFL)

                process = subprocess.Popen(
                    [sys.executable, "-I", "-", str(root), index, "1", "/bin/sh", "-c", command],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, preexec_fn=child_setup,
                )
                process.stdin.write(script)
                process.stdin.close()
                for _attempt in range(200):
                    if (root / "started").exists():
                        break
                    time.sleep(0.05)
                self.assertTrue((root / "started").exists(), "the compiler command did not start")
                return process

            def finish(process: subprocess.Popen) -> str:
                # stdin was closed after the script was written, so wait and read the pipes
                # directly instead of communicate(), which flushes stdin on older Pythons.
                process.wait(timeout=60)
                err = process.stderr.read()
                process.stdout.close()
                process.stderr.close()
                return err

            def reset() -> int:
                for name in ("started", "finished", "l10n.yaml", "l10n.yaml.source-custody-suspended"):
                    (root / name).unlink(missing_ok=True)
                (root / "l10n.yaml").write_bytes(config)
                return (root / "l10n.yaml").stat().st_ino

            # Plain redirections create the marker files: touch also raises IN_ATTRIB on the
            # watched repository directory, which the source custody correctly treats as a change.
            survives = ": > started; sleep 2; : > finished"
            unwinds = ": > started; exec sleep 5"
            for number in (signal.SIGHUP, signal.SIGTERM):
                with self.subTest(case="ignored", signal=number.name):
                    inode = reset()
                    process = launch((number,), survives)
                    process.send_signal(number)
                    err = finish(process)
                    self.assertEqual(process.returncode, 0, err)
                    self.assertTrue((root / "finished").exists(), "the compile must keep running")
                    self.assertEqual((root / "l10n.yaml").read_bytes(), config)
                    self.assertEqual((root / "l10n.yaml").stat().st_ino, inode)
                with self.subTest(case="default", signal=number.name):
                    inode = reset()
                    process = launch((), unwinds)
                    process.send_signal(number)
                    err = finish(process)
                    self.assertNotEqual(process.returncode, 0)
                    self.assertEqual((root / "l10n.yaml").read_bytes(), config)
                    self.assertEqual((root / "l10n.yaml").stat().st_ino, inode)
                    self.assertFalse((root / "l10n.yaml.source-custody-suspended").exists())

    def test_retained_release_source_custody_rejects_compiler_time_mutation(self) -> None:
        completed = subprocess.run(
            [
                "bash",
                str(PRODUCER),
                "--self-test-retained-release-source-custody",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("LINUX RETAINED RELEASE SOURCE CUSTODY SELF-TEST: PASS", completed.stdout)
        custody = SOURCE[
            SOURCE.index("run_with_retained_release_source_custody_at_root() {") : SOURCE.index(
                "run_with_retained_release_source_custody() {"
            )
        ]
        self.assertNotIn("not owner-provisioned", custody)
        self.assertNotIn("owner_blocked", custody)

    def test_xray_is_mandatory_and_skip_switch_fails_before_build(self) -> None:
        self.assertIn("reject_unsupported_release_switches", SOURCE)
        self.assertIn("SKIP_XRAY_DOWNLOAD is not supported for a release build", SOURCE)
        self.assertIn('log "Building mandatory pinned Xray', SOURCE)
        self.assertNotIn("Skipping Xray bundling", SOURCE)
        main = SOURCE[SOURCE.index('formal_index_path="$(resolve_release_input_index)"') :]
        self.assertLess(
            main.index("reject_unsupported_release_switches"),
            main.index('"${FLUTTER_COMMAND}" pub get'),
        )

    def test_store_engine_staging_is_explicit_architecture_bound_and_not_from_flutter_bundle(self) -> None:
        self.assertIn("stage_linux_engine_payloads() {", SOURCE)
        self.assertIn('if [[ "${1:-}" == "--stage-engines" ]]; then', SOURCE)
        self.assertIn('stage_linux_engine_payloads "${BUNDLE_DIR}"', SOURCE)
        self.assertIn("refusing to stage store engines into a Flutter linux bundle.", SOURCE)
        self.assertIn("refusing architecture-mismatched engine staging", SOURCE)
        self.assertIn("Flutter's install tree does not produce them.", SOURCE)
        self.assertIn("store engine staging requires declared local source artifacts", SOURCE)
        self.assertIn("WINS_ENGINE_SOURCE_ROOT", SOURCE)
        self.assertIn("linux/packaging/store_engine_bind.py", SOURCE)
        self.assertIn("export GOPROXY=off", SOURCE)
        self.assertIn('export GOMODCACHE="${WINS_STORE_GOMODCACHE:?}"', SOURCE)
        self.assertIn('if [[ "${store_sources}" != "1" ]]; then', SOURCE)
        self.assertIn("clang version 14.0.6", SOURCE)
        self.assertIn("/usr/bin/clang", SOURCE)
        self.assertIn("arm64 AWG clang must be the package executable", SOURCE)
        self.assertIn("binutils 2.40-2", SOURCE)
        self.assertIn("awg-prebuilt", SOURCE)
        self.assertIn('winn_digest="$(winsvpn_sha256_bind_file "$tmp_dir/winn/winn-datapath")"', SOURCE)
        self.assertIn("winsvpn_stage_bound_engine", SOURCE)
        self.assertIn('winsvpn_stage_bound_engine "$tmp_dir/awg"', SOURCE)
        self.assertIn('winsvpn_stage_bound_engine "$tmp_dir/xray/xray"', SOURCE)
        self.assertIn("Inherited Go custody is forbidden", SOURCE)
        self.assertIn('/usr/bin/env -i "${constructed_env[@]}"', SOURCE)
        self.assertIn('WINS_RELEASE_GO_HELD_PATH="/proc/$$/fd/', SOURCE)
        self.assertIn("wins_release_go_verify", SOURCE)
        self.assertIn('WINS_WINN_SOURCE_ROOT="${tmp_dir}/winn-source"', SOURCE)
        self.assertIn('cp -a -- "${winn_declared_source}/."', SOURCE)
        self.assertIn("wins_release_go_run", SOURCE)
        self.assertIn("prepare_linux_reviewed_go_for_engines", SOURCE)
        native = SOURCE.index('build_and_stage_linux_native_host "${BUNDLE_DIR}" "${tmp_dir}"')
        engines = SOURCE.index('stage_linux_engine_payloads "${BUNDLE_DIR}"', native)
        manifest = SOURCE.index('log "Generating exhaustive release manifest"', engines)
        self.assertLess(native, engines)
        self.assertLess(engines, manifest)
        stage = SOURCE[
            SOURCE.index("stage_linux_engine_payloads() {") : SOURCE.index(
                "acquire_build_lock() {"
            )
        ]
        winn_idx = stage.index("Building mandatory Winn Protocol v3 engine")
        self.assertLess(
            winn_idx,
            stage.index("Bundling pinned AmneziaWG tools"),
        )
        self.assertLess(
            winn_idx,
            stage.index("Building mandatory linux-arm64 AmneziaWG"),
        )
        self.assertLess(
            stage.index("Building pinned AmneziaWG userspace fallback"),
            stage.index("Building mandatory pinned Xray"),
        )
        self.assertLess(stage.index("store_engine_bind.py"), winn_idx)
        self.assertLess(stage.index("export GOPROXY=off"), winn_idx)
        self.assertLess(
            stage.index('export GOMODCACHE="${WINS_STORE_GOMODCACHE:?}"'),
            winn_idx,
        )
        stage_flag = SOURCE.index('if [[ "${1:-}" == "--stage-engines" ]]; then')
        self.assertLess(
            stage_flag,
            SOURCE.index('if [[ "$(uname -s)" != "Linux" ]]; then'),
        )
        self.assertLess(
            stage_flag,
            SOURCE.index('bind_linux_obfuscation_paths "${LINUX_RELEASE_ARCH_LABEL}"'),
        )
        self.assertLess(stage_flag, SOURCE.index("acquire_build_lock", stage_flag))
        with tempfile.TemporaryDirectory() as temporary:
            bundle = (
                pathlib.Path(temporary) / "build" / "linux" / "x64" / "release" / "bundle"
            )
            bundle.mkdir(parents=True)
            completed = subprocess.run(
                ["bash", str(PRODUCER), "--stage-engines", str(bundle), "x64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertRegex(
            completed.stderr,
            r"must run on Linux|refusing to stage store engines into a Flutter linux bundle|"
            r"refusing architecture-mismatched engine staging",
        )

    def test_exact_canonical_flutter_command_is_verified_and_invoked(self) -> None:
        self.assertIn('readonly LINUX_SYSTEM_PYTHON="/usr/bin/python3"', SOURCE)
        self.assertIn('"${LINUX_SYSTEM_PYTHON}" -I -S -', SOURCE)
        hostile_function = r'''
python3() {
  printf 'WINSVPN_HOSTILE_PYTHON_EXECUTED\n' >&2
  local key="${!#}"
  case "${key}" in
    tools.flutter.version|tools.flutter.dart_version) printf '99.99.99' ;;
    tools.flutter.revision) printf '%040d' 0 ;;
    tools.*sha256*|tools.go.executable_sha256_by_platform.*|tools.linux.go.install_tree_sha256.*)
      printf '%064d' 0
      ;;
    *) command /usr/bin/python3 "$@" ;;
  esac
}
export -f python3
'''
        # The live pins carry every Linux Flutter, Pub and Go pin, so both
        # self-tests pass, reading the pins with the literal system Python:
        # the hostile PATH python3 (which would forge all-zero pins) is never
        # executed.
        for self_test, expected_rc, marker in (
            ("--self-test-linux-flutter-pub-pins", 0, "LINUX FLUTTER/PUB TOOLCHAIN PINS: PASS"),
            ("--self-test-linux-go-pins", 0, "LINUX GO TOOLCHAIN PINS: PASS"),
        ):
            completed = subprocess.run(
                ["bash", "-c", hostile_function + 'exec bash "$1" "$2"', "_", str(PRODUCER), self_test],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, expected_rc, completed.stderr)
            self.assertIn(marker, completed.stdout + completed.stderr)
            self.assertNotIn("WINSVPN_HOSTILE_PYTHON_EXECUTED", completed.stderr)

        self.assertIn("prepare_pinned_linux_flutter_and_pub", SOURCE)
        self.assertIn("tools.linux.flutter.archive_sha256.linux_amd64", SOURCE)
        self.assertIn("tools.linux.flutter.archive_sha256.linux_arm64", SOURCE)
        self.assertIn("tools.linux.flutter.install_tree_sha256.linux_amd64", SOURCE)
        self.assertIn("tools.linux.flutter_pub_cache.archive_sha256.linux_amd64", SOURCE)
        self.assertIn("tools.linux.flutter_pub_cache.install_tree_sha256.linux_arm64", SOURCE)
        self.assertIn("tools.linux.go.install_tree_sha256.linux_amd64", SOURCE)
        self.assertIn("tools.go.executable_sha256_by_platform.linux_arm64", SOURCE)
        self.assertNotIn("tools.flutter.archive_sha256.linux_", SOURCE)
        self.assertNotIn("tools.flutter_pub_cache.archive_sha256.linux_", SOURCE)
        self.assertNotIn("tools.go.install_tree_sha256.linux_", SOURCE)
        self.assertIn('FLUTTER_COMMAND="${toolchain_root}/flutter/flutter/bin/flutter"', SOURCE)
        self.assertIn('PUB_CACHE="${toolchain_root}/pub/pub-cache"', SOURCE)
        self.assertIn("pub get --offline --enforce-lockfile", SOURCE)
        for invocation in (
            '"${FLUTTER_COMMAND}" --version --machine',
            '"${FLUTTER_COMMAND}" config --enable-linux-desktop',
            '"${FLUTTER_COMMAND}" pub get',
            '"${FLUTTER_COMMAND}" analyze lib test',
            '"${FLUTTER_COMMAND}" test',
            '"${FLUTTER_COMMAND}" build linux --release --obfuscate',
        ):
            self.assertIn(invocation, SOURCE)
        self.assertIsNone(re.search(r"(?m)^flutter\s", SOURCE))
        self.assertIsNone(re.search(r'(?m)^"\$\{FLUTTER_COMMAND\}"', SOURCE))
        self.assertGreaterEqual(
            SOURCE.count("run_with_reviewed_flutter_pub_custody"), 9
        )
        self.assertIn("WINS_LINUX_FLUTTER_TREE_SHA256", SOURCE)
        self.assertIn("WINS_LINUX_PUB_CACHE_TREE_SHA256", SOURCE)
        self.assertIn("authenticated compiler tree changed while the compiler was running", SOURCE)
        self.assertIn("WINS_STORE_GOMODCACHE_TREE_SHA256", SOURCE)
        self.assertIn('custody_specs+=("${WINS_STORE_GOMODCACHE_TREE_SHA256}=${GOMODCACHE}")', SOURCE)
        self.assertIn("run_with_retained_release_source_custody", SOURCE)
        self.assertIn("release compiler input bytes changed through the retained descriptor", SOURCE)
        self.assertIn('held.append((relative, path, fd, opened, expected_digest))', SOURCE)

    def test_missing_linux_pins_are_plain_refusals_naming_the_pin(self) -> None:
        cases = (
            (
                "--self-test-linux-flutter-pub-pins",
                "RELEASE REFUSED: missing exact Linux Flutter/Pub pins: tools.linux.flutter.archive_sha256.linux_amd64",
                "; measure them on a Linux host from the reviewed archives (archive_sha256: sha256sum of the "
                "Flutter SDK .tar.xz or Pub cache .tar.gz; install_tree_sha256: bash tools/build_linux_release.sh "
                "--measure-tree-sha256 <extracted flutter or pub-cache dir>)",
            ),
            (
                "--self-test-linux-go-pins",
                "RELEASE REFUSED: missing exact Linux Go executable/tree pins: tools.go.executable_sha256_by_platform.linux_amd64",
                "; measure them from the pinned go1.27.1.linux-<arch>.tar.gz (executable_sha256_by_platform: "
                "sha256sum go/bin/go; install_tree_sha256: bash tools/build_linux_release.sh "
                "--measure-tree-sha256 <extracted go dir>)",
            ),
        )
        # The live pins now hold the Linux pins, so the refusals are exercised
        # on a fixture copy of the pin file with every Linux pin removed.
        with tempfile.TemporaryDirectory(prefix="winsvpn-missing-linux-pins-") as raw:
            producer = producer_fixture_root(pathlib.Path(raw))
            pins_path = pathlib.Path(raw) / "tools/toolchain-pins.json"
            pins = json.loads(pins_path.read_text(encoding="utf-8"))
            pins["tools"].pop("linux")
            pins["tools"]["go"].pop("executable_sha256_by_platform")
            pins_path.write_text(json.dumps(pins, indent=2) + "\n", encoding="utf-8")
            for switch, marker, hint in cases:
                with self.subTest(switch=switch):
                    completed = subprocess.run(
                        ["bash", str(producer), switch],
                        cwd=raw,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 65, completed.stderr)
                    self.assertIn(marker, completed.stderr)
                    self.assertIn(hint, completed.stderr)
                    self.assertIn("--measure-tree-sha256", completed.stderr)
                    self.assertIn("record them in tools/toolchain-pins.json", completed.stderr)
                    self.assertNotIn("OWNER-BLOCKED", completed.stderr)
        clang = "tools.linux.arm64.clang_executable_sha256 is absent from tools/toolchain-pins.json"
        self.assertEqual(SOURCE.count(f'release_refused "{clang}'), 3)
        self.assertEqual(
            SOURCE.count(
                f'release_refused "{clang}; on the arm64 Linux build host record the sha256 of the resolved clang 14.0.6 executable'
            ),
            3,
        )

    def test_userspace_awg_runtime_pin_is_satisfied(self) -> None:
        completed = run_producer("--self-test-userspace-awg-runtime-pin")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("LINUX USERSPACE AWG RUNTIME PIN: PASS", completed.stdout)
        check = SOURCE[
            SOURCE.index("assert_userspace_awg_runtime_pin_ready() {") : SOURCE.index(
                "write_linux_winn3_dual_auth_attestation() {"
            )
        ]
        self.assertIn("<<'PY' || return 65", check)
        self.assertNotIn("return 78", check)

    def test_dual_auth_source_capability_gate_is_retired(self) -> None:
        self.assertNotIn("assert_linux_winn3_dual_auth_source_capability", SOURCE)
        self.assertNotIn("--self-test-linux-dual-auth-capability-source", SOURCE)
        self.assertNotIn("still marks Linux host capability absent", SOURCE)
        probe = SOURCE[
            SOURCE.index("prove_linux_winn3_dual_auth_compiled_capability() {") : SOURCE.index(
                "assert_userspace_awg_runtime_pin_ready() {"
            )
        ]
        self.assertIn('"${LINUX_WINN3_ENABLED_PLATFORMS_DEFINE_ARG}"', probe)
        self.assertEqual(probe.count('"${LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG}"'), 1)
        self.assertIn("expect(winn3RelayBuildEnabledPlatforms(), <String>{'linux'});", probe)
        self.assertIn('"${WINN3_DUAL_AUTH_DEFINE_ARG}"', probe)
        self.assertIn(
            'LINUX_WINN3_ENABLED_PLATFORMS_DEFINE_ARG="--dart-define=WINS_WINN3_ENABLED_PLATFORMS=linux"',
            SOURCE,
        )
        self.assertIn(
            'LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG="--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux"',
            SOURCE,
        )
        self.assertIn('release_refused "the compiled Linux dual-auth capability probe failed', probe)

    def test_release_controls_derive_one_epoch_from_the_exact_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-release-controls-") as raw:
            root = pathlib.Path(raw)
            index = root / "RELEASE_INPUT_INDEX.json"
            payload = release_index_fixture(index)
            expected_epoch = 1791507723  # 2026-10-09T01:02:03Z, fraction dropped
            environment = {
                key: value for key, value in os.environ.items() if key != "SOURCE_DATE_EPOCH"
            }
            accepted = run_producer("--self-test-release-controls", str(index), env=environment)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn(f"SOURCE_DATE_EPOCH={expected_epoch} ", accepted.stdout)
            self.assertIn(
                f"RELEASE_INDEX_SHA256={hashlib.sha256(payload).hexdigest()}",
                accepted.stdout,
            )
            same = run_producer(
                "--self-test-release-controls", str(index),
                env={**environment, "SOURCE_DATE_EPOCH": str(expected_epoch)},
            )
            self.assertEqual(same.returncode, 0, same.stderr)
            differs = run_producer(
                "--self-test-release-controls", str(index),
                env={**environment, "SOURCE_DATE_EPOCH": "1"},
            )
            self.assertEqual(differs.returncode, 65, differs.stderr)
            self.assertIn("differs from the release index created_utc epoch", differs.stderr)

            def refused(marker: str) -> None:
                completed = run_producer("--self-test-release-controls", str(index), env=environment)
                self.assertEqual(completed.returncode, 65, completed.stderr)
                self.assertIn(marker, completed.stderr)
                self.assertNotIn("PASS", completed.stdout)

            document = json.loads(payload)
            index.write_text(json.dumps({**document, "extra": 1}), encoding="ascii")
            refused("release index fields are not exact")
            index.write_text('{"schema_version":1,' + payload.decode("ascii")[1:], encoding="ascii")
            refused("duplicate release index JSON key")
            index.write_text(payload.decode("ascii").replace('"schema_version": 1', '"schema_version": NaN'), encoding="ascii")
            refused("non-finite release index JSON number")
            release_index_fixture(index, created_utc="2026-10-09 01:02:03")
            refused("created_utc is not a UTC timestamp")
            release_index_fixture(index)
            index.chmod(0o666)
            refused("group/other-writable")
            index.unlink()
            real = root / "real.json"
            release_index_fixture(real)
            index.symlink_to(real)
            refused("not a single-link regular file")
        for retired in (
            "/etc/winsvpn/release-signing/linux-owner-release-control.json",
            "resolve_owner_release_controls",
            "--emit-owner-release-controls",
            "caller-supplied SOURCE_DATE_EPOCH is forbidden",
            "owner_release_control_sha256\",",
        ):
            self.assertNotIn(retired, SOURCE)

    def test_release_epoch_equals_the_arm64_awg_child_derivation(self) -> None:
        awg = (ROOT / "tools/build_linux_arm64_awg.sh").read_text(encoding="utf-8")
        start = awg.index("derive_release_source_date_epoch() {")
        body = awg[awg.index("<<'PY'\n", start) + len("<<'PY'\n") : awg.index("\nPY\n}", start)]
        environment = {key: value for key, value in os.environ.items() if key != "SOURCE_DATE_EPOCH"}
        # The producer parses the index with its fixed system interpreter, so the
        # child derivation runs on that same interpreter: parity is about the
        # arithmetic, not about which Python accepts which ISO spellings.
        system_python = re.search(r'^readonly LINUX_SYSTEM_PYTHON="([^"]+)"$', SOURCE, re.M)
        self.assertIsNotNone(system_python)
        with tempfile.TemporaryDirectory(prefix="winsvpn-epoch-parity-") as raw:
            index = pathlib.Path(raw) / "RELEASE_INPUT_INDEX.json"
            for created in (
                "2026-10-09T01:02:03.999999Z",
                "2026-10-09T01:02:03Z",
                "2026-10-09T01:02:03.000001+00:00Z",
                "1970-01-01T00:00:01.5Z",
            ):
                with self.subTest(created=created):
                    release_index_fixture(index, created_utc=created)
                    child = subprocess.run(
                        [system_python.group(1), "-I", "-", str(index)],
                        input=body, text=True, capture_output=True, check=False,
                    )
                    producer = run_producer("--self-test-release-controls", str(index), env=environment)
                    if child.returncode != 0:
                        self.assertNotEqual(producer.returncode, 0, producer.stdout)
                        continue
                    self.assertEqual(producer.returncode, 0, producer.stderr)
                    self.assertIn(f"SOURCE_DATE_EPOCH={child.stdout.strip()} ", producer.stdout)

    def test_winn3_ring_identity_is_the_committed_reviewed_pin(self) -> None:
        defines = (ROOT / "tools/winn3_descriptor_ring_defines.py").read_text(encoding="utf-8")
        pinned = re.search(r'REVIEWED_RING_SHA256 = \(\s*"([0-9a-f]{64})"', defines)
        self.assertIsNotNone(pinned)
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("WINS_WINN3_DESCRIPTOR_PUBKEY_")
            and key != "WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256"
        }
        accepted = run_producer("--self-test-winn3-ring-identity", env=environment)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn(f"LINUX WINN3 RING IDENTITY: PASS ({pinned.group(1)})", accepted.stdout)
        matching = run_producer(
            "--self-test-winn3-ring-identity",
            env={**environment, "WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256": pinned.group(1)},
        )
        self.assertEqual(matching.returncode, 0, matching.stderr)
        wrong = run_producer(
            "--self-test-winn3-ring-identity",
            env={**environment, "WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256": "0" * 64},
        )
        self.assertEqual(wrong.returncode, 65, wrong.stderr)
        self.assertIn("differs from the pinned REVIEWED_RING_SHA256", wrong.stderr)
        substituted = run_producer(
            "--self-test-winn3-ring-identity",
            env={
                **environment,
                "WINS_WINN3_DESCRIPTOR_PUBKEY_G1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            },
        )
        self.assertNotEqual(substituted.returncode, 0, substituted.stdout)
        self.assertNotIn("PASS", substituted.stdout)
        self.assertNotIn("caller-computed descriptor-ring identity", SOURCE)

    def test_native_host_store_ids_come_from_the_committed_record(self) -> None:
        completed = run_producer("--self-test-native-host-store-ids")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        ids = json.loads(
            (ROOT / "tools/native_messaging/manifests/store_ids.json").read_text(encoding="utf-8")
        )
        self.assertIn(f"chrome={ids['chrome']} edge={ids['edge']}", completed.stdout)
        with tempfile.TemporaryDirectory(prefix="winsvpn-store-ids-") as raw:
            producer = producer_fixture_root(pathlib.Path(raw))
            layout = pathlib.Path(raw) / "tools/native_messaging/native_host_layout.py"
            layout.parent.mkdir(parents=True)
            layout.write_text(
                "import sys\n"
                "if sys.argv[-1] == 'chrome':\n"
                "    print('lnehjdblendkagjbmdclepjalahdhbbn')\n"
                "    raise SystemExit(0)\n"
                "print('native-host registration refused: no edge id', file=sys.stderr)\n"
                "raise SystemExit(3)\n",
                encoding="utf-8",
            )
            missing_edge = subprocess.run(
                ["bash", str(producer), "--self-test-native-host-store-ids"],
                cwd=raw, text=True, capture_output=True, check=False,
            )
            layout.write_text(
                "print('lnehjdblendkagjbmdclepjalahdhbbn')\n", encoding="utf-8"
            )
            reused = subprocess.run(
                ["bash", str(producer), "--self-test-native-host-store-ids"],
                cwd=raw, text=True, capture_output=True, check=False,
            )
        self.assertEqual(missing_edge.returncode, 65, missing_edge.stderr)
        self.assertIn("RELEASE REFUSED: no Microsoft Edge Add-ons extension id", missing_edge.stderr)
        self.assertEqual(reused.returncode, 65, reused.stderr)
        self.assertIn("must be distinct", reused.stderr)
        build = SOURCE[
            SOURCE.index("build_and_stage_linux_native_host() {") : SOURCE.index(
                "install -D -m 0755 \"${native_host_output}\""
            )
        ]
        self.assertNotIn("return 78", build)

    def test_publication_receipt_binds_every_symbol_and_is_signed_separately(self) -> None:
        self.assertNotIn("winsvpn-linux-publication-receipt-v2", SOURCE)
        self.assertNotIn('"owner_release_control_sha256": owner_control_sha256', SOURCE)
        for marker in (
            "winsvpn-linux-publication-receipt-v3",
            '"schema_version": 3,',
            'receipt["schema_version"] != 3',
            "LINUX_PUBLICATION_RECEIPT.json",
            '"archive_checksum": checksum_record',
            '"installer_bootstrap": bootstrap_record',
            '"symbols": symbol_records',
            "Linux publication receipt symbol inventory changed",
            '"${staged_publication_receipt}" "${staged_publication_receipt_bundle}"',
            "final byte assertion and the physical commit boundary",
        ):
            self.assertIn(marker, SOURCE)

    def test_signed_publication_holds_descriptor_ring_across_commit(self) -> None:
        for marker in (
            "begin_linux_signed_publication_custody",
            "assert_linux_signed_publication_custody",
            "rebind_linux_signed_publication_custody_paths",
            "extend_linux_signed_publication_custody \"${staged_bundle}\"",
            'open_linux_publication_output_under_custody "${staged_archive_sha}"',
            "hold_linux_publication_path \"${staged_installer_bootstrap}\" file",
            "linux_publication_custody_path_for_read",
            "accepted a same-UID bootstrap substitution",
            "accepted a hostile archive/checksum swap",
            "hold_linux_publication_path \"${COSIGN_PATH}\" file",
            "hold_linux_publication_path \"${WINS_LINUX_COSIGN_KEY:?}\" file",
            "hold_linux_publication_path \"${WINS_LINUX_COSIGN_TRUST_ANCHOR:?}\" file",
            "extend_linux_signed_publication_custody \"${staged_private_symbols}\" directory",
        ):
            self.assertIn(marker, SOURCE)

    def test_all_security_json_loaders_reject_nonfinite_and_duplicate_controls(self) -> None:
        loads = [match.start() for match in re.finditer(r"json\.(?:load|loads)\(", SOURCE)]
        self.assertGreaterEqual(len(loads), 10)
        for start in loads:
            window = SOURCE[start : start + 420]
            self.assertIn("object_pairs_hook=", window)
            self.assertIn("parse_constant=", window)
        self.assertIn("fields are not exact", SOURCE)

    def test_release_inputs_fail_before_freeze_signing_or_provisioning(self) -> None:
        main = SOURCE[SOURCE.index('formal_index_path="$(resolve_release_input_index)"') :]
        controls = main.index("resolve_linux_release_controls")
        owner_gate = main.index("assert_linux_release_inputs_ready")
        self.assertLess(controls, owner_gate)
        self.assertLess(owner_gate, main.index("preflight_linux_signing"))
        self.assertLess(owner_gate, main.index('linux_build_apt[@]}" update'))

        wsl_start = SOURCE.index("run_from_neutral_wsl_stage()")
        wsl_end = SOURCE.index("run_build_lock_self_test()", wsl_start)
        wsl = SOURCE[wsl_start:wsl_end]
        controls = wsl.index("resolve_linux_release_controls")
        owner_gate = wsl.index("assert_linux_release_inputs_ready")
        self.assertNotIn("WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256", wsl)
        self.assertLess(controls, owner_gate)
        self.assertLess(owner_gate, wsl.index("preflight_linux_signing"))

    def test_dual_auth_has_one_producer_owner_and_compiled_capability_proof(self) -> None:
        self.assertIn(
            'WINN3_DUAL_AUTH_DEFINE_ARG="--dart-define=${WINN3_DUAL_AUTH_DEFINE_NAME}=true"',
            SOURCE,
        )
        self.assertIn("reject_linux_winn3_dual_auth_environment_override", SOURCE)
        self.assertIn("assert_no_secondary_linux_winn3_dual_auth_injection", SOURCE)
        self.assertIn("prove_linux_winn3_dual_auth_compiled_capability", SOURCE)
        self.assertIn("expect(kWinn3DualAuthHostSupported, isTrue)", SOURCE)
        self.assertIn("expect(flags[kWinnClientCapabilityDualAuth], isTrue)", SOURCE)
        main = SOURCE[SOURCE.index('formal_index_path="$(resolve_release_input_index)"') :]
        self.assertLess(
            main.index("prove_linux_winn3_dual_auth_compiled_capability"),
            main.index('"${FLUTTER_COMMAND}" build linux'),
        )
        self.assertGreater(
            main.index("write_linux_winn3_dual_auth_attestation"),
            main.index('"${FLUTTER_COMMAND}" build linux'),
        )
        self.assertIn("winsvpn-linux-compiled-capability-proof-v3", SOURCE)
        self.assertNotIn("winsvpn-linux-compiled-capability-proof-v2", SOURCE)
        self.assertIn('"enabled_platforms_define": "WINS_WINN3_ENABLED_PLATFORMS=linux"', SOURCE)
        self.assertIn(
            '"relay_enabled_platforms_define": "WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux"',
            SOURCE,
        )
        self.assertNotIn("--winsvpn-release-capability-proof", SOURCE)
        self.assertIn('"verified_artifact": "lib/libapp.so"', SOURCE)
        self.assertIn('"verified_artifact_sha256": artifacts["lib/libapp.so"]', SOURCE)
        self.assertIn("capability proof is not bound to final libapp.so", SOURCE)

    def test_current_sources_have_no_secondary_dual_auth_injection(self) -> None:
        completed = subprocess.run(
            ["bash", str(PRODUCER), "--self-test-winn3-dual-auth-secondary"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("OWNER-BLOCKED:", completed.stderr)

    def test_signing_refusal_is_plain_exit_65(self) -> None:
        mode = SOURCE[SOURCE.index("read_linux_signing_mode()") : SOURCE.index("assert_linux_cosign_public_key_custody()")]
        self.assertNotIn("OWNER-BLOCKED", mode)
        self.assertNotIn("return 78", mode)
        self.assertIn("return 65", mode)

    def test_signing_public_key_is_pinned_without_root_ownership(self) -> None:
        completed = run_producer("--self-test-signing-public-key-custody")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("LINUX COSIGN PUBLIC-KEY CUSTODY SELF-TEST: PASS", completed.stdout)
        self.assertRegex(SOURCE, r'(?m)^LINUX_COSIGN_PUBLIC_KEY_SHA256="(?:[0-9a-f]{64})?"$')
        preflight = SOURCE[SOURCE.index("preflight_linux_signing() {") : SOURCE.index("verify_linux_signature() {")]
        self.assertLess(
            preflight.index("assert_linux_cosign_public_key_custody"),
            preflight.index("authenticate-cosign"),
        )
        self.assertIn('"${LINUX_COSIGN_PUBLIC_KEY_SHA256}"', preflight)
        boundary = SOURCE[
            SOURCE.index("run_linux_signing_with_held_boundary() {") : SOURCE.index("sign_linux_release() {")
        ]
        self.assertIn('"${LINUX_COSIGN_PUBLIC_KEY_SHA256}" <<\'PY\'', boundary)
        self.assertIn("trust_digest != expected_public_key_digest", boundary)
        self.assertIn('"reviewed Cosign executable", expected_uid=None', boundary)
        self.assertIn('"installed trust anchor", expected_uid=None', boundary)
        self.assertNotIn("opened.st_uid != 0", boundary)
        self.assertNotIn("expected_uid=0", SOURCE)
        self.assertIn("sign-blob", (ROOT / "tools/linux_release_signing.py").read_text(encoding="utf-8"))

    def test_arm64_engine_checks_drop_execution_receipts_and_keep_the_epoch(self) -> None:
        stage = SOURCE[
            SOURCE.index("stage_linux_engine_payloads() {") : SOURCE.index("acquire_build_lock() {")
        ]
        self.assertNotIn("env -u SOURCE_DATE_EPOCH", SOURCE)
        self.assertIn('env SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:?}"', stage)
        self.assertIn('bash "$ROOT/tools/build_linux_arm64_awg.sh"', stage)
        self.assertNotIn("--linux-execution-receipts-dir", SOURCE)
        self.assertNotIn("--release-index-sha256", stage)
        self.assertIn(
            '"$tmp_dir/amneziawg-go" --sha256 "${expected_awg_go_binary_sha256}"\n', stage
        )
        self.assertIn('"$tmp_dir/xray/xray" --sha256 "${expected_xray_sha256}"\n', stage)
        self.assertIn('verify-dir "$dest_abs"\n', stage)
        self.assertIn("make PLATFORM=linux WITH_WGQUICK=no", SOURCE)
        self.assertNotIn('run_with_linux_tree_custody "${build_source}=${build}"', SOURCE)

    def test_signing_uses_held_archive_and_trust_anchor_boundary(self) -> None:
        signing_source = ROOT / "tools/linux_release_signing.py"
        signing_pin = re.search(
            r'^LINUX_SIGNING_VERIFIER_SHA256="([0-9a-f]{64})"$',
            SOURCE,
            re.MULTILINE,
        )
        self.assertIsNotNone(signing_pin)
        self.assertEqual(
            signing_pin.group(1), hashlib.sha256(signing_source.read_bytes()).hexdigest()
        )
        self.assertIn("run_linux_signing_with_held_boundary", SOURCE)
        self.assertIn('held_archive = f"/proc/{os.getpid()}/fd/{archive_fd}"', SOURCE)
        self.assertIn('held_bundle = f"/proc/{os.getpid()}/fd/{bundle_fd}"', SOURCE)
        self.assertIn(
            "pass_fds=(archive_fd, public_fd, trust_fd, module_fd, cosign_fd)",
            SOURCE,
        )
        self.assertIn("open_held_key", SOURCE)
        self.assertIn('exec(compile(source, module_path, "exec", dont_inherit=True)', SOURCE)
        self.assertIn("open_held_cosign", SOURCE)
        self.assertIn("Linux signing implementation bytes changed across signing and verification", SOURCE)
        self.assertIn("Sigstore verification bundle changed outside retained descriptor custody", SOURCE)
        self.assertIn("installed trust-anchor ancestor changed across signing verification", SOURCE)
        self.assertIn("Linux signing verifier implementation is not the reviewed producer-bound source", SOURCE)
        self.assertIn("reviewed Cosign executable SHA-256 does not match the held signing verifier", SOURCE)
        self.assertIn("str(public_fd)", SOURCE)
        self.assertIn("str(trust_fd)", SOURCE)
        self.assertIn("Linux signature did not verify with the held installer trust descriptor", SOURCE)
        self.assertIn('/etc/winsvpn/release-signing/cosign.pub', SOURCE)
        self.assertIn("public_digest != trust_digest", SOURCE)
        self.assertIn(
            "Linux archive pathname was swapped across signing and verification",
            SOURCE,
        )
        self.assertIn("Linux signing public-key proof does not exactly match held public/trust descriptors", SOURCE)

    def test_signing_and_output_contracts_are_preflighted_early(self) -> None:
        self.assertIn("linux_release_signing.py", SOURCE)
        self.assertIn('COSIGN_PATH="/usr/local/bin/cosign"', SOURCE)
        self.assertIn("authenticate-cosign", SOURCE)
        self.assertIn("digest-pinned Cosign ${COSIGN_VERSION} at ${COSIGN_PATH}", SOURCE)
        self.assertIn("WINS_LINUX_OUT_DIR must stay inside the repository", SOURCE)
        self.assertIn(
            "Linux release outputs must not be written into the immutable release-manifest directory",
            SOURCE,
        )
        main = SOURCE[SOURCE.index('formal_index_path="$(resolve_release_input_index)"') :]
        begin = main.index('initialize_formal_linux_receipt "${formal_index_path}"')
        self.assertLess(main.index("initialize_linux_output_paths"), begin)
        self.assertLess(main.index("preflight_linux_signing"), begin)

    def test_wsl_child_publishes_only_to_neutral_stage_then_outer_transaction(self) -> None:
        wsl_start = SOURCE.index("run_from_neutral_wsl_stage()")
        wsl_end = SOURCE.index("run_build_lock_self_test()", wsl_start)
        wsl = SOURCE[wsl_start:wsl_end]
        self.assertIn('neutral_child_output="${neutral_linux_tmp}/web/downloads"', wsl)
        self.assertIn('WINS_LINUX_OUT_DIR="${neutral_child_output}"', wsl)
        self.assertIn('dd if="${neutral_archive}" >&${publication_writer_fd}', wsl)
        self.assertLess(
            wsl.index('complete_formal_linux_receipt "${index_path}" "${staged_archive}"'),
            wsl.index("commit_linux_publication"),
        )
        self.assertNotIn("publish_staged_linux_archive", wsl)

    def test_release_manifest_is_generated_outside_package_root_before_packaging(self) -> None:
        # M-2: install.sh (running inside an already cosign-verified stage)
        # still needs an intra-archive manifest to catch corruption/tampering
        # of individual files. It must be written outside PACKAGE_ROOT first
        # so `find .` never observes its own not-yet-complete output as a
        # member to hash, then copied in as the very last file before `tar`.
        self.assertIn('manifest_tmp="${package_tmp}/release-manifest.sha256"', SOURCE)
        self.assertIn(
            'install -m 0644 -- "$manifest_tmp" "$PACKAGE_ROOT/release-manifest.sha256"',
            SOURCE,
        )
        manifest_section = SOURCE[
            SOURCE.index('log "Generating exhaustive release manifest"') :
        ]
        self.assertLess(
            manifest_section.index(
                'install -m 0644 -- "$manifest_tmp" "$PACKAGE_ROOT/release-manifest.sha256"'
            ),
            manifest_section.index('log "Packaging release bundle"'),
        )
        self.assertLess(
            manifest_section.index('log "Packaging release bundle"'),
            manifest_section.index(
                'tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" '
                '--owner=0 --group=0 --numeric-owner'
            ),
        )
        self.assertIn("verify_linux_archive_release_manifest", SOURCE)
        self.assertIn("Linux archive release manifest is not exhaustive and exact", SOURCE)

    def test_archive_release_manifest_must_be_exhaustive_and_exact(self) -> None:
        payloads = {
            "wins_vpn": b"runnable-fixture\n",
            "lib/libapp.so": b"aot-fixture\n",
        }
        with tempfile.TemporaryDirectory(prefix="winsvpn-linux-manifest-") as raw:
            root = pathlib.Path(raw)
            valid = root / "valid.tar.gz"
            write_manifest_archive(valid, payloads)
            accepted = subprocess.run(
                ["bash", str(PRODUCER), "--self-test-release-archive-manifest", str(valid)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn("LINUX ARCHIVE RELEASE MANIFEST: PASS", accepted.stdout)

            wrong = root / "wrong.tar.gz"
            wrong_records = {
                name: hashlib.sha256(payload).hexdigest() for name, payload in payloads.items()
            }
            wrong_records["wins_vpn"] = "0" * 64
            write_manifest_archive(wrong, payloads, records=wrong_records)
            rejected = subprocess.run(
                ["bash", str(PRODUCER), "--self-test-release-archive-manifest", str(wrong)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(rejected.returncode, 1, rejected.stderr)
            self.assertIn("digest mismatch: wins_vpn", rejected.stderr)

            incomplete = root / "incomplete.tar.gz"
            write_manifest_archive(
                incomplete,
                payloads,
                records={"wins_vpn": hashlib.sha256(payloads["wins_vpn"]).hexdigest()},
            )
            rejected = subprocess.run(
                ["bash", str(PRODUCER), "--self-test-release-archive-manifest", str(incomplete)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(rejected.returncode, 1, rejected.stderr)
            self.assertIn("not exhaustive and exact", rejected.stderr)

    def test_bootstrap_script_is_inside_the_atomic_generation(self) -> None:
        prepare_start = SOURCE.index("prepare_linux_publication_stage()")
        prepare_end = SOURCE.index("write_staged_archive_checksum()", prepare_start)
        prepare = SOURCE[prepare_start:prepare_end]
        self.assertIn("${publication_stage_dir}/install-winsvpn-linux.sh", prepare)
        self.assertIn("${ROOT}/linux/packaging/install-winsvpn-linux.sh", prepare)
        commit_start = SOURCE.index("commit_linux_publication()")
        commit_end = SOURCE.index("run_publication_transaction_self_test()", commit_start)
        commit = SOURCE[commit_start:commit_end]
        self.assertIn("missing its verified installer bootstrap", commit)
        self.assertNotIn("${OUT_DIR}/install-winsvpn-linux.sh", SOURCE)
        self.assertIn(
            "./install-winsvpn-linux.sh "
            "wins-vpn-linux-${LINUX_RELEASE_ARCH_LABEL:-x64}.tar.gz "
            "wins-vpn-linux-${LINUX_RELEASE_ARCH_LABEL:-x64}.tar.gz.sigstore.json",
            SOURCE,
        )

    def test_linux_packaging_dir_is_assigned_before_every_dereference(self) -> None:
        # LINUX_PACKAGING_DIR itself is fine to dereference anywhere in the
        # script's top-level (non-function) flow *after* its own assignment,
        # and fine inside any function that is only ever called from there --
        # just not inside run_from_neutral_wsl_stage, which self-contained
        # -exits before that assignment is ever reached (see test above).
        assignment = SOURCE.index('LINUX_PACKAGING_DIR="$ROOT/linux/packaging"')
        wsl_start = SOURCE.index("run_from_neutral_wsl_stage()")
        self.assertLess(wsl_start, assignment)
        for use in re.finditer(r"\$\{?LINUX_PACKAGING_DIR\b", SOURCE):
            self.assertGreater(
                use.start(),
                assignment,
                f"LINUX_PACKAGING_DIR dereferenced at offset {use.start()} before its assignment",
            )

    def test_installer_requires_the_cosign_verified_bootstrap_stage(self) -> None:
        # M-2: install.sh must never run standalone against a manually
        # extracted, unauthenticated archive -- only via
        # install-winsvpn-linux.sh, which sets this after a successful cosign
        # verify-blob and a root-owned, freshly extracted 0700 stage.
        self.assertIn('WINSVPN_VERIFIED_STAGE:-', INSTALLER)
        self.assertIn(
            "must be run via install-winsvpn-linux.sh", INSTALLER
        )
        # gnome-keyring/libsecret remain as *app* runtime dependencies (Secret
        # Service backend for linux/runner/linux_secure_store.cc) -- only the
        # gpg/gpgv *signature verification* tooling is gone, since cosign in
        # install-winsvpn-linux.sh now authenticates the whole archive before
        # this script ever runs.
        self.assertIn("gnome-keyring", INSTALLER)
        self.assertIn("libsecret", INSTALLER)
        self.assertNotIn("gpgv", INSTALLER)
        self.assertNotIn("gnupg", INSTALLER)

    def test_installer_manifest_verification_is_unsigned_sha256_not_gpg(self) -> None:
        # M-2: signature authentication now happens once, on the whole
        # archive, in install-winsvpn-linux.sh before extraction. Inside the
        # already-verified stage, install.sh only needs to catch accidental
        # corruption or later local tampering of individual files, which a
        # plain SHA-256 manifest does without needing its own keyring.
        manifest_fn_start = INSTALLER.index("verify_release_manifest()")
        manifest_fn_end = INSTALLER.index("\n}\n", manifest_fn_start)
        manifest_fn = INSTALLER[manifest_fn_start:manifest_fn_end]
        self.assertIn("sha256sum --strict --check", manifest_fn)
        self.assertIn("release-manifest.sha256", manifest_fn)
        self.assertNotIn("gpg", manifest_fn.lower())

    def test_installer_validates_preexisting_xray_identity_before_mutation(self) -> None:
        existing = INSTALLER.index("if id -u winsvpn-xray")
        create = INSTALLER.index("\nelse\n", existing)
        existing_block = INSTALLER[existing:create]
        self.assertIn("it was not modified", existing_block)
        self.assertNotIn("usermod", existing_block)
        creation_block = INSTALLER[
            create : INSTALLER.index('\n\nrm -rf -- "$stage"', create)
        ]
        self.assertLess(creation_block.index("useradd --system"), creation_block.index("xray_identity_created=1"))
        self.assertLess(creation_block.index("xray_identity_created=1"), creation_block.index("usermod --home"))

    def test_wsl_wrapper_uses_detected_host_architecture(self) -> None:
        linux_check = SOURCE.index('if [[ "$(uname -s)" != "Linux" ]]; then')
        detect_call = SOURCE.index("\ndetect_linux_release_arch\n", linux_check)
        wsl_dispatch = SOURCE.index('\nif [[ "${ROOT}" == /mnt/* ]]; then\n', detect_call)
        self.assertLess(detect_call, wsl_dispatch)
        wsl_start = SOURCE.index("run_from_neutral_wsl_stage()")
        wsl_end = SOURCE.index("run_build_lock_self_test()", wsl_start)
        wsl = SOURCE[wsl_start:wsl_end]
        self.assertIn(
            'neutral_archive="${neutral_generation}/wins-vpn-linux-${LINUX_RELEASE_ARCH_LABEL}.tar.gz"',
            wsl,
        )
        self.assertNotIn("wins-vpn-linux-x64.tar.gz", wsl)
        self.assertIn(
            'linux/${LINUX_RELEASE_ARCH_LABEL}/${APP_VERSION}+${BUILD_NUMBER}"',
            wsl,
        )
        self.assertIn(
            '--target-id "linux-${LINUX_RELEASE_ARCH_LABEL}-package"',
            wsl,
        )

    def test_tarball_mixed_architecture_self_test(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-tarball-arch-") as raw:
            bundle = pathlib.Path(raw)
            tarball_architecture_fixture(bundle, 62)
            accepted = subprocess.run(
                [
                    "bash",
                    str(PRODUCER),
                    "--self-test-bundle-architecture",
                    str(bundle),
                    "x64",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn(
                "LINUX TARBALL BUNDLE ARCHITECTURE SELF-TEST: PASS (x64)",
                accepted.stdout,
            )

            write_executable(bundle / "lib/foreign.so", synthetic_elf64(183, elf_type=3))
            (bundle / "lib/foreign.so").chmod(0o644)
            rejected = subprocess.run(
                [
                    "bash",
                    str(PRODUCER),
                    "--self-test-bundle-architecture",
                    str(bundle),
                    "x64",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(rejected.returncode, 65, rejected.stderr)
            self.assertIn("refusing mixed-architecture bundle", rejected.stderr)
            self.assertIn("foreign.so", rejected.stderr)

            (bundle / "lib/foreign.so").unlink()
            (bundle / "lib/libapp.so").unlink()
            missing = subprocess.run(
                [
                    "bash",
                    str(PRODUCER),
                    "--self-test-bundle-architecture",
                    str(bundle),
                    "x64",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(missing.returncode, 65, missing.stderr)
            self.assertIn("libapp.so", missing.stderr)

    def test_archive_validator_executable_set_equals_what_the_producer_marks_executable(self) -> None:
        # The producer assigns modes in "Normalizing Linux archive ownership and
        # permissions"; the archive validator derives each member's expected mode
        # from its own `executables` set. A file in one list and not the other
        # makes every real build die at "Unsafe Linux archive mode".
        normalize = SOURCE[SOURCE.index('log "Normalizing Linux archive ownership and permissions"') :]
        normalize = normalize[: normalize.index('log "Generating exhaustive release manifest"')]
        chmod_block = re.search(r"chmod 0755 -- \\\n((?:  \"\$PACKAGE_ROOT/[^\"]+\"(?: \\)?\n)+)", normalize)
        self.assertIsNotNone(chmod_block)
        producer_executables = set(re.findall(r'"\$PACKAGE_ROOT/([^"]+)"', chmod_block.group(1)))
        loop = re.search(r"for required_bin in ([a-z0-9 -]+); do", normalize)
        self.assertIsNotNone(loop)
        producer_executables |= set(loop.group(1).split())
        validator = SOURCE[SOURCE.index("executables = {\n") :]
        validator = validator[: validator.index("\n}\n")]
        validator_executables = set(re.findall(r'^    "([^"]+)",?$', validator, re.MULTILINE))
        self.assertEqual(producer_executables, validator_executables)
        # The privacy scan keeps its own copy of the same set (validate_tar_metadata).
        privacy = (ROOT / "tools/validate_release_artifact_privacy.py").read_text(encoding="utf-8")
        table = privacy[privacy.index("reviewed_executables = {") :]
        table = table[: table.index("}\n")]
        privacy_executables = set(re.findall(r'^\s*"([^"]+)",?$', table, re.MULTILINE))
        self.assertEqual(privacy_executables, validator_executables)
        # The same file is what the installer and the deb builder run as 0755.
        self.assertIn("share/wins-vpn/winsvpn-recover", validator_executables)

    def test_archive_metadata_gate_inspects_every_elf_machine(self) -> None:
        self.assertIn("refusing mixed-architecture archive", SOURCE)
        self.assertIn("Linux archive executable has no loadable entry point", SOURCE)
        self.assertIn("Linux archive shared object lacks loadable ET_DYN/PT_DYNAMIC semantics", SOURCE)
        self.assertIn("dynamic_segments", SOURCE)
        self.assertIn("required_payload_missing", SOURCE)
        self.assertIn("winn3-descriptor-ring-attestation.json", SOURCE)
        self.assertIn(
            'python3 - "$staged_archive_read" "$SOURCE_DATE_EPOCH" "$LINUX_RELEASE_ELF_MACHINE"',
            SOURCE,
        )
        self.assertIn("assert_packaged_linux_elf_architecture", SOURCE)
        chmod_loop = SOURCE.index(
            "for required_bin in xray awg awg-quick amneziawg-go winn-datapath; do"
        )
        walk = SOURCE.index(
            'assert_packaged_linux_elf_architecture "$PACKAGE_ROOT" "$LINUX_RELEASE_ELF_MACHINE"',
            chmod_loop,
        )
        manifest = SOURCE.index('log "Generating exhaustive release manifest"', walk)
        self.assertLess(walk, manifest)


if __name__ == "__main__":
    unittest.main()
