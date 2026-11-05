#!/usr/bin/env python3
"""Tests for the remote-host half of remote-attested Windows and Linux builds.

Covers tools/release_remote_attestation_check.py (source transfer check,
manifest check with forged-manifest refusal, run record), the producers'
remote-attested switches, and the Linux tree-custody digest chain (L-E B3).
The Mac half (begin-build/finish-build --remote-host) is covered in
tools/test_release_dependency_freeze.py.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import release_remote_attestation_check as check  # noqa: E402

LINUX_PRODUCER = ROOT / "tools/build_linux_release.sh"
WINDOWS_PRODUCER = ROOT / "installer/windows/build_installer.ps1"


def _blob(payload: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(payload) + payload, usedforsecurity=False).hexdigest()


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class RemoteSourceTransferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temporary.name)
        self.files = {
            "a.txt": (b"alpha\n", 0o644),
            "tools/build_linux_release.sh": (b"#!/bin/bash\necho build\n", 0o755),
            "z/deep/file.txt": (b"zeta\n", 0o644),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _archive(
        self,
        *,
        extra: tuple[tarfile.TarInfo, bytes] | None = None,
        mode_override: int | None = None,
    ) -> tuple[pathlib.Path, dict[str, object]]:
        raw = io.BytesIO()
        listing = hashlib.sha256()
        entries = sorted(self.files.items(), key=lambda item: item[0].encode())
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, (payload, mode) in entries:
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = mode if mode_override is None else mode_override
                info.mtime = 1760000000
                archive.addfile(info, io.BytesIO(payload))
                listing.update(
                    f"{'100755' if mode & 0o111 else '100644'} {_blob(payload)} {name}\n".encode()
                )
            link = tarfile.TarInfo("zz-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "a.txt"
            link.mode = 0o777
            archive.addfile(link)
            listing.update(f"120000 {_blob(b'a.txt')} zz-link\n".encode())
            if extra is not None:
                info, payload = extra
                archive.addfile(info, io.BytesIO(payload))
        path = self.base / "SOURCE.tar"
        path.write_bytes(raw.getvalue())
        record = {
            "contract": check.SOURCE_ARCHIVE_CONTRACT,
            "path": ".artifacts/remote-builds/r/SOURCE.tar",
            "sha256": _sha(raw.getvalue()),
            "size_bytes": len(raw.getvalue()),
            "revision": "0" * 40,
            "object_format": "sha1",
            "file_count": len(entries) + 1 + (1 if extra else 0),
            "listing_sha256": listing.hexdigest(),
            "mtime": 1760000000,
        }
        return path, record

    def _input(self, archive: dict[str, object]) -> pathlib.Path:
        record = {
            "contract": check.INPUT_CONTRACT,
            "release": "1.0.16+33",
            "platform": "linux",
            "remote_host": "linux",
            "build_begin_sha256": "1" * 64,
            "release_input_index": {"path": ".artifacts/i/RELEASE_INPUT_INDEX.json", "sha256": "2" * 64},
            "shared_manifest": {"path": ".artifacts/i/SHARED_INPUTS.json", "sha256": "3" * 64},
            "platform_manifest": {"path": ".artifacts/i/LINUX_INPUTS.json", "sha256": "4" * 64},
            "source_archive": archive,
            "producer": {"path": "tools/build_linux_release.sh", "sha256": "5" * 64},
        }
        path = self.base / "REMOTE_INPUT.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        return path

    def test_extract_source_restores_the_exact_frozen_tree(self) -> None:
        archive, record = self._archive()
        result = check.extract_source(self._input(record), archive, self.base / "src")
        self.assertEqual(result["files"], 4)
        for name, (payload, mode) in self.files.items():
            target = self.base / "src" / name
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(bool(os.stat(target).st_mode & 0o111), bool(mode & 0o111))
        self.assertEqual(os.readlink(self.base / "src" / "zz-link"), "a.txt")

    def test_extract_source_materializes_links_on_windows_hosts(self) -> None:
        archive, record = self._archive()
        saved = check.MATERIALIZE_SYMLINKS
        check.MATERIALIZE_SYMLINKS = True
        try:
            result = check.extract_source(self._input(record), archive, self.base / "src")
        finally:
            check.MATERIALIZE_SYMLINKS = saved
        self.assertEqual(result["files"], 4)
        link = self.base / "src" / "zz-link"
        self.assertFalse(link.is_symlink())
        self.assertEqual(link.read_bytes(), b"alpha\n")

    def test_windows_materialization_refuses_a_link_before_its_target(self) -> None:
        self.files = {"z.txt": (b"zeta\n", 0o644)}
        raw = io.BytesIO()
        listing = hashlib.sha256()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            link = tarfile.TarInfo("a-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "z.txt"
            link.mode = 0o777
            archive.addfile(link)
            listing.update(f"120000 {_blob(b'z.txt')} a-link\n".encode())
            info = tarfile.TarInfo("z.txt")
            info.size = 5
            info.mode = 0o644
            info.mtime = 1760000000
            archive.addfile(info, io.BytesIO(b"zeta\n"))
            listing.update(f"100644 {_blob(b'zeta\n')} z.txt\n".encode())
        path = self.base / "SOURCE.tar"
        path.write_bytes(raw.getvalue())
        _unused, record = self._archive()
        path.write_bytes(raw.getvalue())
        record.update(
            sha256=_sha(raw.getvalue()),
            size_bytes=len(raw.getvalue()),
            file_count=2,
            listing_sha256=listing.hexdigest(),
        )
        saved = check.MATERIALIZE_SYMLINKS
        check.MATERIALIZE_SYMLINKS = True
        try:
            with self.assertRaisesRegex(check.RemoteAttestationError, "not an extracted regular file"):
                check.extract_source(self._input(record), path, self.base / "src")
        finally:
            check.MATERIALIZE_SYMLINKS = saved

    def test_extract_source_refuses_a_changed_archive(self) -> None:
        archive, record = self._archive()
        payload = bytearray(archive.read_bytes())
        payload[600] ^= 1
        archive.write_bytes(bytes(payload))
        with self.assertRaisesRegex(check.RemoteAttestationError, "digest or size differs"):
            check.extract_source(self._input(record), archive, self.base / "src")
        self.assertFalse((self.base / "src").exists())

    def test_extract_source_refuses_escaping_or_unreviewed_members(self) -> None:
        escape = tarfile.TarInfo("zzz/../../escape.txt")
        escape.size = 1
        cases = {
            "escapes the repository": {"extra": (escape, b"x")},
            "mode is not reviewed": {"mode_override": 0o777},
        }
        for number, (message, options) in enumerate(cases.items()):
            with self.subTest(message=message):
                archive, record = self._archive(**options)
                with self.assertRaisesRegex(check.RemoteAttestationError, message):
                    check.extract_source(self._input(record), archive, self.base / f"src{number}")
                # R23 W1-09: a refusal after mkdir removes the partial tree.
                self.assertFalse(os.path.lexists(self.base / f"src{number}"))
        self.assertFalse((self.base.parent / "escape.txt").exists())

    def test_extract_source_refuses_a_listing_that_is_not_the_frozen_revision(self) -> None:
        archive, record = self._archive()
        record["listing_sha256"] = "6" * 64
        with self.assertRaisesRegex(check.RemoteAttestationError, "frozen revision listing"):
            check.extract_source(self._input(record), archive, self.base / "src")
        # R23 W1-09: the fully extracted but refused tree is not left behind.
        self.assertFalse(os.path.lexists(self.base / "src"))

    def test_extract_source_binds_member_times_to_the_begin_record(self) -> None:
        # R24 V2 F-03: the listing binds content, mode and order, not the member
        # time that os.utime applies, so an archive swapped after the digest check
        # could set any time. Every member must carry the recorded commit time.
        archive, record = self._archive()
        record["mtime"] = 1760000001
        with self.assertRaisesRegex(check.RemoteAttestationError, "member time differs"):
            check.extract_source(self._input(record), archive, self.base / "src")
        self.assertFalse(os.path.lexists(self.base / "src"))

    def test_extract_source_does_not_delete_a_replaced_destination(self) -> None:
        # R24 V2 F-03: the failure cleanup removes the directory this call
        # created, not whatever the path names when the extraction fails.
        archive, record = self._archive()
        destination = self.base / "src"
        moved = self.base / "moved-away"

        def swap_then_fail(expected, archive_path, target):
            target.rename(moved)
            target.mkdir()
            (target / "other-owner.txt").write_bytes(b"not ours\n")
            raise check.RemoteAttestationError("simulated failure")

        with mock.patch.object(check, "_extract_source_into", side_effect=swap_then_fail):
            with self.assertRaisesRegex(check.RemoteAttestationError, "simulated failure"):
                check.extract_source(self._input(record), archive, destination)
        self.assertEqual((destination / "other-owner.txt").read_bytes(), b"not ours\n")
        self.assertTrue(moved.is_dir())

    def test_extract_source_keeps_a_destination_it_did_not_create(self) -> None:
        archive, record = self._archive()
        record["listing_sha256"] = "6" * 64
        existing = self.base / "src"
        existing.mkdir()
        (existing / "owner-file.txt").write_bytes(b"kept\n")
        with self.assertRaisesRegex(check.RemoteAttestationError, "must be a new path"):
            check.extract_source(self._input(record), archive, existing)
        self.assertEqual((existing / "owner-file.txt").read_bytes(), b"kept\n")


class RemoteInputVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name) / "repo"
        self.inputs = {
            "lib/main.dart": b"void main() {}\n",
            "linux/runner.cc": b"int main() { return 0; }\n",
            "tools/build_linux_release.sh": b"#!/bin/bash\necho build\n",
        }
        for name, payload in self.inputs.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.index_dir = self.repo / ".artifacts/release-inputs-1.0.16+33"
        self.index_dir.mkdir(parents=True)
        self._write_manifests()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _entry(self, name: str) -> dict[str, object]:
        payload = (self.repo / name).read_bytes()
        return {"path": name, "sha256": _sha(payload), "size": len(payload)}

    ALIAS = "tools/native_messaging/host/lib/main.dart"
    ALIAS_TARGET = "../../../../lib/main.dart"

    def _write_manifests(self, alias: bool = False) -> None:
        shared = {"inputs": {"files": [self._entry("lib/main.dart")]}}
        platform = {
            "platform": "linux",
            "native_inputs": {"files": [self._entry("linux/runner.cc")]},
            "producer_inputs": {"files": [self._entry("tools/build_linux_release.sh")]},
        }
        if alias:
            # The Mac freeze binds a symbolic link input only as the Git blob
            # of its target text (mode 120000), never in a files list.
            platform["native_inputs"]["git_audit"] = {
                "object_format": "sha1",
                "selected_blobs": [
                    {
                        "path": "linux/runner.cc",
                        "mode": "100644",
                        "oid": _blob(self.inputs["linux/runner.cc"]),
                    },
                    {
                        "path": self.ALIAS,
                        "mode": "120000",
                        "oid": _blob(self.ALIAS_TARGET.encode("utf-8")),
                    },
                ],
            }
        self.shared_bytes = json.dumps(shared).encode()
        self.platform_bytes = json.dumps(platform).encode()
        (self.index_dir / "SHARED_INPUTS.json").write_bytes(self.shared_bytes)
        (self.index_dir / "LINUX_INPUTS.json").write_bytes(self.platform_bytes)
        index = {
            "release": "1.0.16+33",
            "shared_manifest": {"path": "SHARED_INPUTS.json", "sha256": _sha(self.shared_bytes)},
            "platform_manifests": {
                "linux": {"path": "LINUX_INPUTS.json", "sha256": _sha(self.platform_bytes)}
            },
        }
        self.index_bytes = json.dumps(index).encode()
        (self.index_dir / "RELEASE_INPUT_INDEX.json").write_bytes(self.index_bytes)

    def _input(self) -> pathlib.Path:
        base = ".artifacts/release-inputs-1.0.16+33"
        record = {
            "contract": check.INPUT_CONTRACT,
            "release": "1.0.16+33",
            "platform": "linux",
            "remote_host": "linux",
            "build_begin_sha256": "1" * 64,
            "release_input_index": {"path": f"{base}/RELEASE_INPUT_INDEX.json", "sha256": _sha(self.index_bytes)},
            "shared_manifest": {"path": f"{base}/SHARED_INPUTS.json", "sha256": _sha(self.shared_bytes)},
            "platform_manifest": {"path": f"{base}/LINUX_INPUTS.json", "sha256": _sha(self.platform_bytes)},
            "source_archive": {
                "contract": check.SOURCE_ARCHIVE_CONTRACT,
                "path": ".artifacts/remote-builds/r/SOURCE.tar",
                "sha256": "7" * 64,
                "size_bytes": 10240,
                "revision": "0" * 40,
                "object_format": "sha1",
                "file_count": 3,
                "listing_sha256": "8" * 64,
                "mtime": 1760000000,
            },
            "producer": {
                "path": "tools/build_linux_release.sh",
                "sha256": _sha(self.inputs["tools/build_linux_release.sh"]),
            },
        }
        path = self.repo / ".artifacts/remote-attestation/REMOTE_INPUT.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record), encoding="utf-8")
        return path

    def test_verify_inputs_accepts_the_tree_the_mac_froze(self) -> None:
        result = check.verify_inputs(
            self.repo, self._input(), self.index_dir / "RELEASE_INPUT_INDEX.json"
        )
        self.assertEqual(result["files_checked"], 3)

    def _install_alias(self) -> pathlib.Path:
        link = self.repo / self.ALIAS
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(self.ALIAS_TARGET)
        self._write_manifests(alias=True)
        return link

    def test_symbolic_link_inputs_are_checked_against_their_frozen_blob(self) -> None:
        link = self._install_alias()
        remote_input = self._input()
        result = check.verify_inputs(self.repo, remote_input, None)
        self.assertEqual(result["files_checked"], 4)
        # Retargeted to another verified input: the frozen blob no longer matches.
        link.unlink()
        link.symlink_to("../../../../linux/runner.cc")
        with self.assertRaisesRegex(
            check.RemoteAttestationError, "target differs from the frozen revision"
        ):
            check.verify_inputs(self.repo, remote_input, None)
        # Replaced by an edited regular file on a POSIX host.
        link.unlink()
        link.write_bytes(b"void main() { hostile(); }\n")
        with self.assertRaisesRegex(
            check.RemoteAttestationError, "is not a symbolic link"
        ):
            check.verify_inputs(self.repo, remote_input, None)

    def test_materialized_link_inputs_must_hold_their_target_bytes(self) -> None:
        link = self._install_alias()
        remote_input = self._input()
        link.unlink()
        link.write_bytes(self.inputs["lib/main.dart"])
        saved = check.MATERIALIZE_SYMLINKS
        check.MATERIALIZE_SYMLINKS = True
        try:
            result = check.verify_inputs(self.repo, remote_input, None)
            self.assertEqual(result["files_checked"], 4)
            # dart compile exe reads this copy, not lib/main.dart.
            link.write_bytes(b"void main() { hostile(); }\n")
            with self.assertRaisesRegex(
                check.RemoteAttestationError, "differs from its target"
            ):
                check.verify_inputs(self.repo, remote_input, None)
        finally:
            check.MATERIALIZE_SYMLINKS = saved

    def test_forged_manifest_is_refused(self) -> None:
        remote_input = self._input()
        # A forger edits a native input and rewrites the platform manifest to
        # match it; the manifest digest no longer equals the Mac's record.
        (self.repo / "linux/runner.cc").write_bytes(b"int main() { return 1; }\n")
        platform = json.loads(self.platform_bytes)
        platform["native_inputs"]["files"] = [self._entry("linux/runner.cc")]
        (self.index_dir / "LINUX_INPUTS.json").write_bytes(json.dumps(platform).encode())
        with self.assertRaisesRegex(check.RemoteAttestationError, "forged or edited manifest"):
            check.verify_inputs(self.repo, remote_input, None)

    def test_changed_input_file_and_producer_are_refused(self) -> None:
        remote_input = self._input()
        for name, message in (
            ("linux/runner.cc", "differs from the frozen manifest"),
            ("tools/build_linux_release.sh", "differs from the frozen manifest"),
        ):
            with self.subTest(name=name):
                original = (self.repo / name).read_bytes()
                (self.repo / name).write_bytes(original + b"#")
                try:
                    with self.assertRaisesRegex(check.RemoteAttestationError, message):
                        check.verify_inputs(self.repo, remote_input, None)
                finally:
                    (self.repo / name).write_bytes(original)

    def test_hashed_inputs_keep_the_control_file_custody(self) -> None:
        # R24 V2 finding 2: hashed inputs, the producer and the artifact get the
        # _read_regular custody: one link, and the inode hashed is the one checked.
        remote_input = self._input()
        runner = self.repo / "linux/runner.cc"
        alias = self.repo / "linux/runner-alias.cc"
        os.link(runner, alias)
        try:
            with self.assertRaisesRegex(
                check.RemoteAttestationError, "not a single-link regular file"
            ):
                check.verify_inputs(self.repo, remote_input, None)
        finally:
            alias.unlink()
        check.verify_inputs(self.repo, remote_input, None)
        decoy = self.repo / "decoy.cc"
        decoy.write_bytes(runner.read_bytes())
        checked = os.lstat(decoy)
        real_lstat = os.lstat
        swapped = os.fspath(runner.resolve())

        def swapped_lstat(path: object) -> os.stat_result:
            # The path is checked while it names the decoy, then opened after
            # it was swapped back to another inode.
            return checked if os.fspath(path) == swapped else real_lstat(path)

        with mock.patch.object(check.os, "lstat", side_effect=swapped_lstat):
            with self.assertRaisesRegex(
                check.RemoteAttestationError, "changed while it was opened"
            ):
                check.verify_inputs(self.repo, remote_input, None)

    def test_another_index_is_refused(self) -> None:
        remote_input = self._input()
        other = self.repo / ".artifacts/other/RELEASE_INPUT_INDEX.json"
        other.parent.mkdir(parents=True)
        other.write_bytes(self.index_bytes)
        with self.assertRaisesRegex(check.RemoteAttestationError, "differs from the one the Mac verified"):
            check.verify_inputs(self.repo, remote_input, other)

    def test_unreviewed_producer_pairing_is_refused(self) -> None:
        remote_input = self._input()
        record = json.loads(remote_input.read_text())
        record["remote_host"] = "windows"
        remote_input.write_text(json.dumps(record))
        with self.assertRaisesRegex(check.RemoteAttestationError, "unreviewed producer"):
            check.load_input(remote_input)

    def test_record_run_binds_artifact_bytes_once(self) -> None:
        remote_input = self._input()
        artifact = self.repo / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00artifact")
        output = remote_input.parent / "REMOTE_RUN.json"
        toolchain = {"name": "Flutter", "version": "3.47.6", "revision": "r", "target": "linux-x64"}
        check.record_run(self.repo, remote_input, artifact, toolchain, output)
        run = json.loads(output.read_text())
        self.assertEqual(
            set(run),
            {
                "contract", "release", "platform", "remote_host", "build_begin_sha256",
                "source_archive_sha256", "release_input_index_sha256",
                "platform_manifest_sha256", "producer", "toolchain", "artifact",
                "signing", "remote_system", "finished_utc",
            },
        )
        self.assertEqual(run["signing"], "unsigned")
        self.assertEqual(run["artifact"]["sha256"], _sha(artifact.read_bytes()))
        self.assertEqual(run["toolchain"], toolchain)
        self.assertEqual(run["build_begin_sha256"], "1" * 64)
        with self.assertRaisesRegex(check.RemoteAttestationError, "must be a new path"):
            check.record_run(self.repo, remote_input, artifact, toolchain, output)

    def _windows_run(self, secret_scan: str | None) -> dict[str, object]:
        remote_input = self.repo / "windows-input.json"
        record = {
            "release": "1.0.16+33",
            "platform": "windows",
            "remote_host": "windows",
            "build_begin_sha256": "1" * 64,
            "source_archive": {"sha256": "7" * 64},
            "release_input_index": {"sha256": "2" * 64},
            "platform_manifest": {"sha256": "4" * 64},
            "producer": {"path": "installer/windows/build_installer.ps1", "sha256": "5" * 64},
        }
        artifact = self.repo / "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
        artifact.write_bytes(b"MZ-installer-fixture")
        output = self.repo / "windows-run.json"
        toolchain = {"name": "Flutter", "version": "3.47.6", "revision": "r",
                     "target": "windows-x64-inno-unsigned"}
        with mock.patch.object(check, "verify_inputs"), mock.patch.object(
            check, "load_input", return_value=record
        ):
            check.record_run(
                self.repo, remote_input, artifact, toolchain, output, "unsigned", secret_scan
            )
        return json.loads(output.read_text())

    def test_windows_run_record_says_the_release_host_runs_the_secret_scan(self) -> None:
        run = self._windows_run("deferred-to-release-host")
        self.assertEqual(run["secret_scan"], "deferred-to-release-host")
        self.assertEqual(run["platform"], "windows")

    def test_secret_scan_deferral_belongs_to_windows_runs_only_and_is_required_there(self) -> None:
        with self.assertRaisesRegex(check.RemoteAttestationError, "must"):
            self._windows_run(None)
        with self.assertRaisesRegex(check.RemoteAttestationError, "not reviewed"):
            self._windows_run("skipped")
        remote_input = self._input()
        artifact = self.repo / "wins-vpn-linux-x64.tar.gz"
        artifact.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00artifact")
        with self.assertRaisesRegex(check.RemoteAttestationError, "only a Windows run"):
            check.record_run(
                self.repo, remote_input, artifact,
                {"name": "Flutter", "version": "3.47.6", "revision": "r", "target": "linux-x64"},
                remote_input.parent / "REMOTE_RUN.json", "unsigned", "deferred-to-release-host",
            )


class SigningDeferralTests(unittest.TestCase):
    """A Linux release signs on the Mac; only the orchestrated remote run may defer."""

    def _self_test(self, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"), **environment}
        return subprocess.run(
            ["bash", str(LINUX_PRODUCER), "--self-test-signing-deferral"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False,
        )

    def test_normal_release_run_cannot_skip_signing(self) -> None:
        for environment in (
            {"WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR": "1"},
            {"WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR": "1", "SIGN_LINUX_RELEASE": "1"},
            {"WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR": "yes"},
        ):
            with self.subTest(environment=environment):
                completed = self._self_test(environment)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertNotIn("PASS", completed.stdout)
        plain = self._self_test({})
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertIn("signing=unsigned remote=0", plain.stdout)

    def test_orchestrated_remote_run_defers_and_never_holds_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            remote_input = pathlib.Path(name) / "REMOTE_INPUT.json"
            remote_input.write_text("{}", encoding="utf-8")
            deferred = self._self_test({
                "WINS_REMOTE_ATTESTATION_INPUT": str(remote_input),
                "WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR": "1",
            })
            self.assertEqual(deferred.returncode, 0, deferred.stderr)
            self.assertIn("signing=orchestrator remote=1", deferred.stdout)
            keyed = self._self_test({
                "WINS_REMOTE_ATTESTATION_INPUT": str(remote_input),
                "SIGN_LINUX_RELEASE": "1",
            })
            self.assertNotEqual(keyed.returncode, 0)
            self.assertIn("never hold the cosign key", keyed.stderr)

    def test_orchestrator_signs_exactly_when_the_remote_run_deferred(self) -> None:
        import release_remote_build as orchestrator

        self.assertTrue(orchestrator.signing_plan("linux", "orchestrator", True))
        self.assertFalse(orchestrator.signing_plan("linux", "unsigned", False))
        self.assertFalse(orchestrator.signing_plan("windows", "producer", False))
        for platform_name, mode, sign in (
            ("linux", "orchestrator", False),
            ("linux", "unsigned", True),
            ("windows", "orchestrator", True),
            ("linux", None, False),
        ):
            with self.subTest(platform=platform_name, mode=mode, sign=sign):
                with self.assertRaises(orchestrator.RemoteBuildError):
                    orchestrator.signing_plan(platform_name, mode, sign)

    def test_mac_signing_refuses_an_unpinned_key_unless_rehearsal(self) -> None:
        import release_remote_build as orchestrator

        with tempfile.TemporaryDirectory() as name:
            base = pathlib.Path(name)
            # The landed producer carries the reviewed pin, so the unpinned case
            # is exercised on a copy whose single assignment is emptied.
            unpinned = base / "repo"
            (unpinned / "tools").mkdir(parents=True)
            source = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
            emptied = re.sub(
                r'(?m)^LINUX_COSIGN_PUBLIC_KEY_SHA256="[0-9a-f]{64}"$',
                'LINUX_COSIGN_PUBLIC_KEY_SHA256=""',
                source,
            )
            (unpinned / "tools/build_linux_release.sh").write_text(emptied, encoding="utf-8")
            self.assertEqual(orchestrator._linux_public_key_pin(unpinned), "")
            (base / "k.pub").write_text("public\n", encoding="utf-8")
            previous = dict(os.environ)
            os.environ["WINS_LINUX_COSIGN_KEY"] = str(base / "k.key")
            os.environ["WINS_LINUX_COSIGN_PUBKEY"] = str(base / "k.pub")
            try:
                with self.assertRaisesRegex(orchestrator.RemoteBuildError, "key ceremony pending"):
                    orchestrator.sign_on_mac(
                        unpinned, base, base / "a.tar.gz", "/nonexistent", False,
                        expected_sha256="0" * 64,
                    )
            finally:
                os.environ.clear()
                os.environ.update(previous)

    def test_mac_signing_pin_is_the_committed_trust_anchor_and_refuses_other_keys(self) -> None:
        import release_remote_build as orchestrator

        anchor = ROOT / "linux/packaging/release-signing/cosign.pub"
        pin = orchestrator._linux_public_key_pin(ROOT)
        self.assertEqual(pin, hashlib.sha256(anchor.read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory() as name:
            base = pathlib.Path(name)
            (base / "other.pub").write_text("another public key\n", encoding="utf-8")
            previous = dict(os.environ)
            os.environ["WINS_LINUX_COSIGN_KEY"] = str(base / "k.key")
            os.environ["WINS_LINUX_COSIGN_PUBKEY"] = str(base / "other.pub")
            try:
                with self.assertRaisesRegex(
                    orchestrator.RemoteBuildError, "is not LINUX_COSIGN_PUBLIC_KEY_SHA256"
                ):
                    orchestrator.signing_preflight(ROOT, True)
            finally:
                os.environ.clear()
                os.environ.update(previous)


class ProducerRemoteSwitchTests(unittest.TestCase):
    def test_linux_producer_reaches_the_controller_only_outside_remote_mode(self) -> None:
        source = LINUX_PRODUCER.read_text(encoding="utf-8")
        wsl = source[source.index("run_from_neutral_wsl_stage() {") : source.index("run_build_lock_self_test() {")]
        outside = source.replace(wsl, "")
        calls = [m.start() for m in re.finditer(r"tools/release_dependency_freeze\.py\" (verify-index|begin-build|finish-build|verify-receipt)", outside)]
        self.assertTrue(calls)
        guarded = {
            "verify_linux_release_inputs_unchanged() {": "verify-inputs",
            "initialize_formal_linux_receipt() {": "if linux_remote_attested; then",
            "complete_formal_linux_receipt() {": "complete_remote_attested_linux_run",
        }
        spans = []
        for header, marker in guarded.items():
            start = outside.index(header)
            end = outside.index("\n}\n", start)
            body = outside[start:end]
            self.assertIn(marker, body)
            remote_at = body.index("linux_remote_attested")
            first_call = body.find("release_dependency_freeze.py")
            self.assertLess(remote_at, first_call, header)
            spans.append((start, end))
        for call in calls:
            self.assertTrue(any(start <= call <= end for start, end in spans), outside[call - 200 : call])
        self.assertIn(
            "assert_linux_remote_attestation_mode\nassert_linux_signing_deferral_mode\n"
            "verify_linux_release_inputs_unchanged",
            outside,
        )

    def test_windows_producer_reaches_the_controller_only_outside_remote_mode(self) -> None:
        source = WINDOWS_PRODUCER.read_text(encoding="utf-8")
        for header in (
            "function Assert-ReleaseInputIndexUnchanged {",
            "function Initialize-WindowsBuildReceipt {",
            "function Complete-WindowsBuildReceipt {",
        ):
            start = source.index(header)
            body = source[start : source.index("\n}\n", start)]
            self.assertLess(
                body.index("Test-WindowsRemoteAttested"),
                body.index("$DependencyFreezeTool") if "$DependencyFreezeTool" in body
                else body.index("release_dependency_freeze.py"),
                header,
            )
        self.assertIn("'record-run', '--repo'", source)
        self.assertIn("Remote-attested builds never run as a witnessed isolated stage.", source)


class LinuxTreeCustodyChainTests(unittest.TestCase):
    """L-E B3: each watched run chains its post-run digest to the next run."""

    @classmethod
    def setUpClass(cls) -> None:
        source = LINUX_PRODUCER.read_text(encoding="utf-8")
        body = source[source.index("run_with_linux_tree_custody() {") :]
        start = body.index("<<'PY'\n") + len("<<'PY'\n")
        cls.program = body[start : body.index("\nPY\n", start)] + "\n"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.temporary.name)
        self.sdk = base / "flutter"
        self.pub = base / "pub-cache"
        self.chain = base / "chain"
        for path, payload in (
            (self.sdk / "bin/flutter", b"launcher\n"),
            (self.sdk / "bin/cache/engine.stamp", b"engine\n"),
            (self.sdk / "bin/cache/libimobiledevice.stamp", b"0bf0f9e941c85d06ce4b5909d7a61b3a4f2a6a05"),
            (self.sdk / "bin/cache/libusbmuxd.stamp", b"19d6bec393c9f9b31ccb090059f59268da32e281"),
            (self.sdk / "bin/cache/other.stamp", b"other"),
            # The real SDK ships packages/flutter_tools; only its .dart_tool is runtime state.
            (self.sdk / "packages/flutter_tools/pubspec.yaml", b"name: flutter_tools\n"),
            (self.pub / "hosted/pub.dev/pkg/lib.dart", b"lib\n"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.chain.mkdir(mode=0o700)
        os.chmod(self.chain, 0o700)
        self.sdk_pin = self._digest(self.sdk)
        self.pub_pin = self._digest(self.pub)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _digest(root: pathlib.Path) -> str:
        records = []
        for path in root.rglob("*"):
            if path.is_file():
                payload = path.read_bytes()
                records.append(f"file {len(payload)} {_sha(payload)} {path.relative_to(root).as_posix()}\n")
        return _sha("".join(sorted(records)).encode())

    def _run(
        self, command: str, *, chain: bool = True, portable: bool = True
    ) -> subprocess.CompletedProcess[str]:
        options = [f"--chain-state-dir={self.chain}"] if chain else []
        return subprocess.run(
            [
                sys.executable, "-I", "-", "1" if portable else "0", *options,
                f"--flutter-sdk-root={self.sdk}", f"--pub-cache-root={self.pub}",
                f"{self.sdk_pin}={self.sdk}", f"{self.pub_pin}={self.pub}",
                "--", "/bin/sh", "-c", command, "sh", str(self.sdk), str(self.pub),
            ],
            input=self.program,
            text=True,
            capture_output=True,
            check=False,
        )

    FIRST_PUB_GET = (
        'mkdir -p "$1/packages/flutter_tools/.dart_tool" "$2/active_roots" && '
        'printf config >"$1/packages/flutter_tools/.dart_tool/package_config.json" && '
        'printf root >"$2/active_roots/r"'
    )

    def test_chained_runs_accept_runtime_state_written_by_the_previous_run(self) -> None:
        first = self._run(self.FIRST_PUB_GET)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(len(list(self.chain.iterdir())), 2)
        second = self._run("exit 0")
        self.assertEqual(second.returncode, 0, second.stderr)
        # Without the chain the install pin is expected again: the B3 refusal.
        unchained = self._run("exit 0", chain=False)
        self.assertNotEqual(unchained.returncode, 0)
        self.assertIn("authenticated compiler tree digest mismatch", unchained.stderr)

    def test_change_between_runs_is_refused_even_in_runtime_state(self) -> None:
        self.assertEqual(self._run(self.FIRST_PUB_GET).returncode, 0)
        (self.sdk / "packages/flutter_tools/.dart_tool/package_config.json").write_text("planted")
        refused = self._run("exit 0")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("authenticated compiler tree digest mismatch", refused.stderr)

    def test_stable_member_change_is_refused_and_not_chained(self) -> None:
        refused = self._run('printf substituted >"$1/bin/flutter"')
        self.assertNotEqual(refused.returncode, 0)
        # Linux reports the write during the run (inotify); portable mode after it.
        self.assertRegex(
            refused.stderr, "changed (after compiler execution|while the compiler was running)"
        )
        self.assertEqual(list(self.chain.iterdir()), [])

    REWRITE_STAMPS = (
        'printf 0bf0f9e941c85d06ce4b5909d7a61b3a4f2a6a05 >"$1/bin/cache/libimobiledevice.stamp" && '
        'printf 19d6bec393c9f9b31ccb090059f59268da32e281 >"$1/bin/cache/libusbmuxd.stamp"'
    )

    def test_stamp_rewrite_with_the_same_bytes_passes_and_chains(self) -> None:
        first = self._run(self.REWRITE_STAMPS)
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self._run(self.REWRITE_STAMPS)
        self.assertEqual(second.returncode, 0, second.stderr)

    def test_stamp_with_different_bytes_is_refused(self) -> None:
        refused = self._run('printf changed >"$1/bin/cache/libusbmuxd.stamp"')
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("changed after compiler execution", refused.stderr)
        self.assertEqual(list(self.chain.iterdir()), [])

    def test_stamp_changed_between_runs_is_refused_at_the_next_chained_check(self) -> None:
        self.assertEqual(self._run(self.REWRITE_STAMPS).returncode, 0)
        (self.sdk / "bin/cache/libimobiledevice.stamp").write_bytes(b"different")
        refused = self._run("exit 0")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("authenticated compiler tree digest mismatch", refused.stderr)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and pathlib.Path("/proc/self/fd").is_dir(),
        "inotify write-event custody runs only on Linux (run in the builder image)",
    )
    def test_same_bytes_write_to_any_other_path_is_refused_by_inotify(self) -> None:
        for label, command in (
            ("launcher", 'printf "launcher\\n" >"$1/bin/flutter"'),
            ("other stamp", 'printf other >"$1/bin/cache/other.stamp"'),
            ("stamp delete and recreate",
             'rm "$1/bin/cache/libusbmuxd.stamp" && printf 19d6bec393c9f9b31ccb090059f59268da32e281 >"$1/bin/cache/libusbmuxd.stamp"'),
            ("pub cache", 'printf "lib\\n" >"$2/hosted/pub.dev/pkg/lib.dart"'),
        ):
            with self.subTest(label=label):
                refused = self._run(command, chain=False, portable=False)
                self.assertNotEqual(refused.returncode, 0, label)
                self.assertIn("changed while the compiler was running", refused.stderr)
        tolerated = self._run(self.REWRITE_STAMPS, chain=False, portable=False)
        self.assertEqual(tolerated.returncode, 0, tolerated.stderr)

    def test_chain_directory_must_be_private(self) -> None:
        os.chmod(self.chain, 0o755)
        refused = self._run("exit 0")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("private 0700 directory", refused.stderr)


if __name__ == "__main__":
    unittest.main()
