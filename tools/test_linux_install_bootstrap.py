#!/usr/bin/env python3
"""Regression contracts for linux/packaging/install-winsvpn-linux.sh.

M-2: this bootstrap is the only supported way to install a downloaded Win's
VPN Linux release. It must authenticate the *complete, unmodified* .tar.gz
with cosign, safety-check every tar member, and only then extract into a
fresh root-owned stage and hand off to install.sh. These tests check both
the shell-level contract (source assertions, matching the style already used
by test_linux_release_producer.py) and, since the embedded archive-member
safety check is a real executable Python program, its actual behavior
against a battery of crafted safe and malicious tar archives.
"""

from __future__ import annotations

import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
BOOTSTRAP_PATH = ROOT / "linux/packaging/install-winsvpn-linux.sh"
SOURCE = BOOTSTRAP_PATH.read_text(encoding="utf-8")


def _extract_embedded_python(source: str) -> str:
    match = re.search(r"python3 - \"\$archive\" <<'PY'\n(.*?)\nPY\n", source, re.DOTALL)
    assert match, "could not find the embedded archive-member safety-check script"
    return match.group(1)


SAFETY_CHECK_SCRIPT = _extract_embedded_python(SOURCE)


def _extract_bundle_check(source: str) -> str:
    match = re.search(
        r"/usr/bin/python3 - \"\$bundle\" \"\$STANDARD_BUNDLE_MEDIA_TYPE\" <<'PY'\n(.*?)\nPY\n",
        source,
        re.DOTALL,
    )
    assert match, "could not find the embedded standardized-bundle check"
    return match.group(1)


BUNDLE_CHECK_SCRIPT = _extract_bundle_check(SOURCE)


def _make_tar(path: pathlib.Path, add_members) -> None:
    with tarfile.open(path, "w:gz") as tf:
        add_members(tf)


def _add_file(tf: tarfile.TarFile, name: str, content: bytes = b"hello", **kwargs) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    for key, value in kwargs.items():
        setattr(info, key, value)
    tf.addfile(info, io.BytesIO(content))


def _add_dir(tf: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    tf.addfile(info)


def _run_safety_check(archive_path: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", SAFETY_CHECK_SCRIPT, str(archive_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class InstallBootstrapSourceContractTests(unittest.TestCase):
    """Source-level assertions about ordering, pins, and identity."""

    def test_requires_exact_reviewed_cosign_version(self) -> None:
        self.assertIn('COSIGN_VERSION="v3.1.3"', SOURCE)
        self.assertIn("Expected exact cosign", SOURCE)
        self.assertIn("GitVersion:", SOURCE)

    def test_refuses_legacy_bundles_before_verification(self) -> None:
        bundle_check = SOURCE.index("SIGSTORE STANDARD BUNDLE: PASS")
        verify = SOURCE.index('"$cosign_path" verify-blob "$archive"')
        self.assertLess(bundle_check, verify)
        self.assertIn("application/vnd.dev.sigstore.bundle.v0.3+json", SOURCE)

    def test_offline_public_key_is_a_root_owned_snapshotted_trust_anchor(self) -> None:
        self.assertIn(
            'OFFLINE_TRUST_ANCHOR_ROUTE="/etc/winsvpn/release-signing/cosign.pub"',
            SOURCE,
        )
        route_check = SOURCE.index('offline_pubkey_source="${OFFLINE_TRUST_ANCHOR_ROUTE}"')
        trust_check = SOURCE.index('trusted_root_path "$offline_pubkey_source"')
        snapshot = SOURCE.index('snapshot_file "$offline_pubkey_source" "$snapshot_pubkey"')
        verify = SOURCE.index('--key "$pubkey"', snapshot)
        self.assertLess(route_check, trust_check)
        self.assertLess(trust_check, snapshot)
        self.assertLess(snapshot, verify)
        self.assertIn('pubkey="$snapshot_pubkey"', SOURCE)

    def test_local_key_is_the_only_release_verification_authority(self) -> None:
        self.assertIn('COSIGN_PATH="/usr/local/bin/cosign"', SOURCE)
        self.assertIn("COSIGN_SHA256_X86_64=", SOURCE)
        self.assertIn("COSIGN_SHA256_AARCH64=", SOURCE)
        self.assertIn("Fixed cosign SHA-256", SOURCE)
        self.assertIn("WINS_LINUX_COSIGN_PUBKEY", SOURCE)
        self.assertIn("--offline", SOURCE)
        self.assertIn("--insecure-ignore-tlog", SOURCE)
        self.assertNotIn("--certificate-identity", SOURCE)
        self.assertNotIn("--certificate-oidc-issuer", SOURCE)

    def test_requires_linux_x86_64_or_arm64(self) -> None:
        self.assertIn('[[ "$(uname -s)" == Linux ]] || die', SOURCE)
        self.assertIn("x86_64|amd64|aarch64|arm64", SOURCE)

    def test_verifies_before_safety_checking_before_extracting_before_handoff(self) -> None:
        verify = SOURCE.index('"$cosign_path" verify-blob "$archive"')
        safety_check = SOURCE.index("Checking archive member safety", verify)
        extract = SOURCE.index("sudo tar --extract", safety_check)
        handoff = SOURCE.index("Handing off to the verified install.sh", extract)
        self.assertLess(verify, safety_check)
        self.assertLess(safety_check, extract)
        self.assertLess(extract, handoff)

    def test_archive_and_bundle_are_resolved_and_rejected_if_symlinks(self) -> None:
        self.assertIn(
            '[[ -f "$archive" && ! -L "$archive" ]] || die "Archive not found '
            'or is a symbolic link: $archive"',
            SOURCE,
        )
        self.assertIn(
            '[[ -f "$bundle" && ! -L "$bundle" ]] || die "Sigstore bundle not '
            'found or is a symbolic link: $bundle"',
            SOURCE,
        )
        self.assertIn('archive="$(realpath -e -- "$archive")"', SOURCE)
        self.assertIn('bundle="$(realpath -e -- "$bundle")"', SOURCE)

    def test_cosign_binary_is_fixed_digest_pinned_and_checked_before_use(self) -> None:
        fixed = SOURCE.index('cosign_path="$COSIGN_PATH"')
        digest_check = SOURCE.index('actual_cosign_sha256=', fixed)
        version_check = SOURCE.index("cosign_version_output=", digest_check)
        verify_blob = SOURCE.index('"$cosign_path" verify-blob', version_check)
        self.assertLess(fixed, digest_check)
        self.assertLess(digest_check, version_check)
        self.assertLess(version_check, verify_blob)
        self.assertIn(
            '[[ -f "$cosign_path" && -x "$cosign_path" && ! -L "$cosign_path" ]]',
            SOURCE,
        )

    def test_extraction_stage_is_freshly_created_root_owned_and_0700(self) -> None:
        # H-1 (TOCTOU): the archive/bundle are first copied into a fresh
        # root-owned snapshot dir and the copies are made immutable (0444)
        # before any verification, so a file that passed cosign can no longer
        # be swapped before root extraction. Extraction then runs into a 0700
        # `payload` subdir of that same root-owned snapshot; cleanup removes
        # the whole snapshot on exit.
        self.assertIn('snapshot_root="$(sudo mktemp -d /var/tmp/winsvpn-snapshot.XXXXXX)"', SOURCE)
        self.assertIn('cleanup() { sudo rm -rf -- "$snapshot_root"; }', SOURCE)
        self.assertIn("trap cleanup EXIT", SOURCE)
        # The snapshot copies are created O_EXCL|O_NOFOLLOW and left mode 0444
        # -- the immutability that closes the verify->extract swap window.
        self.assertIn("os.fchmod(destination_fd, 0o444)", SOURCE)
        # Extraction target is a 0700 payload dir inside the root-owned snapshot.
        self.assertIn('stage="$snapshot_root/payload"', SOURCE)
        self.assertIn('sudo mkdir -m 0700 -- "$stage"', SOURCE)
        self.assertIn('sudo chown -R root:root -- "$stage"', SOURCE)

    def test_extraction_does_not_trust_archive_supplied_owners_or_permissions(self) -> None:
        self.assertIn("--no-same-owner --no-same-permissions", SOURCE)

    def test_installer_presence_is_verified_before_handoff_and_rejects_symlink(self) -> None:
        installer_check = SOURCE.index('installer="$stage/install.sh"')
        handoff = SOURCE.index("Handing off to the verified install.sh", installer_check)
        self.assertLess(installer_check, handoff)
        self.assertIn('if ! sudo test -f "$installer"; then', SOURCE)
        self.assertIn('if sudo test -L "$installer"; then', SOURCE)

    def test_handoff_uses_a_clean_minimal_environment_and_sets_verified_stage(self) -> None:
        self.assertIn("sudo env -i PATH=", SOURCE)
        self.assertIn('WINSVPN_VERIFIED_STAGE=1 "$installer"', SOURCE)

    def test_never_curls_a_shell_script_for_cosign(self) -> None:
        # "curl" appears only as prose (header comment + a die message)
        # warning the operator against a curl-pipe-to-shell cosign install --
        # the script itself never invokes curl as a command.
        self.assertIsNone(re.search(r"(^|[;&|(]|\$\()\s*curl\b", SOURCE, re.MULTILINE))
        self.assertIn("never `curl", SOURCE)


class ArchiveMemberSafetyCheckExecutionTests(unittest.TestCase):
    """Executes the embedded Python safety check against real tar archives."""

    def setUp(self) -> None:
        import tempfile

        self._tmpdir_ctx = tempfile.TemporaryDirectory()
        self.tmpdir = pathlib.Path(self._tmpdir_ctx.name)
        self.addCleanup(self._tmpdir_ctx.cleanup)

    def _archive(self, name: str) -> pathlib.Path:
        return self.tmpdir / f"{name}.tar.gz"

    def test_script_parses_as_valid_python(self) -> None:
        import ast

        ast.parse(SAFETY_CHECK_SCRIPT)

    def test_accepts_a_normal_safe_archive(self) -> None:
        archive = self._archive("safe")

        def build(tf: tarfile.TarFile) -> None:
            _add_dir(tf, "share/")
            _add_file(tf, "install.sh", b"#!/bin/bash\necho hi\n")
            _add_file(tf, "share/notice.txt")

        _make_tar(archive, build)
        result = _run_safety_check(archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ARCHIVE MEMBER SAFETY CHECK: PASS (3 members)", result.stdout)

    def test_rejects_absolute_path_member(self) -> None:
        archive = self._archive("absolute")
        _make_tar(archive, lambda tf: _add_file(tf, "/etc/passwd", b"pwned"))
        result = _run_safety_check(archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsafe absolute or path-traversal", result.stderr)

    def test_rejects_leading_path_traversal(self) -> None:
        archive = self._archive("traversal")
        _make_tar(
            archive,
            lambda tf: _add_file(tf, "../../etc/cron.d/evil", b"* * * * * root touch /tmp/pwned"),
        )
        result = _run_safety_check(archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsafe absolute or path-traversal", result.stderr)

    def test_rejects_nested_mid_path_traversal(self) -> None:
        archive = self._archive("nested_traversal")
        _make_tar(archive, lambda tf: _add_file(tf, "share/../../../etc/evil", b"data"))
        result = _run_safety_check(archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsafe absolute or path-traversal", result.stderr)

    def test_rejects_bare_dotdot_member(self) -> None:
        archive = self._archive("dotdot")

        def build(tf: tarfile.TarFile) -> None:
            info = tarfile.TarInfo(name="..")
            info.type = tarfile.DIRTYPE
            tf.addfile(info)

        _make_tar(archive, build)
        result = _run_safety_check(archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsafe absolute or path-traversal", result.stderr)

    def test_rejects_symlink_member(self) -> None:
        archive = self._archive("symlink")

        def build(tf: tarfile.TarFile) -> None:
            info = tarfile.TarInfo(name="evil_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/shadow"
            tf.addfile(info)

        _make_tar(archive, build)
        result = _run_safety_check(archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Archive contains a link", result.stderr)

    def test_rejects_hardlink_member(self) -> None:
        archive = self._archive("hardlink")

        def build(tf: tarfile.TarFile) -> None:
            _add_file(tf, "real_file", b"data")
            info = tarfile.TarInfo(name="hard_link")
            info.type = tarfile.LNKTYPE
            info.linkname = "real_file"
            tf.addfile(info)

        _make_tar(archive, build)
        result = _run_safety_check(archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Archive contains a link", result.stderr)

    def test_rejects_duplicate_member_names(self) -> None:
        archive = self._archive("duplicate")

        def build(tf: tarfile.TarFile) -> None:
            _add_file(tf, "install.sh", b"first version")
            _add_file(tf, "install.sh", b"second version -- TOCTOU swap within one archive")

        _make_tar(archive, build)
        result = _run_safety_check(archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate archive member", result.stderr)

    def test_rejects_empty_archive(self) -> None:
        archive = self._archive("empty")
        _make_tar(archive, lambda tf: None)
        result = _run_safety_check(archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Archive contains no members", result.stderr)

    def test_accepts_archive_with_many_ordinary_nested_files(self) -> None:
        archive = self._archive("nested_safe")

        def build(tf: tarfile.TarFile) -> None:
            _add_dir(tf, "a/")
            _add_dir(tf, "a/b/")
            _add_file(tf, "a/b/c.txt")
            _add_file(tf, "wins_vpn", b"\x7fELF")

        _make_tar(archive, build)
        result = _run_safety_check(archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS (4 members)", result.stdout)


class StandardBundleCheckExecutionTests(unittest.TestCase):
    def _run_raw(self, payload: str) -> subprocess.CompletedProcess:
        import tempfile

        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "bundle.sigstore.json"
            path.write_text(payload, encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    "-c",
                    BUNDLE_CHECK_SCRIPT,
                    str(path),
                    "application/vnd.dev.sigstore.bundle.v0.3+json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def _run(self, payload: object) -> subprocess.CompletedProcess:
        return self._run_raw(json.dumps(payload))

    def test_accepts_standard_message_signature_bundle_shape(self) -> None:
        result = self._run(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {},
                "messageSignature": {},
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_legacy_bundle_with_attacker_public_key(self) -> None:
        result = self._run(
            {
                "base64Signature": "fixture",
                "cert": "-----BEGIN PUBLIC KEY-----\nattacker\n-----END PUBLIC KEY-----",
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("legacy or unsupported", result.stderr)

    def test_rejects_duplicate_top_level_json_key(self) -> None:
        result = self._run_raw(
            '{"mediaType":"attacker","mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",'
            '"verificationMaterial":{},"messageSignature":{}}'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate JSON key: mediaType", result.stderr)

    def test_rejects_duplicate_nested_json_key(self) -> None:
        result = self._run_raw(
            '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",'
            '"verificationMaterial":{"content":"attacker","content":"trusted"},'
            '"messageSignature":{}}'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate JSON key: content", result.stderr)

if __name__ == "__main__":
    unittest.main()
