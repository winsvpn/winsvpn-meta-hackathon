#!/usr/bin/env python3
"""Contracts for local/offline Linux release signing."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from linux_release_signing import (  # noqa: E402
    COSIGN_PATH,
    COSIGN_VERSION,
    INSTALLER_TRUST_ANCHOR_ROUTE,
    OWNER_BLOCKED,
    SigningError,
    build_parser,
    open_authenticated_cosign,
    preflight,
    signing_mode,
    validate_standard_bundle,
)


SOURCE = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
BOOTSTRAP = (ROOT / "linux/packaging/install-winsvpn-linux.sh").read_text(encoding="utf-8")


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


class LinuxReleaseSigningContractTests(unittest.TestCase):
    def test_missing_cosign_and_key_material_stay_owner_blocked(self) -> None:
        self.assertEqual(OWNER_BLOCKED, "OWNER-BLOCKED: ABSENT")
        with self.assertRaisesRegex(
            SigningError, r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT"
        ):
            with open_authenticated_cosign():
                pass
        env = os.environ.copy()
        try:
            os.environ["SIGN_LINUX_RELEASE"] = "1"
            os.environ.pop("WINS_LINUX_SIGNER_IDENTITY", None)
            os.environ.pop("WINS_LINUX_SIGNER_OIDC_ISSUER", None)
            os.environ.pop("WINS_LINUX_COSIGN_KEY", None)
            os.environ.pop("WINS_LINUX_COSIGN_PUBKEY", None)
            os.environ.pop("WINS_LINUX_COSIGN_TRUST_ANCHOR", None)
            with self.assertRaisesRegex(
                SigningError, r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT"
            ):
                signing_mode()
        finally:
            os.environ.clear()
            os.environ.update(env)

    def test_fixed_cosign_version_is_required_everywhere(self) -> None:
        self.assertEqual(COSIGN_VERSION, "v3.1.3")
        self.assertIn('COSIGN_VERSION="v3.1.3"', SOURCE)
        self.assertIn('COSIGN_VERSION="v3.1.3"', BOOTSTRAP)

    def test_standard_bundle_validator_rejects_legacy_shape(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle = pathlib.Path(name) / "legacy.sigstore.json"
            bundle.write_text(
                json.dumps(
                    {
                        "base64Signature": "fixture",
                        "cert": "-----BEGIN PUBLIC KEY-----\nattacker\n-----END PUBLIC KEY-----",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SigningError):
                validate_standard_bundle(str(bundle))

    def test_producer_uses_the_shared_contract(self) -> None:
        self.assertIn("tools/linux_release_signing.py", SOURCE)
        self.assertIn("run-sign-verify", SOURCE)
        self.assertIn("run-verify", SOURCE)
        self.assertIn('COSIGN_PATH="/usr/local/bin/cosign"', SOURCE)
        self.assertNotIn("--certificate-identity", SOURCE)
        self.assertNotIn("--certificate-oidc-issuer", SOURCE)

    def test_bootstrap_requires_only_the_fixed_local_key_contract(self) -> None:
        self.assertIn('COSIGN_PATH="/usr/local/bin/cosign"', BOOTSTRAP)
        self.assertIn("COSIGN_SHA256_X86_64=", BOOTSTRAP)
        self.assertIn("COSIGN_SHA256_AARCH64=", BOOTSTRAP)
        self.assertIn('offline_pubkey_source="${OFFLINE_TRUST_ANCHOR_ROUTE}"', BOOTSTRAP)
        self.assertIn(
            f'OFFLINE_TRUST_ANCHOR_ROUTE="{INSTALLER_TRUST_ANCHOR_ROUTE}"',
            BOOTSTRAP,
        )
        self.assertIn("--offline", BOOTSTRAP)
        self.assertIn("--insecure-ignore-tlog", BOOTSTRAP)
        self.assertNotIn("--certificate-identity", BOOTSTRAP)
        self.assertNotIn("--certificate-oidc-issuer", BOOTSTRAP)
        self.assertNotIn('offline_pubkey_source="$(realpath', BOOTSTRAP)
        self.assertIn('[[ ! -L "$candidate" ]] || return 1', BOOTSTRAP)
        verify = BOOTSTRAP.index('"$cosign_path" verify-blob "$archive"')
        safety_check = BOOTSTRAP.index("Checking archive member safety", verify)
        extract = BOOTSTRAP.index("sudo tar --extract", safety_check)
        self.assertLess(verify, safety_check)
        self.assertLess(safety_check, extract)

    def test_retired_remote_signing_environment_is_refused(self) -> None:
        env = os.environ.copy()
        try:
            os.environ["SIGN_LINUX_RELEASE"] = "1"
            os.environ["WINS_LINUX_SIGNER_IDENTITY"] = "retired-remote-signer"
            os.environ["WINS_LINUX_SIGNER_OIDC_ISSUER"] = "retired-issuer"
            os.environ["WINS_LINUX_COSIGN_KEY"] = "/tmp/does-not-need-to-exist.key"
            os.environ["WINS_LINUX_COSIGN_PUBKEY"] = "/tmp/does-not-need-to-exist.pub"
            os.environ["WINS_LINUX_COSIGN_TRUST_ANCHOR"] = INSTALLER_TRUST_ANCHOR_ROUTE
            with self.assertRaises(SigningError):
                signing_mode()
        finally:
            os.environ.clear()
            os.environ.update(env)

    def test_cli_exposes_only_integrated_sign_and_verify_operations(self) -> None:
        action = next(
            item for item in build_parser()._actions if item.dest == "action"
        )
        self.assertEqual(
            set(action.choices),
            {
                "preflight",
                "mode",
                "authenticate-cosign",
                "run-sign-verify",
                "run-verify",
                "validate-bundle",
            },
        )
        signing_source = (ROOT / "tools/linux_release_signing.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("argv-sign", signing_source)
        self.assertNotIn("argv-verify", signing_source)

    def test_integrated_local_key_commands_are_offline(self) -> None:
        signing_source = (ROOT / "tools/linux_release_signing.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"sign-blob"', signing_source)
        self.assertIn('"verify-blob"', signing_source)
        self.assertIn('"--tlog-upload=false"', signing_source)
        self.assertIn('"--offline"', signing_source)
        self.assertIn('"--insecure-ignore-tlog"', signing_source)
        self.assertNotIn('"--certificate-identity"', signing_source)
        self.assertNotIn('"--certificate-oidc-issuer"', signing_source)

    def test_local_key_preflight_accepts_owner_custody(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".wins-linux-signing-", dir=ROOT.parent
        ) as name:
            root = pathlib.Path(name)
            keys = root / "keys"
            keys.mkdir()
            key = keys / "cosign.key"
            pubkey = keys / "cosign.pub"
            key.write_text("private-fixture\n", encoding="utf-8")
            pubkey.write_text("public-fixture\n", encoding="utf-8")
            key.chmod(0o600)
            pubkey.chmod(0o644)
            env = os.environ.copy()
            try:
                os.environ["SIGN_LINUX_RELEASE"] = "1"
                os.environ.pop("WINS_LINUX_SIGNER_IDENTITY", None)
                os.environ.pop("WINS_LINUX_SIGNER_OIDC_ISSUER", None)
                os.environ["WINS_LINUX_COSIGN_KEY"] = str(key)
                os.environ["WINS_LINUX_COSIGN_PUBKEY"] = str(pubkey)
                os.environ["WINS_LINUX_COSIGN_TRUST_ANCHOR"] = INSTALLER_TRUST_ANCHOR_ROUTE
                self.assertEqual(preflight(ROOT), "key")
            finally:
                os.environ.clear()
                os.environ.update(env)

    def test_local_key_preflight_rejects_sticky_world_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".wins-linux-signing-", dir=ROOT.parent
        ) as name:
            root = pathlib.Path(name)
            sticky = root / "sticky"
            sticky.mkdir(mode=0o700)
            sticky.chmod(0o1777)
            keys = sticky / "keys"
            keys.mkdir(mode=0o700)
            key = keys / "cosign.key"
            pubkey = keys / "cosign.pub"
            key.write_text("private-fixture\n", encoding="utf-8")
            pubkey.write_text("public-fixture\n", encoding="utf-8")
            key.chmod(0o600)
            pubkey.chmod(0o644)
            env = os.environ.copy()
            try:
                os.environ["SIGN_LINUX_RELEASE"] = "1"
                os.environ.pop("WINS_LINUX_SIGNER_IDENTITY", None)
                os.environ.pop("WINS_LINUX_SIGNER_OIDC_ISSUER", None)
                os.environ["WINS_LINUX_COSIGN_KEY"] = str(key)
                os.environ["WINS_LINUX_COSIGN_PUBKEY"] = str(pubkey)
                os.environ["WINS_LINUX_COSIGN_TRUST_ANCHOR"] = (
                    INSTALLER_TRUST_ANCHOR_ROUTE
                )
                with self.assertRaisesRegex(SigningError, "group/other-writable"):
                    preflight(ROOT)
            finally:
                os.environ.clear()
                os.environ.update(env)

    def test_repository_local_key_is_refused(self) -> None:
        env = os.environ.copy()
        try:
            os.environ["SIGN_LINUX_RELEASE"] = "1"
            os.environ.pop("WINS_LINUX_SIGNER_IDENTITY", None)
            os.environ.pop("WINS_LINUX_SIGNER_OIDC_ISSUER", None)
            os.environ["WINS_LINUX_COSIGN_KEY"] = str(ROOT / "tools/linux_release_signing.py")
            os.environ["WINS_LINUX_COSIGN_PUBKEY"] = str(
                ROOT / "tools/test_linux_release_signing.py"
            )
            os.environ["WINS_LINUX_COSIGN_TRUST_ANCHOR"] = INSTALLER_TRUST_ANCHOR_ROUTE
            with self.assertRaises(SigningError):
                preflight(ROOT)
        finally:
            os.environ.clear()
            os.environ.update(env)

    def test_cli_preflight_unsigned(self) -> None:
        env = os.environ.copy()
        try:
            os.environ["SIGN_LINUX_RELEASE"] = "0"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/linux_release_signing.py"),
                    "preflight",
                    "--repo",
                    str(ROOT),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        finally:
            os.environ.clear()
            os.environ.update(env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "unsigned")

    def test_producer_signing_self_test(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".wins-linux-signing-", dir=ROOT.parent
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

    def test_producer_does_not_execute_hostile_path_cosign(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".wins-linux-signing-", dir=ROOT.parent
        ) as name:
            root = pathlib.Path(name)
            marker = root / "hostile-cosign-executed"
            fake = root / "cosign"
            fake.write_text(
                f"#!/bin/sh\nprintf hostile > {marker!s}\nexit 0\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            environment = os.environ.copy()
            launcher_dir = _write_authenticated_python_launcher(root)
            environment["PATH"] = (
                f"{root}{os.pathsep}{launcher_dir}"
                f"{os.pathsep}/usr/bin:/bin:/usr/sbin:/sbin"
            )
            environment["TMPDIR"] = str(root)
            completed = subprocess.run(
                ["bash", str(ROOT / "tools/build_linux_release.sh"), "--self-test-signing"],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(marker.exists(), "producer executed cosign selected from PATH")

    def test_bootstrap_resets_hostile_path_before_program_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            marker = root / "hostile-path-program-executed"
            for command in ("cosign", "uname", "realpath", "sha256sum"):
                fake = root / command
                fake.write_text(
                    f"#!/bin/sh\nprintf hostile >> {marker!s}\nexit 0\n",
                    encoding="utf-8",
                )
                fake.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = str(root)
            completed = subprocess.run(
                ["/bin/bash", str(ROOT / "linux/packaging/install-winsvpn-linux.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(marker.exists(), "bootstrap resolved a hostile PATH program")

    def test_fake_cosign_requires_an_explicit_fixture_digest_binding(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            fake = pathlib.Path(name) / "cosign"
            fake.write_text("#!/bin/sh\nprintf 'GitVersion: v3.1.3\\n'\n", encoding="utf-8")
            fake.chmod(0o755)
            digest = hashlib.sha256(fake.read_bytes()).hexdigest()
            with (
                mock.patch("linux_release_signing.COSIGN_PATH", str(fake)),
                mock.patch("linux_release_signing.assert_owner_controlled_path_chain"),
                mock.patch("linux_release_signing._validate_open_file"),
                mock.patch("linux_release_signing._proc_fd_path", return_value=str(fake)),
                mock.patch("linux_release_signing.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="GitVersion: v3.1.3\n")),
            ):
                with self.assertRaisesRegex(SigningError, "SHA-256 mismatch"):
                    with open_authenticated_cosign(str(fake)):
                        pass
                with mock.patch(
                    "linux_release_signing.COSIGN_SHA256_BY_MACHINE",
                    {platform.machine().lower(): digest},
                ), mock.patch(
                    "linux_release_signing.COSIGN_DARWIN_SHA256_BY_MACHINE",
                    {platform.machine().lower(): digest},
                ):
                    with open_authenticated_cosign(str(fake)):
                        pass

    def _authenticate_fixture_cosign(self, fake: pathlib.Path) -> mock.MagicMock:
        digest = hashlib.sha256(fake.read_bytes()).hexdigest()
        chain = mock.MagicMock()
        with (
            mock.patch("linux_release_signing.COSIGN_PATH", str(fake)),
            mock.patch("linux_release_signing.assert_owner_controlled_path_chain", chain),
            mock.patch("linux_release_signing._proc_fd_path", return_value=str(fake)),
            mock.patch(
                "linux_release_signing.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="GitVersion: v3.1.3\n"),
            ),
            mock.patch(
                "linux_release_signing.COSIGN_SHA256_BY_MACHINE",
                {platform.machine().lower(): digest},
            ),
            mock.patch(
                "linux_release_signing.COSIGN_DARWIN_SHA256_BY_MACHINE",
                {platform.machine().lower(): digest},
            ),
        ):
            with open_authenticated_cosign(str(fake)):
                pass
        return chain

    def test_pinned_cosign_needs_no_root_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            fake = pathlib.Path(name) / "cosign"
            fake.write_text("#!/bin/sh\nprintf 'GitVersion: v3.1.3\\n'\n", encoding="utf-8")
            fake.chmod(0o755)
            self.assertNotEqual(os.stat(fake).st_uid, 0)
            chain = self._authenticate_fixture_cosign(fake)
            chain.assert_called_once()
            self.assertEqual(chain.call_args.kwargs.get("root_only"), False)
            self.assertEqual(chain.call_args.kwargs.get("include_leaf"), False)

    def test_pinned_cosign_still_refuses_writable_or_linked_executables(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            fake = pathlib.Path(name) / "cosign"
            fake.write_text("#!/bin/sh\nprintf 'GitVersion: v3.1.3\\n'\n", encoding="utf-8")
            fake.chmod(0o775)
            with self.assertRaisesRegex(SigningError, "must not be writable by group or other"):
                self._authenticate_fixture_cosign(fake)
            fake.chmod(0o644)
            with self.assertRaisesRegex(SigningError, "must be executable"):
                self._authenticate_fixture_cosign(fake)
            fake.chmod(0o755)
            os.link(fake, pathlib.Path(name) / "cosign-second-link")
            with self.assertRaisesRegex(SigningError, "must not be hard-linked"):
                self._authenticate_fixture_cosign(fake)

    def test_local_key_mode_requires_exact_installer_trust_anchor_route(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            key = root / "cosign.key"
            pubkey = root / "cosign.pub"
            key.write_text("private-fixture\n", encoding="utf-8")
            pubkey.write_text("public-fixture\n", encoding="utf-8")
            key.chmod(0o600)
            pubkey.chmod(0o644)
            env = os.environ.copy()
            try:
                os.environ["SIGN_LINUX_RELEASE"] = "1"
                os.environ.pop("WINS_LINUX_SIGNER_IDENTITY", None)
                os.environ.pop("WINS_LINUX_SIGNER_OIDC_ISSUER", None)
                os.environ["WINS_LINUX_COSIGN_KEY"] = str(key)
                os.environ["WINS_LINUX_COSIGN_PUBKEY"] = str(pubkey)
                os.environ.pop("WINS_LINUX_COSIGN_TRUST_ANCHOR", None)
                with mock.patch("linux_release_signing.assert_owner_controlled_path_chain"):
                    with self.assertRaisesRegex(SigningError, "TRUST_ANCHOR"):
                        preflight(ROOT)
                os.environ["WINS_LINUX_COSIGN_TRUST_ANCHOR"] = "/tmp/cosign.pub"
                with mock.patch("linux_release_signing.assert_owner_controlled_path_chain"):
                    with self.assertRaisesRegex(SigningError, "reviewed installer route"):
                        preflight(ROOT)
                os.environ["WINS_LINUX_COSIGN_TRUST_ANCHOR"] = INSTALLER_TRUST_ANCHOR_ROUTE
                with mock.patch("linux_release_signing.assert_owner_controlled_path_chain"):
                    self.assertEqual(preflight(ROOT), "key")
            finally:
                os.environ.clear()
                os.environ.update(env)

    def test_local_key_files_require_owner_safe_modes_and_single_links(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            key = root / "cosign.key"
            pubkey = root / "cosign.pub"
            key.write_text("private-fixture\n", encoding="utf-8")
            pubkey.write_text("public-fixture\n", encoding="utf-8")
            env = os.environ.copy()
            try:
                os.environ["SIGN_LINUX_RELEASE"] = "1"
                os.environ.pop("WINS_LINUX_SIGNER_IDENTITY", None)
                os.environ.pop("WINS_LINUX_SIGNER_OIDC_ISSUER", None)
                os.environ["WINS_LINUX_COSIGN_KEY"] = str(key)
                os.environ["WINS_LINUX_COSIGN_PUBKEY"] = str(pubkey)
                os.environ["WINS_LINUX_COSIGN_TRUST_ANCHOR"] = INSTALLER_TRUST_ANCHOR_ROUTE

                key.chmod(0o644)
                pubkey.chmod(0o644)
                with mock.patch("linux_release_signing.assert_owner_controlled_path_chain"):
                    with self.assertRaisesRegex(SigningError, "mode 0600"):
                        preflight(ROOT)

                key.chmod(0o600)
                pubkey.chmod(0o666)
                with mock.patch("linux_release_signing.assert_owner_controlled_path_chain"):
                    with self.assertRaisesRegex(SigningError, "0644 or stricter"):
                        preflight(ROOT)

                pubkey.chmod(0o644)
                with mock.patch("linux_release_signing.os.getuid", return_value=os.getuid() + 1):
                    with mock.patch("linux_release_signing.assert_owner_controlled_path_chain"):
                        with self.assertRaisesRegex(SigningError, "current user"):
                            preflight(ROOT)

                hardlink = root / "cosign.key.second-link"
                os.link(key, hardlink)
                with mock.patch("linux_release_signing.assert_owner_controlled_path_chain"):
                    with self.assertRaisesRegex(SigningError, "hard-linked"):
                        preflight(ROOT)
            finally:
                os.environ.clear()
                os.environ.update(env)

    def test_local_key_paths_reject_symlinked_files(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            key = root / "cosign.key"
            pubkey = root / "cosign.pub"
            key.write_text("private-fixture\n", encoding="utf-8")
            pubkey.write_text("public-fixture\n", encoding="utf-8")
            key.chmod(0o600)
            pubkey.chmod(0o644)
            linked = root / "cosign-key-link"
            linked.symlink_to(key)
            env = os.environ.copy()
            try:
                os.environ["SIGN_LINUX_RELEASE"] = "1"
                os.environ.pop("WINS_LINUX_SIGNER_IDENTITY", None)
                os.environ.pop("WINS_LINUX_SIGNER_OIDC_ISSUER", None)
                os.environ["WINS_LINUX_COSIGN_KEY"] = str(linked)
                os.environ["WINS_LINUX_COSIGN_PUBKEY"] = str(pubkey)
                os.environ["WINS_LINUX_COSIGN_TRUST_ANCHOR"] = INSTALLER_TRUST_ANCHOR_ROUTE
                with mock.patch("linux_release_signing.assert_owner_controlled_path_chain"):
                    with self.assertRaisesRegex(SigningError, "could not be opened without following links"):
                        preflight(ROOT)
            finally:
                os.environ.clear()
                os.environ.update(env)


    def test_darwin_cosign_pin_is_the_official_release_digest(self) -> None:
        import linux_release_signing as signing

        # cosign_checksums.txt of sigstore/cosign v3.1.3 lists these three; its
        # Linux entries equal the reviewed Linux pins, which authenticates the file.
        self.assertEqual(
            signing.COSIGN_DARWIN_SHA256_BY_MACHINE,
            {"arm64": "5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76"},
        )
        self.assertEqual(
            signing.COSIGN_SHA256_BY_MACHINE["x86_64"],
            "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
        )
        self.assertEqual(
            signing.COSIGN_SHA256_BY_MACHINE["aarch64"],
            "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a",
        )

    def test_cosign_rewritten_in_place_after_authentication_is_refused(self) -> None:
        import linux_release_signing as signing

        with tempfile.TemporaryDirectory() as name:
            fake = pathlib.Path(name) / "cosign"
            original = b"#!/bin/sh\nprintf 'GitVersion: v3.1.3\\n'\n"
            fake.write_bytes(original)
            fake.chmod(0o755)
            digest = hashlib.sha256(original).hexdigest()
            machine = platform.machine().lower()
            with mock.patch.object(signing, "COSIGN_PATH", str(fake)), mock.patch.object(
                signing, "assert_owner_controlled_path_chain"
            ), mock.patch.object(
                signing, "COSIGN_SHA256_BY_MACHINE", {machine: digest}
            ), mock.patch.object(
                signing, "COSIGN_DARWIN_SHA256_BY_MACHINE", {machine: digest}
            ):
                with signing.open_authenticated_cosign(str(fake)) as cosign_fd:
                    before = os.stat(fake)
                    # Same inode and same size: only the bytes differ.
                    replacement = b"#!/bin/sh\nexit 0\n".ljust(len(original), b"#")
                    with fake.open("r+b") as handle:
                        handle.write(replacement)
                    after = os.stat(fake)
                    self.assertEqual(
                        (before.st_dev, before.st_ino, before.st_size),
                        (after.st_dev, after.st_ino, after.st_size),
                    )
                    with mock.patch.object(signing.subprocess, "run") as run:
                        with self.assertRaisesRegex(
                            SigningError, "changed after authentication"
                        ):
                            signing._run_cosign(cosign_fd, ["version"], ())
                    run.assert_not_called()

    def test_cosign3_offline_signing_opts_out_of_the_signing_config(self) -> None:
        import linux_release_signing as signing

        arguments = signing._sign_arguments("/a", "/b", "/dev/fd/5")
        self.assertIn("--use-signing-config=false", arguments)
        self.assertIn("--tlog-upload=false", arguments)
        self.assertLess(
            arguments.index("--use-signing-config=false"),
            arguments.index("--tlog-upload=false"),
        )

    def test_version_check_tolerates_cosign_column_alignment(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            fake = pathlib.Path(name) / "cosign"
            fake.write_text("#!/bin/sh\n", encoding="utf-8")
            fake.chmod(0o755)
            digest = hashlib.sha256(fake.read_bytes()).hexdigest()
            for output, accepted in (
                ("GitVersion:    v3.1.3\nGitCommit:     x\n", True),
                ("GitVersion:    v3.1.2\n", False),
            ):
                with self.subTest(output=output), (
                    mock.patch("linux_release_signing.COSIGN_PATH", str(fake))
                ), mock.patch("linux_release_signing.assert_owner_controlled_path_chain"), mock.patch(
                    "linux_release_signing._proc_fd_path", return_value=str(fake)
                ), mock.patch(
                    "linux_release_signing.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, stdout=output),
                ), mock.patch(
                    "linux_release_signing.COSIGN_SHA256_BY_MACHINE", {platform.machine().lower(): digest}
                ), mock.patch(
                    "linux_release_signing.COSIGN_DARWIN_SHA256_BY_MACHINE", {platform.machine().lower(): digest}
                ):
                    if accepted:
                        with open_authenticated_cosign(str(fake)):
                            pass
                    else:
                        with self.assertRaisesRegex(SigningError, "Expected exact Cosign"):
                            with open_authenticated_cosign(str(fake)):
                                pass

if __name__ == "__main__":
    unittest.main()
