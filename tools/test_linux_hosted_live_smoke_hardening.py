#!/usr/bin/env python3
"""Adversarial contracts for the retired hosted Linux release authority.

These tests intentionally use fake Cosign files and mutable local inputs.  They
exercise only the fail-closed evidence verifier and never invoke a workflow,
sign an artifact, publish anything, or contact a remote service.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import public_release_live_smoke_common as smoke  # noqa: E402


WORKFLOW = ROOT / ".github/workflows/build-linux-release.yml"
WRAPPER = ROOT / "tools/linux_public_release_live_smoke.sh"
DEPLOYMENT_DOC = ROOT / "README_FINAL_DEPLOYMENT.md"
CHECKLIST_DOC = ROOT / "docs/CROSS_STORE_RELEASE_CHECKLIST.md"


def _standard_bundle() -> str:
    return json.dumps(
        {
            "mediaType": smoke.LINUX_STANDARD_BUNDLE_MEDIA_TYPE,
            "verificationMaterial": {},
            "messageSignature": {},
        }
    )


class HostedWorkflowPolicyTests(unittest.TestCase):
    def test_workflow_is_an_inert_local_signing_policy_sentinel(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8").lower()
        self.assertIn("workflow_dispatch:", source)
        self.assertIn("contents: read", source)
        self.assertIn("exit 64", source)
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
            self.assertNotIn(forbidden, source, forbidden)

    def test_docs_describe_only_the_fixed_local_linux_authority(self) -> None:
        deployment = DEPLOYMENT_DOC.read_text(encoding="utf-8").lower()
        checklist = CHECKLIST_DOC.read_text(encoding="utf-8").lower()
        self.assertIn("/usr/local/bin/cosign", deployment)
        self.assertIn("/etc/winsvpn/release-signing/cosign.pub", deployment)
        self.assertIn("github is backup storage only", deployment)
        self.assertNotIn("signs keylessly with github oidc", deployment)
        self.assertNotIn("github actions oidc issuer", deployment)
        self.assertNotIn("cosign 3.0.6", deployment)
        self.assertIn("local key signing", checklist)
        self.assertIn("/etc/winsvpn/release-signing/cosign.pub", checklist)


class LinuxLiveSmokeWrapperTests(unittest.TestCase):
    def test_wrapper_refuses_each_retired_remote_signer_environment(self) -> None:
        for retired in smoke.RETIRED_LINUX_SIGNER_ENV:
            with self.subTest(retired=retired):
                env = os.environ.copy()
                env[retired] = "retired-remote-authority"
                completed = subprocess.run(
                    ["bash", str(WRAPPER)],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn("retired", completed.stderr.lower())
                self.assertIn("local /etc trust anchor", completed.stderr.lower())

    def test_wrapper_never_accepts_remote_signer_arguments(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("WINS_LINUX_COSIGN_BUNDLE", source)
        for forbidden in (
            "--certificate-identity",
            "--certificate-oidc-issuer",
            "WINS_LINUX_SIGNER_IDENTITY=",
            "WINS_LINUX_SIGNER_OIDC_ISSUER=",
        ):
            self.assertNotIn(forbidden, source, forbidden)


class LinuxLiveSmokeSignatureAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tempdir.name)
        self.cosign = self.root / "reviewed-cosign"
        self.cosign.write_text("#!/bin/sh\nprintf 'GitVersion: v3.1.3\\n'\n", encoding="utf-8")
        self.cosign.chmod(0o755)
        self.trust = self.root / "cosign.pub"
        self.trust.write_text("fixture-local-public-key\n", encoding="utf-8")
        self.artifact = self.root / "wins-vpn-linux.tar.gz"
        self.artifact.write_bytes(b"release-artifact")
        self.bundle = self.root / "wins-vpn-linux.tar.gz.sigstore.json"
        self.bundle.write_text(_standard_bundle(), encoding="utf-8")
        self.args = type("Args", (), {"linux_bundle": str(self.bundle)})()
        self.calls: list[list[str]] = []

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @contextlib.contextmanager
    def _test_open_root(self, path: pathlib.Path, label: str, *, executable: bool):
        del label, executable
        with smoke._open_linux_input_file(path, "fixture root input") as fd:
            yield fd

    def _run(self, argv: list[str], pass_fds: tuple[int, ...], label: str):
        del pass_fds, label
        self.calls.append(argv)
        if argv[-1] == "version":
            return subprocess.CompletedProcess(argv, 0, "GitVersion: v3.1.3\n")
        return subprocess.CompletedProcess(argv, 0, "")

    def _patches(self, *, expected_digest: str | None = None):
        expected = expected_digest or hashlib.sha256(self.cosign.read_bytes()).hexdigest()
        return contextlib.ExitStack(), {
            "cosign": mock.patch.object(smoke, "LINUX_COSIGN_PATH", self.cosign),
            "trust": mock.patch.object(smoke, "LINUX_COSIGN_TRUST_ANCHOR", self.trust),
            "digests": mock.patch.object(
                smoke,
                "LINUX_COSIGN_SHA256_BY_MACHINE",
                {"x86_64": expected},
            ),
            "platform": mock.patch.object(smoke.sys, "platform", "linux"),
            "machine": mock.patch.object(smoke.platform, "machine", return_value="x86_64"),
            "root_open": mock.patch.object(smoke, "_open_linux_root_file", self._test_open_root),
            "run": mock.patch.object(smoke, "_run_linux_cosign", self._run),
            "fd_path": mock.patch.object(smoke, "_linux_fd_path", side_effect=lambda fd: f"/fixture-fd/{fd}"),
        }

    @contextlib.contextmanager
    def _verification_context(self, *, expected_digest: str | None = None):
        stack, patches = self._patches(expected_digest=expected_digest)
        with stack:
            for patch in patches.values():
                stack.enter_context(patch)
            yield

    def test_path_fake_is_never_selected(self) -> None:
        path_fake_dir = self.root / "attacker-bin"
        path_fake_dir.mkdir()
        marker = self.root / "path-fake-ran"
        path_fake = path_fake_dir / "cosign"
        path_fake.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        path_fake.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(path_fake_dir) + os.pathsep + old_path
        try:
            with self._verification_context():
                smoke.verify_linux_signature(self.artifact, self.args)
        finally:
            os.environ["PATH"] = old_path
        self.assertFalse(marker.exists())
        self.assertRegex(self.calls[0][0], r"^/fixture-fd/[0-9]+$")

    def test_version_only_fake_is_rejected_before_execution_when_digest_is_wrong(self) -> None:
        wrong_digest = "0" * 64
        with self._verification_context(expected_digest=wrong_digest):
            with self.assertRaisesRegex(smoke.EvidenceError, "SHA-256"):
                smoke.verify_linux_signature(self.artifact, self.args)
        self.assertEqual(self.calls, [])

    def test_fixed_local_trust_anchor_is_required_and_env_cannot_replace_it(self) -> None:
        missing_anchor = self.root / "arbitrary-user-anchor.pub"
        old = os.environ.get("WINS_LINUX_COSIGN_PUBKEY")
        os.environ["WINS_LINUX_COSIGN_PUBKEY"] = str(self.trust)
        try:
            with self._verification_context():
                with mock.patch.object(smoke, "LINUX_COSIGN_TRUST_ANCHOR", missing_anchor):
                    with self.assertRaisesRegex(smoke.EvidenceError, "existing non-symlink"):
                        smoke.verify_linux_signature(self.artifact, self.args)
        finally:
            if old is None:
                os.environ.pop("WINS_LINUX_COSIGN_PUBKEY", None)
            else:
                os.environ["WINS_LINUX_COSIGN_PUBKEY"] = old

    def test_retired_environment_is_refused_before_any_input_is_opened(self) -> None:
        old = os.environ.get(smoke.RETIRED_LINUX_SIGNER_ENV[0])
        os.environ[smoke.RETIRED_LINUX_SIGNER_ENV[0]] = "retired"
        try:
            with self._verification_context():
                with self.assertRaisesRegex(smoke.EvidenceError, "retired"):
                    smoke.verify_linux_signature(self.artifact, self.args)
        finally:
            if old is None:
                os.environ.pop(smoke.RETIRED_LINUX_SIGNER_ENV[0], None)
            else:
                os.environ[smoke.RETIRED_LINUX_SIGNER_ENV[0]] = old
        self.assertEqual(self.calls, [])

    def test_symlink_and_hardlink_signature_inputs_are_refused(self) -> None:
        for input_name in ("cosign", "trust", "artifact", "bundle"):
            with self.subTest(kind="symlink", input=input_name):
                original = getattr(self, input_name)
                linked = self.root / f"{input_name}.link"
                linked.symlink_to(original)
                with self._verification_context():
                    if input_name == "cosign":
                        patch = mock.patch.object(smoke, "LINUX_COSIGN_PATH", linked)
                    elif input_name == "trust":
                        patch = mock.patch.object(smoke, "LINUX_COSIGN_TRUST_ANCHOR", linked)
                    else:
                        patch = mock.patch.object(self.args, "linux_bundle", str(linked)) if input_name == "bundle" else mock.patch.object(self, "artifact", linked)
                    with patch, self.assertRaises(smoke.EvidenceError):
                        smoke.verify_linux_signature(self.artifact, self.args)
                linked.unlink()

            with self.subTest(kind="hardlink", input=input_name):
                original = getattr(self, input_name)
                linked = self.root / f"{input_name}.hardlink"
                os.link(original, linked)
                with self._verification_context():
                    if input_name == "cosign":
                        patch = mock.patch.object(smoke, "LINUX_COSIGN_PATH", linked)
                    elif input_name == "trust":
                        patch = mock.patch.object(smoke, "LINUX_COSIGN_TRUST_ANCHOR", linked)
                    else:
                        patch = mock.patch.object(self.args, "linux_bundle", str(linked)) if input_name == "bundle" else mock.patch.object(self, "artifact", linked)
                    with patch, self.assertRaises(smoke.EvidenceError):
                        smoke.verify_linux_signature(self.artifact, self.args)
                linked.unlink()

    def test_mutation_during_verification_is_refused(self) -> None:
        def mutate_on_verify(argv, pass_fds, label):
            completed = self._run(argv, pass_fds, label)
            if "verify-blob" in argv:
                self.artifact.write_bytes(b"mutated-after-open")
            return completed

        with self._verification_context():
            with mock.patch.object(smoke, "_run_linux_cosign", mutate_on_verify):
                with self.assertRaisesRegex(smoke.EvidenceError, "changed during verification"):
                    smoke.verify_linux_signature(self.artifact, self.args)


if __name__ == "__main__":
    unittest.main()
