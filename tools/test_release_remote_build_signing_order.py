#!/usr/bin/env python3
"""Tests for the Mac orchestrator's signing order and execution-evidence class.

Two properties, both about tools/release_remote_build.py:

1. Mac signing is the last step. `finish` must call the authenticated worker's
   finish-build, then verify-receipt, and only then touch the cosign key. A
   worker refusal must leave the artifact unsigned, and an artifact whose bytes
   moved between verification and signing must be refused rather than signed.

2. A remote-attested receipt is labelled as the weaker evidence class it is.
   `finish` refuses without an explicit acceptance and writes
   REMOTE_EXECUTION_EVIDENCE.json naming the claims the Mac proved and the
   claims nobody proved, because REMOTE_RUN.json is unsigned self-report.

3. A pinned host key upgrades the class and removes the acceptance fallback, so
   a half-migrated release cannot quietly trust an unsigned run record again.

Run: python3 -B tools/test_release_remote_build_signing_order.py
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import release_remote_build as orchestrator  # noqa: E402
import release_remote_run_record_signature as signatures  # noqa: E402

TOOLCHAIN = {"name": "clang", "version": "14.0.6", "revision": "", "target": "linux-x64"}
SSH_KEYGEN = "/usr/bin/ssh-keygen"
HAVE_KEYGEN = shutil.which(SSH_KEYGEN) is not None


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _worker_record(run_record: pathlib.Path) -> dict[str, object]:
    """What finish-build returns: the receipt record, which binds the
    REMOTE_RUN.json bytes the worker itself read by their digest."""

    return {
        "contract": "winsvpn-build-receipt-v1",
        "remote_attestation": {"run_record": {"sha256": _sha(run_record)}},
    }


class FinishOrderingTests(unittest.TestCase):
    """Signing follows verification, and never precedes a refusal."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        self.run_id = "r1"
        self.run = self.repo / ".artifacts" / "remote-builds" / self.run_id
        self.run.mkdir(parents=True)
        self.index = self.repo / "release-index.json"
        self.index.write_text("{}", encoding="utf-8")
        self.artifact = self.repo / ".artifacts" / "winsvpn-linux.tar.gz"
        self.artifact.write_bytes(b"artifact-bytes")
        self.run_record = self.run / "REMOTE_RUN.json"
        self.run_record.write_text(
            json.dumps(
                {
                    "release": "1.0.16+33",
                    "platform": "linux",
                    "remote_host": "linux",
                    "build_begin_sha256": "00" * 32,
                    "toolchain": TOOLCHAIN,
                    "signing": "orchestrator",
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        self.receipt = self.run / "BUILD_RECEIPT.json"
        self.calls: list[str] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _finish(
        self,
        run_build_step=None,
        verify_build_receipt=None,
        sign_on_mac=None,
        signing_preflight=None,
        **overrides,
    ):
        """Run finish() with the worker, the verifier and the signer stubbed.

        The three stubs are parameters, not outer patches: finish() is called
        inside one patch context here, so a test that patched the same names
        outside would be silently overridden by this one.
        """

        if run_build_step is None:
            def run_build_step(repo, arguments):
                self.calls.append(arguments[0])
                self.receipt.write_text(
                    '{"contract":"winsvpn-build-receipt-v1"}', encoding="utf-8"
                )
                return _worker_record(self.run_record)

        if verify_build_receipt is None:
            def verify_build_receipt(repo, index, platform, receipt, artifact, secret_inventory_path=None):
                self.calls.append("verify-receipt")
                return {
                    "receipt_sha256": _sha(receipt),
                    "artifact_sha256": _sha(pathlib.Path(artifact)),
                }

        if sign_on_mac is None:
            def sign_on_mac(repo, run, artifact, cosign, allow_unpinned_rehearsal_key,
                            *, expected_sha256):
                self.calls.append("sign_on_mac")
                self.assertEqual(expected_sha256, _sha(pathlib.Path(artifact)))
                return {"archive_sha256": _sha(pathlib.Path(artifact))}

        if signing_preflight is None:
            def signing_preflight(repo, allow_unpinned_rehearsal_key):
                self.calls.append("signing-preflight")
                return ("", "", "", "")

        arguments = {
            "repo": self.repo,
            "index": self.index,
            "platform": "linux",
            "remote_host": "linux",
            "run_id": self.run_id,
            "artifact": self.artifact,
            "sign": True,
            "cosign": "/nonexistent/cosign",
            "allow_unpinned_rehearsal_key": True,
            "accept_remote_self_reported_execution": True,
        }
        arguments.update(overrides)
        with mock.patch.object(orchestrator.client, "run_build_step", run_build_step), \
                mock.patch.object(orchestrator.client, "verify_build_receipt", verify_build_receipt), \
                mock.patch.object(orchestrator, "signing_preflight", signing_preflight), \
                mock.patch.object(orchestrator, "sign_on_mac", sign_on_mac):
            return orchestrator.finish(**arguments)

    def _forbidden_signer(self, repo, run, artifact, cosign, allow_unpinned, **_keywords):
        self.calls.append("sign_on_mac")
        raise AssertionError("sign_on_mac must not be reached on this path")

    def test_signing_is_the_last_step(self) -> None:
        result = self._finish()
        self.assertEqual(
            self.calls,
            ["signing-preflight", "finish-build", "verify-receipt", "sign_on_mac"],
            "the cosign key must not be reachable before the worker verified",
        )
        self.assertEqual(result["ok"], True)
        self.assertIsNotNone(result["mac_signing"])

    def test_a_worker_refusal_leaves_the_artifact_unsigned(self) -> None:
        def refuse(repo, arguments):
            self.calls.append(arguments[0])
            raise orchestrator.client.FreezeClientError("dependency-freeze worker refused")

        with self.assertRaises(orchestrator.client.FreezeClientError):
            self._finish(run_build_step=refuse, sign_on_mac=self._forbidden_signer)
        self.assertEqual(self.calls, ["signing-preflight", "finish-build"])

    def test_a_verification_refusal_leaves_the_artifact_unsigned(self) -> None:
        def refuse(repo, index, platform, receipt, artifact, secret_inventory_path=None):
            self.calls.append("verify-receipt")
            raise orchestrator.client.FreezeClientError("verify-receipt refused")

        with self.assertRaises(orchestrator.client.FreezeClientError):
            self._finish(verify_build_receipt=refuse, sign_on_mac=self._forbidden_signer)
        self.assertEqual(
            self.calls, ["signing-preflight", "finish-build", "verify-receipt"]
        )

    def test_an_artifact_substituted_after_verification_is_not_signed(self) -> None:
        real_sha = orchestrator._sha256

        def verify_then_swap(repo, index, platform, receipt, artifact, secret_inventory_path=None):
            self.calls.append("verify-receipt")
            digest = real_sha(pathlib.Path(artifact))
            # The transport, or anything with write access to the run
            # directory, swaps the artifact in the window before signing.
            self.artifact.write_bytes(b"substituted-artifact")
            return {"receipt_sha256": _sha(receipt), "artifact_sha256": digest}

        with self.assertRaisesRegex(
            orchestrator.RemoteBuildError, "changed between receipt verification"
        ):
            self._finish(
                verify_build_receipt=verify_then_swap,
                sign_on_mac=self._forbidden_signer,
            )
        self.assertNotIn("sign_on_mac", self.calls)

    def _real_signer_with_tool(self, tool):
        """Run the real sign_on_mac with its preflight and signing tool stubbed."""

        real_sign_on_mac = orchestrator.sign_on_mac

        def signing_preflight(repo, allow_unpinned_rehearsal_key):
            return ("/k.key", "/k.pub", "f" * 64, "")

        def run(argv, **_keywords):
            return tool(argv)

        def signer(repo, run_directory, artifact, cosign, allow_unpinned, **keywords):
            self.calls.append("sign_on_mac")
            with mock.patch.object(orchestrator, "signing_preflight", signing_preflight), \
                    mock.patch.object(orchestrator.subprocess, "run", run):
                return real_sign_on_mac(
                    repo, run_directory, artifact, cosign, allow_unpinned, **keywords
                )

        return signer

    def test_cosign_signs_the_verified_bytes_even_if_the_artifact_moves(self) -> None:
        # R23 W1-08: cosign read the artifact by path after the re-hash, so a
        # writer racing the key got its own bytes signed. The signing tool
        # now sees a private snapshot of the verified bytes.
        verified = _sha(self.artifact)
        seen: dict[str, object] = {}

        def tool(argv):
            archive = pathlib.Path(argv[argv.index("--archive") + 1])
            self.artifact.write_bytes(b"substituted-while-signing")
            seen["archive"] = archive
            seen["signed_sha256"] = _sha(archive)
            pathlib.Path(argv[argv.index("--bundle") + 1]).write_text(
                "{}", encoding="utf-8"
            )
            return subprocess.CompletedProcess(argv, 0)

        result = self._finish(sign_on_mac=self._real_signer_with_tool(tool))
        self.assertNotEqual(seen["archive"], self.artifact)
        self.assertEqual(seen["signed_sha256"], verified)
        self.assertEqual(result["mac_signing"]["archive_sha256"], verified)
        self.assertFalse(pathlib.Path(seen["archive"]).exists())
        self.assertEqual(
            [entry.name for entry in self.run.iterdir() if entry.name.startswith(".mac-signing-")],
            [],
        )

    def test_an_artifact_swapped_before_the_snapshot_never_reaches_the_tool(self) -> None:
        calls: list[list[str]] = []

        def tool(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0)

        signer = self._real_signer_with_tool(tool)

        def swapping_signer(repo, run_directory, artifact, cosign, allow_unpinned, **keywords):
            self.artifact.write_bytes(b"substituted-before-snapshot")
            return signer(repo, run_directory, artifact, cosign, allow_unpinned, **keywords)

        with self.assertRaisesRegex(
            orchestrator.RemoteBuildError, "changed between receipt verification"
        ):
            self._finish(sign_on_mac=swapping_signer)
        self.assertEqual(calls, [])

    def test_a_run_that_did_not_defer_signing_never_reaches_the_key(self) -> None:
        self.run_record.write_text(
            json.dumps(
                {
                    "release": "1.0.16+33",
                    "platform": "linux",
                    "remote_host": "linux",
                    "build_begin_sha256": "00" * 32,
                    "toolchain": TOOLCHAIN,
                    "signing": "unsigned",
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        result = self._finish(sign=False, sign_on_mac=self._forbidden_signer)
        self.assertEqual(self.calls, ["finish-build", "verify-receipt"])
        self.assertIsNone(result["mac_signing"])

    def test_signing_misconfiguration_refuses_before_the_attempt_is_spent(self) -> None:
        # The real preflight, not a stub: with no key paths in the
        # environment finish must refuse before finish-build consumes the
        # single-use attempt, so no receipt exists for an unsignable archive.
        with mock.patch.dict(orchestrator.os.environ, clear=False) as environment:
            environment.pop("WINS_LINUX_COSIGN_KEY", None)
            environment.pop("WINS_LINUX_COSIGN_PUBKEY", None)
            with self.assertRaisesRegex(
                orchestrator.RemoteBuildError, "absolute WINS_LINUX_COSIGN_KEY"
            ):
                self._finish(
                    signing_preflight=orchestrator.signing_preflight,
                    sign_on_mac=self._forbidden_signer,
                )
        self.assertEqual(self.calls, [], "finish-build must not run")
        self.assertFalse(self.receipt.exists())

    def test_signing_preflight_reads_no_private_key(self) -> None:
        public = self.repo / "cosign.pub"
        public.write_bytes(b"public key bytes\n")
        producer = self.repo / "tools" / "build_linux_release.sh"
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text(
            f'LINUX_COSIGN_PUBLIC_KEY_SHA256="{_sha(public)}"\n', encoding="utf-8"
        )
        private = self.repo / "absent-private.key"
        with mock.patch.dict(
            orchestrator.os.environ,
            {
                "WINS_LINUX_COSIGN_KEY": str(private),
                "WINS_LINUX_COSIGN_PUBKEY": str(public),
            },
        ):
            self.assertEqual(
                orchestrator.signing_preflight(self.repo, False),
                (str(private), str(public), _sha(public), _sha(public)),
            )
            producer.write_text(
                f'LINUX_COSIGN_PUBLIC_KEY_SHA256="{"0" * 64}"\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                orchestrator.RemoteBuildError, "is not LINUX_COSIGN_PUBLIC_KEY_SHA256"
            ):
                orchestrator.signing_preflight(self.repo, False)
        self.assertFalse(private.exists())


class ExecutionEvidenceClassTests(unittest.TestCase):
    """The weaker evidence class is stated, and accepting it is explicit."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        self.run = self.repo / ".artifacts" / "remote-builds" / "r1"
        self.run.mkdir(parents=True)
        self.index = self.repo / "release-index.json"
        self.index.write_text("{}", encoding="utf-8")
        self.artifact = self.repo / ".artifacts" / "a.tar.gz"
        self.artifact.write_bytes(b"artifact")
        (self.run / "REMOTE_RUN.json").write_text(
            json.dumps(
                {
                    "release": "1.0.16+33",
                    "platform": "linux",
                    "remote_host": "linux",
                    "build_begin_sha256": "00" * 32,
                    "toolchain": TOOLCHAIN,
                    "signing": "unsigned",
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        self.receipt = self.run / "BUILD_RECEIPT.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build_step(self, repo, arguments):
        self.receipt.write_text("{}", encoding="utf-8")
        return _worker_record(self.run / "REMOTE_RUN.json")

    def _stubs(self):
        return (
            mock.patch.object(
                orchestrator.client,
                "run_build_step",
                self._build_step,
            ),
            mock.patch.object(
                orchestrator.client,
                "verify_build_receipt",
                lambda repo, index, platform, receipt, artifact, secret_inventory_path=None: {
                    "receipt_sha256": _sha(receipt),
                    "artifact_sha256": _sha(pathlib.Path(artifact)),
                },
            ),
        )

    def test_finish_refuses_without_explicit_acceptance(self) -> None:
        build_step, verify = self._stubs()
        with build_step, verify, mock.patch.object(
            orchestrator, "sign_on_mac", lambda *a, **k: None
        ):
            with self.assertRaisesRegex(
                orchestrator.RemoteBuildError, "proves no remote execution"
            ):
                orchestrator.finish(
                    self.repo, self.index, "linux", "linux", "r1", self.artifact
                )
        self.assertFalse(self.receipt.exists(), "no receipt may be written before acceptance")

    def test_acceptance_records_what_was_and_was_not_proven(self) -> None:
        build_step, verify = self._stubs()
        with build_step, verify:
            result = orchestrator.finish(
                self.repo,
                self.index,
                "linux",
                "linux",
                "r1",
                self.artifact,
                accept_remote_self_reported_execution=True,
            )
        evidence_path = self.repo / result["execution_evidence"]["path"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(
            evidence["contract"], orchestrator.EXECUTION_EVIDENCE_CONTRACT
        )
        self.assertEqual(
            evidence["execution_evidence_class"],
            orchestrator.EXECUTION_EVIDENCE_CLASS_SELF_REPORTED,
        )
        self.assertEqual(
            evidence["remote_run_record"]["signed_by_remote_host"],
            False,
            "the run record is unsigned self-report and must not be recorded otherwise",
        )
        self.assertEqual(evidence["artifact"]["sha256"], _sha(self.artifact))
        self.assertEqual(evidence["receipt"]["sha256"], _sha(self.receipt))
        self.assertEqual(
            evidence["not_proven"], list(orchestrator.EXECUTION_NOT_PROVEN)
        )
        self.assertIn(
            "the reviewed producer script executed on the named remote host",
            evidence["not_proven"],
        )
        self.assertEqual(evidence["mac_signing_planned"], False)
        self.assertEqual(
            result["execution_evidence"]["sha256"], _sha(evidence_path)
        )
        self.assertEqual(
            pathlib.Path(evidence_path).stat().st_mode & 0o077,
            0,
            "the evidence record must not be group or world readable",
        )

    def test_a_dangling_trust_link_is_not_an_absent_trust_file(self) -> None:
        trust = self.repo / "tools" / "release_remote_host_keys.trust.json"
        trust.parent.mkdir(parents=True, exist_ok=True)
        trust.symlink_to(self.repo / "no-such-trust.json")
        build_step, verify = self._stubs()
        with build_step, verify:
            with self.assertRaisesRegex(
                orchestrator.RemoteBuildError, "regular non-symlink"
            ):
                orchestrator.finish(
                    self.repo,
                    self.index,
                    "linux",
                    "linux",
                    "r1",
                    self.artifact,
                    accept_remote_self_reported_execution=True,
                )
        self.assertFalse(self.receipt.exists(), "no receipt may be written")

    def test_a_run_record_swapped_before_the_worker_is_refused(self) -> None:
        run_record = self.run / "REMOTE_RUN.json"

        def swap_then_build(repo, arguments):
            # Anything that can write the run directory replaces the record
            # after finish read it; the worker then binds the replacement.
            body = json.loads(run_record.read_text(encoding="utf-8"))
            body["release"] = "9.9.99+1"
            run_record.write_text(json.dumps(body, sort_keys=True), encoding="utf-8")
            return self._build_step(repo, arguments)

        build_step, verify = self._stubs()
        with build_step, verify, mock.patch.object(
            orchestrator.client, "run_build_step", swap_then_build
        ):
            with self.assertRaisesRegex(
                orchestrator.RemoteBuildError, "other than the one this finish verified"
            ):
                orchestrator.finish(
                    self.repo,
                    self.index,
                    "linux",
                    "linux",
                    "r1",
                    self.artifact,
                    accept_remote_self_reported_execution=True,
                )
        self.assertFalse((self.run / "REMOTE_EXECUTION_EVIDENCE.json").exists())

    def test_the_evidence_record_is_written_once(self) -> None:
        build_step, verify = self._stubs()
        with build_step, verify:
            orchestrator.finish(
                self.repo,
                self.index,
                "linux",
                "linux",
                "r1",
                self.artifact,
                accept_remote_self_reported_execution=True,
            )
            with self.assertRaises(FileExistsError):
                orchestrator.finish(
                    self.repo,
                    self.index,
                    "linux",
                    "linux",
                    "r1",
                    self.artifact,
                    accept_remote_self_reported_execution=True,
                )


class CommandLineSurfaceTests(unittest.TestCase):
    def test_finish_exposes_the_acceptance_flag(self) -> None:
        source = (ROOT / "tools/release_remote_build.py").read_text(encoding="utf-8")
        self.assertIn("--accept-remote-self-reported-execution", source)
        self.assertEqual(
            source.count("args.accept_remote_self_reported_execution"),
            1,
            "the flag must reach finish() exactly once",
        )

    def test_no_signing_call_precedes_the_worker_in_finish(self) -> None:
        source = (ROOT / "tools/release_remote_build.py").read_text(encoding="utf-8")
        body = source.split("def finish(", 1)[1].split("\ndef main(", 1)[0]
        self.assertLess(
            body.index('client.run_build_step'),
            body.index('sign_on_mac(repo, run, artifact'),
            "sign_on_mac must appear after the worker call inside finish()",
        )
        self.assertLess(
            body.index('client.verify_build_receipt'),
            body.index('sign_on_mac(repo, run, artifact'),
            "sign_on_mac must appear after verify_build_receipt inside finish()",
        )


@unittest.skipUnless(HAVE_KEYGEN, "ssh-keygen is unavailable")
class HostKeyUpgradeTests(unittest.TestCase):
    """A pinned host key upgrades the class and removes the acceptance fallback."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temporary.name).resolve()
        self.repo = self.base / "repo"
        self.run = self.repo / ".artifacts" / "remote-builds" / "r1"
        self.run.mkdir(parents=True)
        self.index = self.repo / "release-index.json"
        self.index.write_text("{}", encoding="utf-8")
        self.artifact = self.repo / ".artifacts" / "a.tar.gz"
        self.artifact.write_bytes(b"artifact")
        self.run_record = self.run / "REMOTE_RUN.json"
        self.run_record.write_text(
            json.dumps(
                {
                    "release": "1.0.16+33",
                    "platform": "linux",
                    "remote_host": "linux",
                    "build_begin_sha256": "00" * 32,
                    "toolchain": TOOLCHAIN,
                    "signing": "unsigned",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.receipt = self.run / "BUILD_RECEIPT.json"
        self.key = self.base / "host_ed25519"
        subprocess.run(
            [SSH_KEYGEN, "-t", "ed25519", "-N", "", "-f", str(self.key), "-q"],
            check=True,
            capture_output=True,
        )
        public_key = " ".join(
            self.key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2]
        )
        trust = self.repo / signatures.TRUST_RELATIVE_PATH
        trust.parent.mkdir(parents=True, exist_ok=True)
        trust.write_text(
            json.dumps(
                {
                    "contract": signatures.TRUST_CONTRACT,
                    "hosts": {
                        "linux": {
                            "principal": "winsvpn-builder@aicore",
                            "public_key": public_key,
                            "public_key_sha256": hashlib.sha256(
                                public_key.encode("utf-8")
                            ).hexdigest(),
                            "host_key_path": "/etc/ssh/ssh_host_ed25519_key",
                        }
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build_step(self, repo, arguments):
        self.receipt.write_text("{}", encoding="utf-8")
        return _worker_record(self.run / "REMOTE_RUN.json")

    def _stubs(self):
        return (
            mock.patch.object(
                orchestrator.client,
                "run_build_step",
                self._build_step,
            ),
            mock.patch.object(
                orchestrator.client,
                "verify_build_receipt",
                lambda repo, index, platform, receipt, artifact, secret_inventory_path=None: {
                    "receipt_sha256": _sha(receipt),
                    "artifact_sha256": _sha(pathlib.Path(artifact)),
                },
            ),
        )

    def _sign_run_record(self) -> None:
        completed = subprocess.run(
            signatures.remote_sign_command(str(self.key), str(self.run_record)),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_a_host_signed_run_record_needs_no_acceptance_flag(self) -> None:
        self._sign_run_record()
        build_step, verify = self._stubs()
        with build_step, verify:
            result = orchestrator.finish(
                self.repo, self.index, "linux", "linux", "r1", self.artifact
            )
        evidence = json.loads(
            (self.repo / result["execution_evidence"]["path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(
            evidence["execution_evidence_class"],
            orchestrator.EXECUTION_EVIDENCE_CLASS_HOST_SIGNED,
        )
        self.assertEqual(evidence["remote_run_record"]["signed_by_remote_host"], True)
        self.assertEqual(
            evidence["remote_run_record"]["host_key_proof"]["principal"],
            "winsvpn-builder@aicore",
        )
        self.assertEqual(
            evidence["not_proven"],
            list(orchestrator.EXECUTION_NOT_PROVEN_HOST_SIGNED),
        )
        self.assertNotIn(
            "the remote host, and not the transport, wrote REMOTE_RUN.json",
            evidence["not_proven"],
            "a host key signature does prove this one claim",
        )
        self.assertIn(
            "the reviewed producer script executed on the named remote host",
            evidence["not_proven"],
            "a host key signature still does not prove the producer ran",
        )

    def test_a_signed_run_record_swapped_before_the_worker_is_refused(self) -> None:
        self._sign_run_record()

        def swap_then_build(repo, arguments):
            # The signature was verified over the held bytes; the record the
            # worker now reads is an unsigned replacement.
            body = json.loads(self.run_record.read_text(encoding="utf-8"))
            body["artifact"] = {"name": "a.tar.gz", "size_bytes": 9, "sha256": "ff" * 32}
            self.run_record.write_text(
                json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return self._build_step(repo, arguments)

        build_step, verify = self._stubs()
        with build_step, verify, mock.patch.object(
            orchestrator.client, "run_build_step", swap_then_build
        ):
            with self.assertRaisesRegex(
                orchestrator.RemoteBuildError, "other than the one this finish verified"
            ):
                orchestrator.finish(
                    self.repo, self.index, "linux", "linux", "r1", self.artifact
                )
        self.assertFalse(
            (self.run / "REMOTE_EXECUTION_EVIDENCE.json").exists(),
            "no host-signed evidence may describe a record the signature never covered",
        )

    def test_a_pinned_host_without_a_signature_cannot_fall_back(self) -> None:
        build_step, verify = self._stubs()
        with build_step, verify:
            with self.assertRaisesRegex(
                orchestrator.RemoteBuildError, "signature is not valid|unreadable"
            ):
                orchestrator.finish(
                    self.repo,
                    self.index,
                    "linux",
                    "linux",
                    "r1",
                    self.artifact,
                    accept_remote_self_reported_execution=True,
                )
        self.assertFalse(self.receipt.exists(), "no receipt may be written for an unsigned run record")

    def test_a_substituted_artifact_breaks_the_host_signature_too(self) -> None:
        self._sign_run_record()
        body = json.loads(self.run_record.read_text(encoding="utf-8"))
        body["artifact"] = {"name": "a.tar.gz", "size_bytes": 9, "sha256": "ff" * 32}
        self.run_record.write_text(
            json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        build_step, verify = self._stubs()
        with build_step, verify:
            with self.assertRaisesRegex(
                orchestrator.RemoteBuildError, "signature is not valid"
            ):
                orchestrator.finish(
                    self.repo, self.index, "linux", "linux", "r1", self.artifact
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
