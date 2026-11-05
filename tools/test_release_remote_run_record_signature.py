#!/usr/bin/env python3
"""Tests for the host-key signature over REMOTE_RUN.json.

Generates an ephemeral ed25519 key per test, signs a fixture run record with
the real /usr/bin/ssh-keygen, and asserts the Mac-side verifier accepts the
pinned key and refuses a tampered record, a wrong key, a wrong principal, a
wrong namespace, a missing signature and a malformed trust file.

The remote half of the protocol (root signing with /etc/ssh/ssh_host_ed25519_key
on aione, aicore and lenovo) is NOT exercised here: this lane has no remote
host. What is exercised is the exact signature format and the exact verifier.

Run: python3 -B tools/test_release_remote_run_record_signature.py
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import release_remote_run_record_signature as signatures  # noqa: E402

SSH_KEYGEN = "/usr/bin/ssh-keygen"
HAVE_KEYGEN = shutil.which(SSH_KEYGEN) is not None


def _public_key_line(private_key: pathlib.Path) -> str:
    return " ".join(
        private_key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2]
    )


def _write_trust(repo: pathlib.Path, hosts: dict[str, dict[str, str]]) -> pathlib.Path:
    trust = repo / signatures.TRUST_RELATIVE_PATH
    trust.parent.mkdir(parents=True, exist_ok=True)
    trust.write_text(
        json.dumps({"contract": signatures.TRUST_CONTRACT, "hosts": hosts}, indent=2),
        encoding="utf-8",
    )
    return trust


@unittest.skipUnless(HAVE_KEYGEN, "ssh-keygen is unavailable")
class HostKeySignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temporary.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.key = self.base / "host_ed25519"
        subprocess.run(
            [SSH_KEYGEN, "-t", "ed25519", "-N", "", "-f", str(self.key), "-q"],
            check=True,
            capture_output=True,
        )
        self.public_key = _public_key_line(self.key)
        self.run_record = self.base / "REMOTE_RUN.json"
        self.record_body = {"contract": "winsvpn-remote-producer-run-v1", "release": "1.0.16+33"}
        self.run_record.write_text(
            json.dumps(self.record_body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.principal = "winsvpn-builder@aicore"
        _write_trust(
            self.repo,
            {
                "linux": {
                    "principal": self.principal,
                    "public_key": self.public_key,
                    "public_key_sha256": hashlib.sha256(
                        self.public_key.encode("utf-8")
                    ).hexdigest(),
                    "host_key_path": "/etc/ssh/ssh_host_ed25519_key",
                }
            },
        )
        self.trust = signatures.load_host_key_trust(self.repo)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _sign(self, namespace: str | None = None, key: pathlib.Path | None = None) -> None:
        command = signatures.remote_sign_command(
            str(key or self.key), str(self.run_record)
        )
        if namespace is not None:
            command[command.index("-n") + 1] = namespace
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_the_documented_sign_command_produces_a_verifiable_signature(self) -> None:
        self.assertEqual(
            signatures.remote_sign_command("/etc/ssh/ssh_host_ed25519_key", "REMOTE_RUN.json"),
            [
                SSH_KEYGEN, "-Y", "sign",
                "-f", "/etc/ssh/ssh_host_ed25519_key",
                "-n", "winsvpn-remote-run-v1",
                "REMOTE_RUN.json",
            ],
        )
        self._sign()
        verified = signatures.verify_run_record_signature(
            self.run_record, self.trust, "linux"
        )
        self.assertEqual(verified["principal"], self.principal)
        self.assertEqual(verified["namespace"], signatures.SIGNATURE_NAMESPACE)
        self.assertTrue(verified["key_fingerprint"].startswith("SHA256:"))
        self.assertEqual(
            verified["public_key_sha256"],
            hashlib.sha256(self.public_key.encode("utf-8")).hexdigest(),
        )

    def test_a_tampered_run_record_is_refused(self) -> None:
        self._sign()
        tampered = dict(self.record_body)
        tampered["release"] = "9.9.99+1"
        self.run_record.write_text(
            json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            signatures.RemoteRunRecordSignatureError, "not valid"
        ):
            signatures.verify_run_record_signature(self.run_record, self.trust, "linux")

    def test_a_different_host_key_is_refused(self) -> None:
        other = self.base / "other_ed25519"
        subprocess.run(
            [SSH_KEYGEN, "-t", "ed25519", "-N", "", "-f", str(other), "-q"],
            check=True,
            capture_output=True,
        )
        self._sign(key=other)
        with self.assertRaises(signatures.RemoteRunRecordSignatureError):
            signatures.verify_run_record_signature(self.run_record, self.trust, "linux")

    def test_a_wrong_namespace_is_refused(self) -> None:
        self._sign(namespace="some-other-namespace")
        with self.assertRaises(signatures.RemoteRunRecordSignatureError):
            signatures.verify_run_record_signature(self.run_record, self.trust, "linux")

    def test_a_missing_signature_is_refused(self) -> None:
        with self.assertRaisesRegex(
            signatures.RemoteRunRecordSignatureError, "unreadable"
        ):
            signatures.verify_run_record_signature(self.run_record, self.trust, "linux")

    def test_an_unpinned_host_is_refused(self) -> None:
        self._sign()
        with self.assertRaisesRegex(
            signatures.RemoteRunRecordSignatureError, "no pinned host key"
        ):
            signatures.verify_run_record_signature(self.run_record, self.trust, "windows")

    def test_a_symlinked_signature_is_refused(self) -> None:
        self._sign()
        signature = self.run_record.with_name(self.run_record.name + ".sig")
        target = self.base / "real.sig"
        shutil.move(str(signature), str(target))
        signature.symlink_to(target)
        with self.assertRaisesRegex(
            signatures.RemoteRunRecordSignatureError, "regular non-symlink"
        ):
            signatures.verify_run_record_signature(self.run_record, self.trust, "linux")

    def test_ssh_keygen_receives_the_bytes_that_were_bound_checked(self) -> None:
        self._sign()
        signature = self.run_record.with_name(self.run_record.name + ".sig")
        expected = signature.read_bytes()
        seen_bytes = self.base / "seen.sig"
        seen_path = self.base / "seen-path.txt"
        fake = self.base / "fake-ssh-keygen"
        fake.write_text(
            "#!/bin/sh\n"
            f"/bin/cp \"${{10}}\" '{seen_bytes}'\n"
            f"printf '%s' \"${{10}}\" > '{seen_path}'\n"
            f"printf 'Good \"{signatures.SIGNATURE_NAMESPACE}\" signature for "
            f"{self.principal} with ED25519 key SHA256:{'A' * 43}\\n'\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        verified = signatures.verify_run_record_signature(
            self.run_record, self.trust, "linux", ssh_keygen=str(fake)
        )
        self.assertEqual(verified["principal"], self.principal)
        self.assertEqual(seen_bytes.read_bytes(), expected)
        self.assertNotEqual(
            seen_path.read_text(encoding="utf-8"),
            str(signature),
            "ssh-keygen must get a private copy, not the run directory's .sig path",
        )

    def test_a_failed_second_temporary_file_is_a_refusal_and_leaves_nothing(self) -> None:
        # R23 F-W1-05: both temporary files were created before the try, so a
        # failure creating the second leaked the first and escaped as OSError.
        self._sign()
        created: list[str] = []
        real_mkstemp = signatures.tempfile.mkstemp

        def failing_second(*args, **kwargs):
            if created:
                raise OSError(28, "No space left on device")
            descriptor, name = real_mkstemp(*args, **kwargs)
            created.append(name)
            return descriptor, name

        with mock.patch.object(signatures.tempfile, "mkstemp", failing_second):
            with self.assertRaisesRegex(
                signatures.RemoteRunRecordSignatureError, "did not run"
            ):
                signatures.verify_run_record_signature(self.run_record, self.trust, "linux")
        self.assertEqual(len(created), 1)
        self.assertFalse(os.path.lexists(created[0]))

    def test_a_file_swapped_between_its_checks_and_its_read_is_refused(self) -> None:
        self._sign()
        signature = self.run_record.with_name(self.run_record.name + ".sig")
        oversized = self.base / "oversized.sig"
        oversized.write_bytes(b"A" * (signatures.MAX_SIGNATURE_BYTES + 1))
        real_open = signatures.os.open
        swapped = []

        def swap_then_open(path, flags, *args, **kwargs):
            if os.fspath(path) == os.fspath(signature) and not swapped:
                # The lstat already passed; a writer replaces the file before
                # the open, as a racing copy into the run directory would.
                os.replace(oversized, signature)
                swapped.append(True)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(signatures.os, "open", swap_then_open):
            with self.assertRaisesRegex(
                signatures.RemoteRunRecordSignatureError, "changed while it was opened"
            ):
                signatures.verify_run_record_signature(
                    self.run_record, self.trust, "linux"
                )
        self.assertEqual(swapped, [True])

    def test_held_record_bytes_are_the_bytes_verified(self) -> None:
        self._sign()
        held = signatures.read_run_record(self.run_record)
        tampered = dict(self.record_body)
        tampered["release"] = "9.9.99+1"
        self.run_record.write_text(
            json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        verified = signatures.verify_run_record_signature(
            self.run_record, self.trust, "linux", record_bytes=held
        )
        self.assertEqual(verified["principal"], self.principal)
        with self.assertRaisesRegex(
            signatures.RemoteRunRecordSignatureError, "not valid"
        ):
            signatures.verify_run_record_signature(
                self.run_record, self.trust, "linux"
            )

    def test_malformed_trust_is_refused(self) -> None:
        good = self.trust
        for mutate in (
            lambda entry: entry.update(principal="../escape"),
            lambda entry: entry.update(public_key="not-a-key AAAA"),
            lambda entry: entry.update(public_key_sha256="0" * 63),
            lambda entry: entry.update(host_key_path="/home/user/id_ed25519"),
            # R24 V2 F-16: under /etc/ssh by prefix only.
            lambda entry: entry.update(host_key_path="/etc/ssh/../../home/builder/id_ed25519"),
            lambda entry: entry.update(host_key_path="/etc/ssh/./ssh_host_ed25519_key"),
            lambda entry: entry.update(host_key_path="/etc/ssh//ssh_host_ed25519_key"),
            lambda entry: entry.pop("principal"),
        ):
            with self.subTest(mutator=mutate):
                hosts = {
                    "linux": {
                        "principal": self.principal,
                        "public_key": self.public_key,
                        "public_key_sha256": hashlib.sha256(
                            self.public_key.encode("utf-8")
                        ).hexdigest(),
                        "host_key_path": "/etc/ssh/ssh_host_ed25519_key",
                    }
                }
                mutate(hosts["linux"])
                _write_trust(self.repo, hosts)
                with self.assertRaises(signatures.RemoteRunRecordSignatureError):
                    signatures.load_host_key_trust(self.repo)
        self.assertEqual(len(good), 1)

    def test_a_digest_mismatch_in_trust_is_refused(self) -> None:
        _write_trust(
            self.repo,
            {
                "linux": {
                    "principal": self.principal,
                    "public_key": self.public_key,
                    "public_key_sha256": "a" * 64,
                    "host_key_path": "/etc/ssh/ssh_host_ed25519_key",
                }
            },
        )
        with self.assertRaisesRegex(
            signatures.RemoteRunRecordSignatureError, "does not match its digest"
        ):
            signatures.load_host_key_trust(self.repo)


if __name__ == "__main__":
    unittest.main(verbosity=2)
