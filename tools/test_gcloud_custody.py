#!/usr/bin/env python3

from __future__ import annotations

import gzip
import hashlib
import copy
import fcntl
import inspect
import io
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import gcloud_custody as custody
import create_gcloud_custody_receipt as producer


REAL_PINS = Path(__file__).with_name("toolchain-pins.json")
ACCOUNT = "proof@winsproof123.iam.gserviceaccount.com"
PROJECT = "winsproof123"
OTHER_ACCOUNT = "other@winsproof123.iam.gserviceaccount.com"
FAKE_PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "TEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL\n"
    "-----END PRIVATE KEY-----\n"
)
GCLOUD_SCRIPT = """#!/bin/sh
if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]; then
  printf 'HAS_GOOGLE_APPLICATION_CREDENTIALS\\n'
fi
if [ -n "${PYTHONPATH:-}" ]; then
  printf 'HAS_PYTHONPATH\\n'
fi
case "${CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE:-}" in
  *attacker-sentinel*) printf 'HAS_AMBIENT_OVERRIDE\\n' ;;
esac
if [ -f "${HOME}/.config/gcloud/application_default_credentials.json" ]; then
  printf 'HAS_AMBIENT_HOME_CREDENTIAL\\n'
fi
support="${CLOUDSDK_ROOT_DIR:-.}/lib/support.txt"
if [ -f "$support" ]; then
  cat "$support"
fi
printf 'REVIEWED\\n'
"""
PIPE_PAYLOAD = b"fixture-pipe-payload-v1\n"
PIPE_SECRET = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"TEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL\n"
    b"-----END PRIVATE KEY-----\n"
)
PIPE_PRODUCER_OK = """#!/usr/bin/env python3
import sys
sys.stdout.buffer.write(b"fixture-pipe-payload-v1\\n")
sys.stdout.buffer.flush()
"""
PIPE_CONSUMER_HASH = """#!/usr/bin/env python3
import hashlib
import json
import sys
payload = sys.stdin.buffer.read()
digest = hashlib.sha256(payload).hexdigest()
body = json.dumps(
    {
        "contract": "winsvpn-gcloud-ssh-pipe-response-v1",
        "payload_sha256": digest,
        "schema_version": 1,
        "status": "ok",
    },
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
)
sys.stdout.buffer.write(body.encode("ascii") + b"\\n")
"""
PIPE_CONSUMER_FDS = """#!/usr/bin/env python3
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
payload = sys.stdin.buffer.read()
digest = hashlib.sha256(payload).hexdigest()
extra = []
for fd in range(3, 64):
    try:
        fcntl.fcntl(fd, fcntl.F_GETFD)
    except OSError:
        continue
    extra.append(str(fd))
Path(os.environ["TMPDIR"], "inherited-fds").write_text(",".join(extra), encoding="ascii")
body = json.dumps(
    {
        "contract": "winsvpn-gcloud-ssh-pipe-response-v1",
        "payload_sha256": digest,
        "schema_version": 1,
        "status": "ok",
    },
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
)
sys.stdout.buffer.write(body.encode("ascii") + b"\\n")
"""
PIPE_PRODUCER_FAIL = """#!/usr/bin/env python3
import sys
sys.stdout.buffer.write(
    b"-----BEGIN PRIVATE KEY-----\\nTEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL\\n-----END PRIVATE KEY-----\\n"
)
sys.stdout.buffer.flush()
sys.exit(3)
"""
PIPE_CONSUMER_REFUSE = """#!/usr/bin/env python3
import sys
sys.exit(9)
"""
PIPE_PRODUCER_SLEEP = """#!/usr/bin/env python3
import time
time.sleep(30)
"""
PIPE_CONSUMER_SLEEP = """#!/usr/bin/env python3
import sys
import time
time.sleep(30)
sys.stdin.buffer.read()
"""
PIPE_CONSUMER_SHORT = """#!/usr/bin/env python3
import sys
sys.stdin.buffer.read(1)
sys.exit(0)
"""
PIPE_PRODUCER_BULK = """#!/usr/bin/env python3
import sys
try:
    sys.stdout.buffer.write(b"X" * (4 * 1024 * 1024))
    sys.stdout.buffer.flush()
except (BrokenPipeError, OSError):
    sys.exit(1)
sys.exit(0)
"""
PIPE_CONSUMER_SECRET = """#!/usr/bin/env python3
import sys
sys.stdin.buffer.read()
sys.stdout.buffer.write(
    b"-----BEGIN PRIVATE KEY-----\\nTEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL\\n-----END PRIVATE KEY-----\\n"
)
"""
PIPE_PRODUCER_STDERR_SECRET = """#!/usr/bin/env python3
import sys
sys.stderr.buffer.write(
    b"-----BEGIN PRIVATE KEY-----\\nTEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL\\n-----END PRIVATE KEY-----\\n"
)
sys.stdout.buffer.write(b"fixture-pipe-payload-v1\\n")
sys.stdout.buffer.flush()
"""
PIPE_OPAQUE_SECRET = b"opaque-fixture-secret-token-9f3c2a1b7e4d"
PIPE_CONSUMER_OPAQUE = """#!/usr/bin/env python3
import sys
sys.stdin.buffer.read()
sys.stdout.buffer.write(b"opaque-fixture-secret-token-9f3c2a1b7e4d")
"""
PIPE_CONSUMER_OVERSIZE = """#!/usr/bin/env python3
import sys
limit = __WINSVPN_PIPE_OVERSIZE__
sys.stdin.buffer.read()
sys.stdout.buffer.write(b"X" * (limit + 1))
sys.stdout.buffer.flush()
"""
PIPE_CONSUMER_PARTIAL_JSON = """#!/usr/bin/env python3
import sys
sys.stdin.buffer.read()
sys.stdout.buffer.write(b'{"contract":"winsvpn-gcloud-ssh-pipe-response-v1"')
"""
PIPE_CONSUMER_STDERR_NOISE = """#!/usr/bin/env python3
import hashlib
import json
import sys
payload = sys.stdin.buffer.read()
digest = hashlib.sha256(payload).hexdigest()
body = json.dumps(
    {
        "contract": "winsvpn-gcloud-ssh-pipe-response-v1",
        "payload_sha256": digest,
        "schema_version": 1,
        "status": "ok",
    },
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
)
sys.stderr.buffer.write(b"unexpected-consumer-stderr\\n")
sys.stdout.buffer.write(body.encode("ascii") + b"\\n")
"""


class GcloudCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "google-cloud-sdk"
        (self.root / "bin").mkdir(parents=True)
        (self.root / "lib").mkdir()
        self.executable = self.root / "bin" / "gcloud"
        self.executable.write_text(GCLOUD_SCRIPT, encoding="ascii")
        self.executable.chmod(0o755)
        (self.root / "lib" / "support.txt").write_text("SUPPORT_OK\n", encoding="ascii")
        (self.root / "lib.txt").write_text("reviewed\n", encoding="ascii")
        self.platform_key = custody.current_platform_key()
        real = custody.parse_google_cloud_cli_pin_document(REAL_PINS.read_bytes())
        self.pin = {
            "version": real["version"],
            "archive_sha256": dict(real["archive_sha256"]),
            "archive_name": dict(real["archive_name"]),
            "note": real["note"],
        }
        self.pin_path = Path(self.temporary.name) / "pins.json"
        self.archive_source = Path(self.temporary.name) / "archive-source" / "google-cloud-sdk"
        self.archive_source.parent.mkdir()
        shutil.copytree(self.root, self.archive_source, symlinks=True)
        self.archive = Path(self.temporary.name) / self.pin["archive_name"][self.platform_key]
        self.make_archive(self.archive_source, self.archive)
        self.archive_data = self.archive.read_bytes()
        self.pin["archive_sha256"][self.platform_key] = hashlib.sha256(self.archive_data).hexdigest()
        self.write_pin()
        producer.create_test_only(self.archive, self.root, self.pin_path)
        self.good_credential = self.write_credential(
            "good-sa.json",
            self.service_account_payload(ACCOUNT, PROJECT),
        )
        self.workload_credential = self.write_credential(
            "good-wif.json",
            self.workload_identity_payload(ACCOUNT),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_pin(self, *, raw: bytes | None = None) -> None:
        python_path = Path(sys.executable).resolve(strict=True)
        python_pin = {
            "version": platform.python_version(),
            "implementation": "cpython",
            "reviewed_executable_path": {self.platform_key: str(python_path)},
            "executable_sha256": {
                self.platform_key: hashlib.sha256(python_path.read_bytes()).hexdigest()
            },
        }
        data = raw if raw is not None else json.dumps(
            {"tools": {"google_cloud_cli": self.pin, "python": python_pin}}
        ).encode()
        self.pin_path.write_bytes(data)

    def make_archive(self, source: Path, destination: Path) -> None:
        if destination.name.endswith(".zip"):
            import zipfile

            with zipfile.ZipFile(destination, "w") as bundle:
                for path in sorted(source.rglob("*")):
                    if path.is_file():
                        bundle.write(path, Path("google-cloud-sdk") / path.relative_to(source))
        else:
            with tarfile.open(destination, "w:gz") as bundle:
                bundle.add(source, arcname="google-cloud-sdk")

    def write_receipt(self, root: Path | None = None) -> Path:
        selected_root = root or self.root
        path = selected_root / custody.RECEIPT_NAME
        if path.exists():
            path.chmod(0o600)
            path.unlink()
        record = {
            "schema_version": 1,
            "contract": custody.RECEIPT_CONTRACT,
            "version": self.pin["version"],
            "platform": self.platform_key,
            "archive_name": self.pin["archive_name"][self.platform_key],
            "archive_sha256": self.pin["archive_sha256"][self.platform_key],
            "install_tree_sha256": custody.install_tree_sha256(selected_root),
            "executable_path": "bin/gcloud",
            "test_only": True,
        }
        path.write_text(json.dumps(record, sort_keys=True), encoding="ascii")
        path.chmod(custody.SEALED_PUBLIC_DATA_MODE)
        return path

    def service_account_payload(self, account: str, project: str) -> dict[str, str]:
        return {
            "type": "service_account",
            "project_id": project,
            "private_key_id": "fixture",
            "private_key": FAKE_PRIVATE_KEY,
            "client_email": account,
            "client_id": "1234567890",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }

    def workload_identity_payload(self, account: str) -> dict[str, object]:
        subject_token = Path(self.temporary.name) / "wif-subject-token"
        if subject_token.exists():
            subject_token.chmod(0o600)
        subject_token.write_text("fixture-signed-subject-token\n", encoding="ascii")
        subject_token.chmod(0o400)
        return {
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/pool/providers/prov",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://sts.googleapis.com/v1/token",
            "service_account_impersonation_url": (
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
                f"{account}:generateAccessToken"
            ),
            "credential_source": {"file": str(subject_token)},
        }

    def write_credential(self, name: str, payload: dict[str, object], *, mode: int = 0o400) -> custody.GcloudCredentialInput:
        path = Path(self.temporary.name) / name
        path.write_text(json.dumps(payload), encoding="ascii")
        path.chmod(mode)
        return custody.GcloudCredentialInput(
            kind=custody.SERVICE_ACCOUNT_KIND if payload.get("type") == "service_account" else custody.WORKLOAD_IDENTITY_KIND,
            path=path,
            expected_account=ACCOUNT,
            expected_project=PROJECT,
        )

    def bind_fixture(self) -> custody.VerifiedGcloud:
        pin = custody.parse_google_cloud_cli_pin_document(self.pin_path.read_bytes())
        return custody.bind_test_only_installed_gcloud(
            self.executable, pin, self.pin_path
        )

    def leftover_runtimes(self) -> set[Path]:
        parent = Path(tempfile.gettempdir())
        return {path for path in parent.glob("winsvpn-gcloud-*") if path.exists()}

    def assert_no_secret(self, text: str) -> None:
        self.assertNotIn(FAKE_PRIVATE_KEY, text)
        self.assertNotIn(ACCOUNT, text)
        self.assertNotIn(OTHER_ACCOUNT, text)
        self.assertNotIn("attacker-sentinel", text)

    def ssh_argv(
        self,
        *,
        instance: str = "pf-test-control",
        project: str = PROJECT,
        zone: str = "us-east1-b",
        command: str = "/usr/bin/true",
        with_gcloud: bool = True,
    ) -> list[str]:
        argv = [
            "compute",
            "ssh",
            instance,
            f"--project={project}",
            f"--zone={zone}",
            "--quiet",
            f"--command={command}",
        ]
        if with_gcloud:
            return ["gcloud", *argv]
        return argv

    def pipe_env(self) -> dict[str, str]:
        home = Path(self.temporary.name) / "pipe-home"
        home.mkdir(exist_ok=True)
        return {
            "HOME": str(home),
            "TMPDIR": str(home),
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def write_pipe_script(self, name: str, body: str) -> Path:
        path = Path(self.temporary.name) / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o700)
        return path

    def expected_pipe_response(self, payload: bytes = PIPE_PAYLOAD) -> bytes:
        digest = hashlib.sha256(payload).hexdigest()
        return json.dumps(
            {
                "contract": custody.SSH_PIPE_RESPONSE_CONTRACT,
                "payload_sha256": digest,
                "schema_version": 1,
                "status": "ok",
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    def run_kernel_pipe(
        self,
        producer_body: str,
        consumer_body: str,
        *,
        capture_name: str = "pipe-captures",
        timeout_seconds: int = 5,
        extra_env: dict[str, str] | None = None,
    ) -> custody.CustodyRunResult:
        capture_dir = Path(self.temporary.name) / capture_name
        capture_dir.mkdir()
        producer = self.write_pipe_script(f"{capture_name}-producer.py", producer_body)
        consumer = self.write_pipe_script(f"{capture_name}-consumer.py", consumer_body)
        env = self.pipe_env()
        if extra_env:
            env.update(extra_env)
        return custody._run_two_process_kernel_pipe(
            (sys.executable, str(producer)),
            (sys.executable, str(consumer)),
            env=env,
            timeout_seconds=timeout_seconds,
            capture_dir=capture_dir,
        )

    def test_current_repository_pin_is_exact_and_generated_go_pin_is_current(self) -> None:
        pin = custody.parse_google_cloud_cli_pin_document(REAL_PINS.read_bytes())
        self.assertEqual(pin["version"], "582.0.0")
        with self.assertRaisesRegex(
            custody.GcloudCustodyError,
            r"owner-blocked|component digest mismatch|(?:controller|release Python custody) digest does not match the trust-anchor",
        ):
            custody.validate_google_cloud_cli_pin(REAL_PINS)
        generated = Path(__file__).with_name("gcp_proof_client") / "gcloud_pin_generated.go"
        self.assertIn(pin["archive_sha256"]["linux_amd64"], generated.read_text())

    def test_valid_installation_is_bound_to_receipt_and_tree(self) -> None:
        verified = self.bind_fixture()
        self.assertEqual(verified.tree_sha256, custody.install_tree_sha256(self.root))
        self.assertEqual(verified.archive_bytes, self.archive_data)
        self.assertEqual(verified.runtime_tree_sha256, custody.install_tree_sha256(self.archive_source))
        verified.verify_unchanged()

    def test_arbitrary_sdk_and_self_authored_receipt_cannot_forge_archive_binding(self) -> None:
        forged_root = Path(self.temporary.name) / "forged" / "google-cloud-sdk"
        (forged_root / "bin").mkdir(parents=True)
        forged_executable = forged_root / "bin" / "gcloud"
        forged_executable.write_text("#!/bin/sh\nprintf 'MALICIOUS\\n'\n", encoding="ascii")
        forged_executable.chmod(0o755)
        (forged_root / "attacker.txt").write_text("self-authored\n", encoding="ascii")
        retained = forged_root / custody.CUSTODY_ARCHIVE_NAME
        retained.write_bytes(self.archive_data)
        retained.chmod(custody.SEALED_PUBLIC_DATA_MODE)
        self.write_receipt(forged_root)

        with self.assertRaisesRegex(
            custody.GcloudCustodyError,
            "installation tree does not match its reviewed archive",
        ):
            custody.bind_test_only_installed_gcloud(
                forged_executable,
                custody.parse_google_cloud_cli_pin_document(self.pin_path.read_bytes()),
                self.pin_path,
            )

        retained.unlink()
        self.write_receipt(forged_root)
        with self.assertRaises(custody.GcloudCustodyError):
            custody.bind_test_only_installed_gcloud(
                forged_executable,
                custody.parse_google_cloud_cli_pin_document(self.pin_path.read_bytes()),
                self.pin_path,
            )

    def test_duplicate_keys_and_schema_mutations_fail(self) -> None:
        base = json.dumps({"tools": {"google_cloud_cli": self.pin}})
        duplicate = base.replace('"version": "582.0.0"', '"version":"582.0.0","version":"582.0.0"')
        cases = [
            ("duplicate", None),
            ("unstable version", ("version", "582.0.0-rc1")),
            ("extra key", ("extra", True)),
            ("missing platform", ("missing", "linux_arm64")),
            ("wrong filename", ("filename", "unreviewed.tar.gz")),
            ("zero hash", ("hash", "0" * 64)),
        ]
        for name, mutation in cases:
            with self.subTest(name=name):
                pin = copy.deepcopy(self.pin)
                if mutation is None:
                    self.write_pin(raw=duplicate.encode())
                elif mutation[0] == "missing":
                    pin["archive_name"].pop(mutation[1])
                    self.pin_path.write_text(json.dumps({"tools": {"google_cloud_cli": pin}}))
                elif mutation[0] == "filename":
                    pin["archive_name"]["linux_amd64"] = mutation[1]
                    self.pin_path.write_text(json.dumps({"tools": {"google_cloud_cli": pin}}))
                elif mutation[0] == "hash":
                    pin["archive_sha256"]["linux_amd64"] = mutation[1]
                    self.pin_path.write_text(json.dumps({"tools": {"google_cloud_cli": pin}}))
                else:
                    pin[mutation[0]] = mutation[1]
                    self.pin_path.write_text(json.dumps({"tools": {"google_cloud_cli": pin}}))
                with self.assertRaises(custody.GcloudCustodyError):
                    custody.parse_google_cloud_cli_pin_document(self.pin_path.read_bytes())
        self.write_pin()

    def test_corrupt_receipt_hash_filename_and_executable_replacement_fail(self) -> None:
        for field, value in (
            ("archive_sha256", "f" * 64),
            ("archive_name", "google-cloud-cli-582.0.0-linux-wrong.tar.gz"),
        ):
            with self.subTest(field=field):
                record = json.loads((self.root / custody.RECEIPT_NAME).read_text())
                record[field] = value
                (self.root / custody.RECEIPT_NAME).chmod(0o600)
                (self.root / custody.RECEIPT_NAME).write_text(json.dumps(record))
                (self.root / custody.RECEIPT_NAME).chmod(custody.SEALED_PUBLIC_DATA_MODE)
                with self.assertRaises(custody.GcloudCustodyError):
                    self.bind_fixture()
                self.write_receipt()
        verified = self.bind_fixture()
        self.executable.chmod(0o700)
        self.executable.write_text("#!/bin/sh\nexit 9\n")
        self.executable.chmod(0o755)
        with self.assertRaises(custody.GcloudCustodyError):
            verified.verify_unchanged()

    def test_retained_official_archive_mutation_fails_closed(self) -> None:
        retained = self.root / custody.CUSTODY_ARCHIVE_NAME
        retained.chmod(0o600)
        retained.write_bytes(self.archive_data + b"substituted")
        retained.chmod(custody.SEALED_PUBLIC_DATA_MODE)
        with self.assertRaises(custody.GcloudCustodyError):
            self.bind_fixture()

    def test_runner_executes_valid_post_freeze_runtime_without_delegate_path_lookup(self) -> None:
        verified = self.bind_fixture()

        class PathDelegateMustNotRun:
            def run(inner_self, argv, *, timeout_seconds):
                raise AssertionError(f"pathname delegate executed: {argv!r} {timeout_seconds}")

        wrapped = custody.CustodyRunner(PathDelegateMustNotRun(), verified, self.good_credential)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
            wrapped.run([str(self.executable), "version"], timeout_seconds=5)

    def test_workload_identity_input_executes_the_same_snapshot(self) -> None:
        verified = self.bind_fixture()

        class PathDelegateMustNotRun:
            def run(inner_self, argv, *, timeout_seconds):
                raise AssertionError("pathname delegate executed")

        wrapped = custody.CustodyRunner(PathDelegateMustNotRun(), verified, self.workload_credential)
        with verified.private_runtime(self.workload_credential) as runtime:
            self.assertFalse(runtime.sealed)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
            wrapped.run([str(self.executable), "version"], timeout_seconds=5)

    def test_private_runtime_swap_restore_never_executes_substituted_bytes(self) -> None:
        verified = self.bind_fixture()
        spawned: list[object] = []

        def refuse_spawn(*_args: object, **_kwargs: object) -> int:
            spawned.append("posix_spawn")
            raise AssertionError("pathname spawn executed")

        def refuse_subprocess(*_args: object, **_kwargs: object) -> None:
            spawned.append("subprocess")
            raise AssertionError("pathname subprocess executed")

        with mock.patch.object(custody, "_posix_spawn", refuse_spawn):
            with mock.patch.object(custody.subprocess, "run", refuse_subprocess):
                with verified.private_runtime(self.good_credential) as runtime:
                    target = runtime.root / "bin" / "gcloud"
                    if target.exists() and not target.is_symlink():
                        try:
                            target.chmod(0o700)
                            target.write_text("#!/bin/sh\nprintf 'MALICIOUS\\n'\n", encoding="ascii")
                        except OSError:
                            pass
                    with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
                        runtime.run([], timeout_seconds=5)
        self.assertEqual(spawned, [])

    def test_support_file_swap_never_substitutes_reviewed_support_code(self) -> None:
        verified = self.bind_fixture()
        with verified.private_runtime(self.good_credential) as runtime:
            original_support = runtime.root / "lib" / "support.txt"
            self.assertEqual(original_support.read_text(encoding="ascii"), "SUPPORT_OK\n")
            extracted_support = runtime.scratch / "archive" / "google-cloud-sdk" / "lib" / "support.txt"
            extracted_support.chmod(0o600)
            extracted_support.write_text("MALICIOUS_SUPPORT\n", encoding="ascii")
            (self.root / "lib" / "support.txt").chmod(0o600)
            (self.root / "lib" / "support.txt").write_text("MALICIOUS_SUPPORT\n", encoding="ascii")
            with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
                runtime.run([], timeout_seconds=5)

    def test_ambient_credentials_are_omitted_from_the_isolated_child(self) -> None:
        attacker_home = Path(self.temporary.name) / "attacker-home"
        (attacker_home / ".config" / "gcloud").mkdir(parents=True)
        (attacker_home / ".config" / "gcloud" / "application_default_credentials.json").write_text(
            '{"type":"authorized_user","refresh_token":"attacker-sentinel"}',
            encoding="ascii",
        )
        attacker_key = Path(self.temporary.name) / "attacker-sentinel.json"
        attacker_key.write_text(json.dumps(self.service_account_payload(OTHER_ACCOUNT, PROJECT)), encoding="ascii")
        verified = self.bind_fixture()

        class PathDelegateMustNotRun:
            def run(inner_self, argv, *, timeout_seconds):
                raise AssertionError("pathname delegate executed")

        poisoned = {
            "HOME": str(attacker_home),
            "GOOGLE_APPLICATION_CREDENTIALS": str(attacker_key),
            "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": str(attacker_key),
            "CLOUDSDK_CONFIG": str(attacker_home / ".config" / "gcloud"),
            "PYTHONPATH": "/tmp/attacker-sentinel",
            "PYTHONHOME": "/tmp/attacker-sentinel-home",
        }
        with mock.patch.dict(os.environ, poisoned, clear=False):
            wrapped = custody.CustodyRunner(PathDelegateMustNotRun(), verified, self.good_credential)
            with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
                wrapped.run([str(self.executable), "version"], timeout_seconds=5)

    def test_wrong_identity_is_refused_without_printing_values(self) -> None:
        wrong = self.write_credential(
            "wrong-sa.json",
            self.service_account_payload(OTHER_ACCOUNT, PROJECT),
        )
        verified = self.bind_fixture()
        with self.assertRaises(custody.GcloudCustodyError) as raised:
            with verified.private_runtime(wrong):
                raise AssertionError("wrong identity reached execution")
        message = str(raised.exception)
        self.assertIn("does not match the bound identity", message)
        self.assert_no_secret(message)
        self.assertNotIn(PROJECT, message)

        wrong_project = self.write_credential(
            "wrong-project.json",
            self.service_account_payload(ACCOUNT, "otherproj123"),
        )
        with self.assertRaises(custody.GcloudCustodyError) as raised_project:
            custody.authenticate_credential(wrong_project)
        self.assert_no_secret(str(raised_project.exception))

    def test_unsafe_credential_mode_is_refused(self) -> None:
        unsafe = self.write_credential(
            "unsafe-sa.json",
            self.service_account_payload(ACCOUNT, PROJECT),
            mode=0o644,
        )
        with self.assertRaisesRegex(custody.GcloudCustodyError, "immutable mode 0400"):
            custody.authenticate_credential(unsafe)
        verified = self.bind_fixture()
        with self.assertRaisesRegex(custody.GcloudCustodyError, "immutable mode 0400"):
            with verified.private_runtime(unsafe):
                raise AssertionError("unsafe-mode credential reached execution")

    def test_missing_credential_is_an_owner_blocker(self) -> None:
        verified = self.bind_fixture()
        with self.assertRaisesRegex(custody.GcloudCustodyError, "owner blocker:.*credential or workload identity"):
            custody.CustodyRunner(object(), verified)

    def test_python_39_is_an_honest_owner_blocker_not_a_false_green(self) -> None:
        fake = SimpleNamespace(major=3, minor=9, micro=6, releaselevel="final", serial=0)
        with mock.patch.object(sys, "version_info", fake):
            with self.assertRaisesRegex(
                custody.GcloudCustodyError,
                r"owner blocker: Python 3\.9.*false-green",
            ):
                custody.require_compatible_python()
            with self.assertRaisesRegex(custody.GcloudCustodyError, r"owner blocker: Python 3\.9"):
                custody.extract_official_archive_bytes(self.archive_data, self.archive.name, Path(self.temporary.name) / "py39")

    def test_archive_bomb_limits_fail_before_extraction(self) -> None:
        def packed(members: list[tuple[str, bytes]]) -> bytes:
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as bundle:
                for name, body in members:
                    info = tarfile.TarInfo(name)
                    info.size = len(body)
                    info.mode = 0o644
                    bundle.addfile(info, io.BytesIO(body))
            compressed = io.BytesIO()
            with gzip.GzipFile(fileobj=compressed, mode="wb", compresslevel=9) as encoder:
                encoder.write(raw.getvalue())
            return compressed.getvalue()

        with mock.patch.object(custody, "MAX_ARCHIVE", 8):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "outer size"):
                custody.extract_official_archive_bytes(self.archive_data, self.archive.name, Path(self.temporary.name) / "outer")

        count_bomb = packed(
            [
                ("google-cloud-sdk/a", b"1"),
                ("google-cloud-sdk/b", b"2"),
                ("google-cloud-sdk/c", b"3"),
                ("google-cloud-sdk/d", b"4"),
            ]
        )
        with mock.patch.object(custody, "MAX_MEMBERS", 2):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "too many members"):
                custody.extract_official_archive_bytes(count_bomb, "google-cloud-cli.tar.gz", Path(self.temporary.name) / "count")

        member_bomb = packed([("google-cloud-sdk/big.bin", b"abcdefghij")])
        with mock.patch.object(custody, "MAX_MEMBER", 4):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "member size"):
                custody.extract_official_archive_bytes(member_bomb, "google-cloud-cli.tar.gz", Path(self.temporary.name) / "member")

        aggregate_bomb = packed(
            [
                ("google-cloud-sdk/one.bin", b"abcd"),
                ("google-cloud-sdk/two.bin", b"efgh"),
            ]
        )
        with mock.patch.object(custody, "MAX_EXPANDED", 6):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "aggregate"):
                custody.extract_official_archive_bytes(aggregate_bomb, "google-cloud-cli.tar.gz", Path(self.temporary.name) / "aggregate")

        depth_bomb = packed([("google-cloud-sdk/a/b/c/d", b"x")])
        with mock.patch.object(custody, "MAX_DEPTH", 3):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "depth"):
                custody.extract_official_archive_bytes(depth_bomb, "google-cloud-cli.tar.gz", Path(self.temporary.name) / "depth")

        zeros = b"\0" * (256 * 1024)
        ratio_bomb = packed([("google-cloud-sdk/zeros.bin", zeros)])
        with mock.patch.object(custody, "MAX_RATIO", 2):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "ratio|expanded size"):
                custody.extract_official_archive_bytes(ratio_bomb, "google-cloud-cli.tar.gz", Path(self.temporary.name) / "ratio")

    def test_cleanup_removes_runtime_and_credential_snapshots(self) -> None:
        before = self.leftover_runtimes()
        verified = self.bind_fixture()
        scratch_name = ""
        credential_path = Path()
        with verified.private_runtime(self.good_credential) as runtime:
            scratch_name = str(runtime.scratch)
            credential_path = runtime.credential_file
            self.assertTrue(runtime.scratch.exists())
            self.assertTrue(credential_path.exists())
            with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
                runtime.run([], timeout_seconds=5)
        self.assertFalse(Path(scratch_name).exists())
        self.assertFalse(credential_path.exists())
        self.assertEqual(self.leftover_runtimes(), before)

    def test_receipt_producer_requires_verified_archive_and_exact_extraction(self) -> None:
        install_root = Path(self.temporary.name) / "second" / "google-cloud-sdk"
        install_root.parent.mkdir()
        shutil.copytree(self.archive_source, install_root, symlinks=True)
        with self.assertRaisesRegex(
            custody.GcloudCustodyError,
            "self-authored synthetic|owner-blocked",
        ):
            producer.create(self.archive, install_root, self.pin_path)
        created = producer.create_test_only(self.archive, install_root, self.pin_path)
        receipt = install_root / custody.RECEIPT_NAME
        self.assertEqual(created.resolve(), receipt.resolve())
        self.assertEqual(
            created.stat().st_mode & 0o777, custody.SEALED_PUBLIC_DATA_MODE
        )
        retained = install_root / custody.CUSTODY_ARCHIVE_NAME
        self.assertEqual(retained.read_bytes(), self.archive_data)
        self.assertEqual(
            retained.stat().st_mode & 0o777, custody.SEALED_PUBLIC_DATA_MODE
        )
        payload = json.loads(receipt.read_text(encoding="ascii"))
        self.assertIs(payload["test_only"], True)
        retried = producer.create_test_only(self.archive, install_root, self.pin_path)
        self.assertEqual(retried.resolve(), receipt.resolve())
        self.archive.write_bytes(self.archive_data + b"corrupt")
        other_root = Path(self.temporary.name) / "third" / "google-cloud-sdk"
        other_root.parent.mkdir()
        shutil.copytree(self.archive_source, other_root, symlinks=True)
        with self.assertRaises(custody.GcloudCustodyError):
            producer.create_test_only(self.archive, other_root, self.pin_path)

    def test_fixed_ssh_argv_is_exact_and_does_not_print_values(self) -> None:
        parsed = custody.validate_fixed_gcloud_ssh_argv(self.ssh_argv())
        self.assertEqual(parsed[0], "compute")
        self.assertEqual(parsed[1], "ssh")
        self.assertEqual(
            parsed,
            custody.validate_fixed_gcloud_ssh_argv(self.ssh_argv(with_gcloud=False)),
        )
        cases = [
            ("empty", []),
            ("shell string", "gcloud compute ssh"),
            ("not ssh", ["gcloud", "compute", "scp", "pf-test-control", f"--project={PROJECT}", "--zone=us-east1-b", "--quiet", "--command=/usr/bin/true"]),
            ("extra", [*self.ssh_argv(), "--dry-run"]),
            ("missing quiet", ["gcloud", "compute", "ssh", "pf-test-control", f"--project={PROJECT}", "--zone=us-east1-b", "--command=/usr/bin/true"]),
            ("filter", ["gcloud", "compute", "ssh", "pf-test-control", f"--project={PROJECT}", "--zone=us-east1-b", "--quiet", "--filter=name=pf-test-control"]),
            ("glob instance", ["gcloud", "compute", "ssh", "pf-*", f"--project={PROJECT}", "--zone=us-east1-b", "--quiet", "--command=/usr/bin/true"]),
            ("newline command", self.ssh_argv(command="/usr/bin/true\n/bin/sh")),
            ("empty command", self.ssh_argv(command="")),
            ("bool token", ["gcloud", "compute", "ssh", True, f"--project={PROJECT}", "--zone=us-east1-b", "--quiet", "--command=/usr/bin/true"]),
        ]
        for name, argv in cases:
            with self.subTest(name=name):
                with self.assertRaises(custody.GcloudCustodyError) as raised:
                    custody.validate_fixed_gcloud_ssh_argv(argv)  # type: ignore[arg-type]
                self.assert_no_secret(str(raised.exception))
                self.assertNotIn(PROJECT, str(raised.exception))
                self.assertNotIn("pf-test-control", str(raised.exception))
                self.assertNotIn("/usr/bin/true", str(raised.exception))

    def test_ssh_pipe_happy_path_never_exposes_producer_stdout(self) -> None:
        capture_dir = Path(self.temporary.name) / "happy-captures"
        capture_dir.mkdir()
        producer = self.write_pipe_script("happy-producer.py", PIPE_PRODUCER_OK)
        consumer = self.write_pipe_script("happy-consumer.py", PIPE_CONSUMER_HASH)
        records: list[tuple[object, dict[str, object]]] = []
        pipe_fds: list[int] = []
        real_popen = subprocess.Popen
        real_pipe = custody._cloexec_pipe
        real_read = os.read
        real_pread = os.pread

        def record_pipe() -> tuple[int, int]:
            pair = real_pipe()
            if not pipe_fds:
                pipe_fds.extend(pair)
            return pair

        def spy_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            records.append((args[0], dict(kwargs)))
            return real_popen(*args, **kwargs)

        def guarded_read(fd: int, n: int) -> bytes:
            if fd in pipe_fds:
                try:
                    mode = os.fstat(fd).st_mode
                except OSError:
                    return real_read(fd, n)
                if stat.S_ISFIFO(mode):
                    raise AssertionError("producer stdout pipe was read by Python")
            return real_read(fd, n)

        def guarded_pread(fd: int, n: int, offset: int) -> bytes:
            if fd in pipe_fds:
                try:
                    mode = os.fstat(fd).st_mode
                except OSError:
                    return real_pread(fd, n, offset)
                if stat.S_ISFIFO(mode):
                    raise AssertionError("producer stdout pipe was read by Python")
            return real_pread(fd, n, offset)

        with mock.patch.object(custody, "_cloexec_pipe", record_pipe):
            with mock.patch.object(custody.subprocess, "Popen", spy_popen):
                with mock.patch.object(os, "read", guarded_read):
                    with mock.patch.object(os, "pread", guarded_pread):
                        result = custody._run_two_process_kernel_pipe(
                            (sys.executable, str(producer)),
                            (sys.executable, str(consumer)),
                            env=self.pipe_env(),
                            timeout_seconds=5,
                            capture_dir=capture_dir,
                        )
        expected = self.expected_pipe_response()
        self.assertEqual(result.stdout, expected)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.exit_code, 0)
        self.assertNotIn(PIPE_PAYLOAD, result.stdout)
        self.assertNotIn(PIPE_PAYLOAD, result.stderr)
        self.assertEqual(set(result.__dataclass_fields__), {"stdout", "stderr", "exit_code"})
        self.assertEqual(len(records), 2)
        self.assertTrue(str(records[0][0][1]).endswith("happy-consumer.py"))
        self.assertTrue(str(records[1][0][1]).endswith("happy-producer.py"))
        for argv, kwargs in records:
            del argv
            self.assertIs(kwargs["shell"], False)
            self.assertIs(kwargs["close_fds"], True)
            self.assertIs(kwargs["start_new_session"], True)
            self.assertIsNot(kwargs["stdout"], subprocess.PIPE)
            self.assertIsNot(kwargs["stdin"], subprocess.PIPE)
            self.assertIsInstance(kwargs["stdout"], int)
            self.assertIsInstance(kwargs["stderr"], int)
        self.assertIsInstance(records[0][1]["stdin"], int)
        self.assertIsInstance(records[1][1]["stdout"], int)
        names = {path.name for path in capture_dir.iterdir()}
        self.assertNotIn("gcloud-pipe-producer-stdout", names)
        self.assertFalse(
            {
                custody.PIPE_PRODUCER_STDERR,
                custody.PIPE_CONSUMER_STDOUT,
                custody.PIPE_CONSUMER_STDERR,
            }
            & names
        )

    def test_partial_producer_failure_fails_closed_without_secret_leakage(self) -> None:
        with self.assertRaises(custody.GcloudCustodyError) as raised:
            self.run_kernel_pipe(PIPE_PRODUCER_FAIL, PIPE_CONSUMER_HASH, capture_name="partial")
        message = str(raised.exception)
        self.assertIn("did not both exit zero", message)
        self.assert_no_secret(message)
        self.assertNotIn("BEGIN PRIVATE KEY", message)
        self.assertNotIn(PIPE_SECRET.decode("ascii"), message)

    def test_early_consumer_refusal_fails_closed(self) -> None:
        with self.assertRaises(custody.GcloudCustodyError) as raised:
            self.run_kernel_pipe(PIPE_PRODUCER_OK, PIPE_CONSUMER_REFUSE, capture_name="refuse")
        self.assertIn("did not both exit zero", str(raised.exception))
        self.assert_no_secret(str(raised.exception))

    def test_timeout_kills_both_process_groups(self) -> None:
        capture_dir = Path(self.temporary.name) / "timeout-captures"
        capture_dir.mkdir()
        producer = self.write_pipe_script("timeout-producer.py", PIPE_PRODUCER_SLEEP)
        consumer = self.write_pipe_script("timeout-consumer.py", PIPE_CONSUMER_SLEEP)
        pids: list[int] = []
        real_popen = subprocess.Popen

        def spy_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            proc = real_popen(*args, **kwargs)
            pids.append(int(proc.pid))
            return proc

        started = time.monotonic()
        with mock.patch.object(custody.subprocess, "Popen", spy_popen):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "timed out"):
                custody._run_two_process_kernel_pipe(
                    (sys.executable, str(producer)),
                    (sys.executable, str(consumer)),
                    env=self.pipe_env(),
                    timeout_seconds=1,
                    capture_dir=capture_dir,
                )
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(len(pids), 2)
        for pid in pids:
            with self.assertRaises(OSError):
                os.kill(pid, 0)

    def test_broken_pipe_fails_closed(self) -> None:
        with self.assertRaises(custody.GcloudCustodyError) as raised:
            self.run_kernel_pipe(PIPE_PRODUCER_BULK, PIPE_CONSUMER_SHORT, capture_name="broken")
        self.assertIn("did not both exit zero", str(raised.exception))
        self.assert_no_secret(str(raised.exception))

    def test_descriptor_leaks_are_not_inherited(self) -> None:
        canary_r, canary_w = os.pipe()
        try:
            for fd in (canary_r, canary_w):
                os.set_inheritable(fd, True)
                flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                fcntl.fcntl(fd, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
            pipe_fds: list[int] = []
            real_pipe = custody._cloexec_pipe

            def record_pipe() -> tuple[int, int]:
                pair = real_pipe()
                if not pipe_fds:
                    pipe_fds.extend(pair)
                return pair

            capture_dir = Path(self.temporary.name) / "leak-captures"
            capture_dir.mkdir()
            producer = self.write_pipe_script("leak-producer.py", PIPE_PRODUCER_OK)
            consumer = self.write_pipe_script("leak-consumer.py", PIPE_CONSUMER_FDS)
            with mock.patch.object(custody, "_cloexec_pipe", record_pipe):
                result = custody._run_two_process_kernel_pipe(
                    (sys.executable, str(producer)),
                    (sys.executable, str(consumer)),
                    env=self.pipe_env(),
                    timeout_seconds=5,
                    capture_dir=capture_dir,
                )
            self.assertEqual(result.stdout, self.expected_pipe_response())
            report = Path(self.pipe_env()["TMPDIR"]) / "inherited-fds"
            extra_text = report.read_text(encoding="ascii")
            extra = {int(item) for item in extra_text.split(",") if item}
            forbidden = set(pipe_fds) | {canary_r, canary_w}
            self.assertFalse(extra & forbidden)
            self.assertNotIn(PIPE_PAYLOAD, result.stdout)
        finally:
            os.close(canary_r)
            os.close(canary_w)

    def test_cloexec_pipe_sets_close_on_exec(self) -> None:
        read_fd, write_fd = custody._cloexec_pipe()
        try:
            for fd in (read_fd, write_fd):
                flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                self.assertTrue(flags & fcntl.FD_CLOEXEC)
                self.assertFalse(os.get_inheritable(fd))
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_hostile_capture_swap_does_not_retarget_kernel_streams(self) -> None:
        capture_dir = Path(self.temporary.name) / "swap-captures"
        capture_dir.mkdir()
        secret_outside = Path(self.temporary.name) / "swapped-secret"
        secret_outside.write_bytes(PIPE_SECRET)
        for name in (
            custody.PIPE_PRODUCER_STDERR,
            custody.PIPE_CONSUMER_STDOUT,
            custody.PIPE_CONSUMER_STDERR,
        ):
            (capture_dir / name).symlink_to(secret_outside)
        producer = self.write_pipe_script("swap-producer.py", PIPE_PRODUCER_OK)
        consumer = self.write_pipe_script("swap-consumer.py", PIPE_CONSUMER_HASH)
        opened: list[str] = []
        real_open = os.open

        def spy_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            text = os.fspath(path) if isinstance(path, (str, bytes, os.PathLike)) else str(path)
            opened.append(str(text))
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(os, "open", spy_open):
            result = custody._run_two_process_kernel_pipe(
                (sys.executable, str(producer)),
                (sys.executable, str(consumer)),
                env=self.pipe_env(),
                timeout_seconds=5,
                capture_dir=capture_dir,
            )
        self.assertEqual(result.stdout, self.expected_pipe_response())
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(PIPE_SECRET, result.stdout)
        self.assertFalse(any(custody.PIPE_CONSUMER_STDOUT in item for item in opened))
        self.assertFalse(any(custody.PIPE_CONSUMER_STDERR in item for item in opened))
        self.assertFalse(any(custody.PIPE_PRODUCER_STDERR in item for item in opened))

    def test_opaque_secret_echo_is_rejected_without_leakage(self) -> None:
        with self.assertRaises(custody.GcloudCustodyError) as raised:
            self.run_kernel_pipe(PIPE_PRODUCER_OK, PIPE_CONSUMER_OPAQUE, capture_name="opaque")
        self.assertIn("consumer response is invalid", str(raised.exception))
        self.assertNotIn(PIPE_OPAQUE_SECRET.decode("ascii"), str(raised.exception))
        self.assert_no_secret(str(raised.exception))

    def test_oversize_stream_is_rejected_during_production(self) -> None:
        limit = 4096
        capture_dir = Path(self.temporary.name) / "oversize-captures"
        capture_dir.mkdir()
        probe = capture_dir / "probe"
        probe.write_bytes(b"")
        producer = self.write_pipe_script("oversize-producer.py", PIPE_PRODUCER_OK)
        consumer = self.write_pipe_script(
            "oversize-consumer.py",
            PIPE_CONSUMER_OVERSIZE.replace("__WINSVPN_PIPE_OVERSIZE__", str(limit)),
        )
        env = self.pipe_env()
        with mock.patch.object(custody, "MAX_PIPE_CAPTURE", limit):
            with self.assertRaises(custody.GcloudCustodyError) as raised:
                custody._run_two_process_kernel_pipe(
                    (sys.executable, str(producer)),
                    (sys.executable, str(consumer)),
                    env=env,
                    timeout_seconds=5,
                    capture_dir=capture_dir,
                )
        self.assertIn("exceeds the size limit", str(raised.exception))
        self.assertEqual(probe.stat().st_size, 0)
        self.assertEqual({path.name for path in capture_dir.iterdir()}, {"probe"})

    def test_secret_shaped_and_stderr_streams_fail_closed_without_leakage(self) -> None:
        with self.assertRaises(custody.GcloudCustodyError) as raised_out:
            self.run_kernel_pipe(PIPE_PRODUCER_OK, PIPE_CONSUMER_SECRET, capture_name="secret-out")
        self.assertIn("consumer response is invalid", str(raised_out.exception))
        self.assert_no_secret(str(raised_out.exception))
        self.assertNotIn("BEGIN PRIVATE KEY", str(raised_out.exception))
        with self.assertRaises(custody.GcloudCustodyError) as raised_err:
            self.run_kernel_pipe(
                PIPE_PRODUCER_STDERR_SECRET, PIPE_CONSUMER_HASH, capture_name="secret-err"
            )
        self.assertIn("producer stderr is not empty", str(raised_err.exception))
        self.assert_no_secret(str(raised_err.exception))
        self.assertNotIn("BEGIN PRIVATE KEY", str(raised_err.exception))
        with self.assertRaises(custody.GcloudCustodyError) as raised_consumer_err:
            self.run_kernel_pipe(
                PIPE_PRODUCER_OK, PIPE_CONSUMER_STDERR_NOISE, capture_name="consumer-err"
            )
        self.assertIn("consumer stderr is not empty", str(raised_consumer_err.exception))
        self.assert_no_secret(str(raised_consumer_err.exception))

    def test_partial_json_consumer_failure_fails_closed(self) -> None:
        with self.assertRaises(custody.GcloudCustodyError) as raised:
            self.run_kernel_pipe(
                PIPE_PRODUCER_OK, PIPE_CONSUMER_PARTIAL_JSON, capture_name="partial-json"
            )
        self.assertIn("consumer response is invalid", str(raised.exception))
        self.assert_no_secret(str(raised.exception))
        self.assertNotIn(PIPE_PAYLOAD.decode("ascii"), str(raised.exception))

    def test_bool_and_zero_timeouts_are_invalid(self) -> None:
        capture_dir = Path(self.temporary.name) / "timeout-invalid"
        capture_dir.mkdir()
        producer = self.write_pipe_script("invalid-producer.py", PIPE_PRODUCER_OK)
        consumer = self.write_pipe_script("invalid-consumer.py", PIPE_CONSUMER_HASH)
        for timeout in (True, False, 0, -1, 3601, 1.5):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(custody.GcloudCustodyError, "timeout is invalid"):
                    custody._run_two_process_kernel_pipe(
                        (sys.executable, str(producer)),
                        (sys.executable, str(consumer)),
                        env=self.pipe_env(),
                        timeout_seconds=timeout,  # type: ignore[arg-type]
                        capture_dir=capture_dir,
                    )

    def test_ssh_pipe_consumer_response_schema_is_exact(self) -> None:
        valid = self.expected_pipe_response()
        self.assertEqual(custody.validate_ssh_pipe_consumer_response(valid + b"\n"), valid)
        digest = hashlib.sha256(PIPE_PAYLOAD).hexdigest()
        cases = [
            b"",
            b"{",
            b"[]",
            json.dumps(
                {
                    "contract": custody.SSH_PIPE_RESPONSE_CONTRACT,
                    "payload_sha256": digest,
                    "schema_version": True,
                    "status": "ok",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii"),
            json.dumps(
                {
                    "contract": custody.SSH_PIPE_RESPONSE_CONTRACT,
                    "payload_sha256": digest,
                    "schema_version": 1,
                    "status": "ok",
                    "extra": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii"),
            json.dumps(
                {
                    "contract": custody.SSH_PIPE_RESPONSE_CONTRACT,
                    "payload_sha256": digest,
                    "schema_version": 1,
                    "status": "ok",
                }
            ).encode("ascii"),
            valid.replace(b"ok", b"fail"),
            PIPE_OPAQUE_SECRET,
        ]
        for payload in cases:
            with self.subTest(payload=payload[:40]):
                with self.assertRaises(custody.GcloudCustodyError) as raised:
                    custody.validate_ssh_pipe_consumer_response(payload)
                self.assert_no_secret(str(raised.exception))
                self.assertNotIn(PIPE_OPAQUE_SECRET.decode("ascii"), str(raised.exception))

    def test_duplicate_untrusted_ssh_pipe_json_keys_map_to_safe_refusal(self) -> None:
        opaque = PIPE_OPAQUE_SECRET.decode("ascii")
        cases = (
            ("opaque-token", opaque),
            ("pem-header", "-----BEGIN PRIVATE KEY-----"),
            ("pem-shaped", FAKE_PRIVATE_KEY),
        )
        for name, key in cases:
            with self.subTest(name=name):
                encoded = json.dumps(key, ensure_ascii=True)
                payload = f"{{{encoded}:1,{encoded}:1}}".encode("ascii")
                with self.assertRaises(custody.GcloudCustodyError) as raised:
                    custody.validate_ssh_pipe_consumer_response(payload)
                message = str(raised.exception)
                self.assertEqual(message, custody.SSH_PIPE_RESPONSE)
                self.assertNotIn("duplicate JSON key", message)
                self.assertNotIn(key, message)
                self.assertNotIn(opaque, message)
                self.assertNotIn("BEGIN PRIVATE KEY", message)
                self.assertNotIn("TEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL", message)
                self.assert_no_secret(message)
                cause = raised.exception.__cause__
                context = raised.exception.__context__
                for item in (cause, context):
                    if item is None:
                        continue
                    chained = str(item)
                    self.assertNotIn("duplicate JSON key", chained)
                    self.assertNotIn(key, chained)
                    self.assertNotIn(opaque, chained)
                    self.assertNotIn("BEGIN PRIVATE KEY", chained)
                    self.assertNotIn("TEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL", chained)
                    self.assert_no_secret(chained)

    def test_runner_ssh_pipe_reverifies_before_and_after(self) -> None:
        verified = self.bind_fixture()
        calls: list[str] = []
        expected = self.expected_pipe_response()

        def counting(_self: object) -> None:
            calls.append("verify")

        with mock.patch.object(custody.VerifiedGcloud, "verify_unchanged", counting):
            with mock.patch.object(
                custody.PrivateGcloudRuntime,
                "run_ssh_pipe",
                return_value=custody.CustodyRunResult(expected, b"", 0),
            ):
                runner = custody.CustodyRunner(object(), verified, self.good_credential)
                result = runner.run_ssh_pipe(
                    self.ssh_argv(),
                    self.ssh_argv(instance="pf-test-winn3"),
                    timeout_seconds=5,
                    consumer_response_validator=custody.validate_ssh_pipe_consumer_response,
                )
        self.assertGreaterEqual(calls.count("verify"), 2)
        self.assertEqual(result.stdout, expected)
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(PIPE_PAYLOAD, result.stdout)

    def test_runner_ssh_pipe_failure_still_reverifies(self) -> None:
        verified = self.bind_fixture()
        calls: list[str] = []

        def counting(_self: object) -> None:
            calls.append("verify")

        with mock.patch.object(custody.VerifiedGcloud, "verify_unchanged", counting):
            with mock.patch.object(
                custody.PrivateGcloudRuntime,
                "run_ssh_pipe",
                side_effect=custody.GcloudCustodyError("Google Cloud CLI SSH pipe processes did not both exit zero"),
            ):
                runner = custody.CustodyRunner(object(), verified, self.good_credential)
                with self.assertRaises(custody.GcloudCustodyError) as raised:
                    runner.run_ssh_pipe(
                        self.ssh_argv(),
                        self.ssh_argv(),
                        timeout_seconds=5,
                        consumer_response_validator=custody.validate_ssh_pipe_consumer_response,
                    )
        self.assertGreaterEqual(calls.count("verify"), 2)
        self.assertIn("did not both exit zero", str(raised.exception))
        self.assert_no_secret(str(raised.exception))

    def test_runtime_ssh_pipe_failure_still_reverifies_tree_and_credential(self) -> None:
        verified = self.bind_fixture()
        post: list[str] = []
        real_reverify = custody._reverify_private_runtime_after_execution

        def counting(runtime: object) -> None:
            post.append("post")
            real_reverify(runtime)

        with mock.patch.object(custody, "_reverify_private_runtime_after_execution", counting):
            with verified.private_runtime(self.good_credential) as runtime:
                with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
                    runtime.run_ssh_pipe(
                        self.ssh_argv(with_gcloud=False),
                        self.ssh_argv(with_gcloud=False),
                        timeout_seconds=5,
                        consumer_response_validator=custody.validate_ssh_pipe_consumer_response,
                    )
        self.assertEqual(post, ["post"])

    def test_runner_ssh_pipe_refuses_unbound_project_without_printing_it(self) -> None:
        verified = self.bind_fixture()
        runner = custody.CustodyRunner(object(), verified, self.good_credential)
        with self.assertRaises(custody.GcloudCustodyError) as raised:
            runner.run_ssh_pipe(
                self.ssh_argv(project="otherproj123"),
                self.ssh_argv(),
                timeout_seconds=5,
                consumer_response_validator=custody.validate_ssh_pipe_consumer_response,
            )
        self.assertIn("does not match the bound plan project", str(raised.exception))
        self.assert_no_secret(str(raised.exception))
        self.assertNotIn(PROJECT, str(raised.exception))
        self.assertNotIn("otherproj123", str(raised.exception))

    def test_runner_ssh_pipe_unsealed_host_fails_closed_after_argv_validation(self) -> None:
        verified = self.bind_fixture()
        runner = custody.CustodyRunner(object(), verified, self.good_credential)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
            runner.run_ssh_pipe(
                self.ssh_argv(),
                self.ssh_argv(),
                timeout_seconds=5,
                consumer_response_validator=custody.validate_ssh_pipe_consumer_response,
            )

    def test_production_ssh_pipe_validator_cannot_be_omitted_or_substituted(self) -> None:
        verified = self.bind_fixture()
        runner = custody.CustodyRunner(object(), verified, self.good_credential)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "validator is required"):
            runner.run_ssh_pipe(self.ssh_argv(), self.ssh_argv(), timeout_seconds=5)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "validator is required"):
            runner.run_ssh_pipe(
                self.ssh_argv(),
                self.ssh_argv(),
                timeout_seconds=5,
                consumer_response_validator=lambda data: data,  # type: ignore[arg-type]
            )
        runtime_sig = inspect.signature(custody.PrivateGcloudRuntime.run_ssh_pipe)
        runner_sig = inspect.signature(custody.CustodyRunner.run_ssh_pipe)
        self.assertIn("consumer_response_validator", runtime_sig.parameters)
        self.assertIn("consumer_response_validator", runner_sig.parameters)
        self.assertIs(
            inspect.unwrap(custody.validate_ssh_pipe_consumer_response),
            custody.validate_ssh_pipe_consumer_response,
        )

    def test_macos_pipe_stdio_uses_held_nofollow_descriptors(self) -> None:
        stdio_src = inspect.getsource(custody._posix_spawn_stdio)
        self.assertIn("posix_spawn_file_actions_adddup2", stdio_src)
        self.assertIn("adddup2 stdin", stdio_src)
        self.assertIn("adddup2 stdout", stdio_src)
        self.assertIn("adddup2 stderr", stdio_src)
        self.assertNotIn("stdout_path", stdio_src)
        self.assertNotIn("stderr_path", stdio_src)
        self.assertNotIn("posix_spawn_file_actions_addopen", stdio_src)
        self.assertNotIn("create_stdio_files", stdio_src)
        devnull_src = inspect.getsource(custody._cloexec_devnull)
        self.assertIn("O_NOFOLLOW", devnull_src)
        self.assertIn("O_CLOEXEC", devnull_src)
        recorded: list[dict[str, object]] = []

        def fake_spawn(*_args: object, **kwargs: object) -> int:
            recorded.append(dict(kwargs))
            raise custody.GcloudCustodyError("stop after descriptor spawn record")

        with mock.patch.object(custody, "_posix_spawn_stdio", fake_spawn):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "stop after descriptor spawn record"):
                custody._run_darwin_gcloud_ssh_pipe(
                    ("compute", "ssh", "pf-test-control", f"--project={PROJECT}", "--zone=us-east1-b", "--quiet", "--command=/usr/bin/true"),
                    ("compute", "ssh", "pf-test-winn3", f"--project={PROJECT}", "--zone=us-east1-b", "--quiet", "--command=/usr/bin/true"),
                    env=self.pipe_env(),
                    timeout_seconds=5,
                    root_fd=0,
                    consumer_response_validator=custody.validate_ssh_pipe_consumer_response,
                )
        self.assertEqual(len(recorded), 1)
        self.assertIsInstance(recorded[0]["stdin_fd"], int)
        self.assertIsInstance(recorded[0]["stdout_fd"], int)
        self.assertIsInstance(recorded[0]["stderr_fd"], int)
        self.assertNotIn("stdout_path", recorded[0])
        self.assertNotIn("stderr_path", recorded[0])

    def test_ssh_pipe_source_never_names_a_producer_stdout_capture(self) -> None:
        source = Path(__file__).with_name("gcloud_custody.py").read_text(encoding="ascii")
        self.assertIn("run_ssh_pipe", source)
        self.assertIn("O_CLOEXEC", source)
        self.assertIn("posix_spawn_file_actions_adddup2", source)
        self.assertIn("validate_ssh_pipe_consumer_response", source)
        self.assertIn("_reverify_private_runtime_after_execution", source)
        self.assertIn(custody.PIPE_PRODUCER_STDERR, source)
        self.assertIn(custody.PIPE_CONSUMER_STDOUT, source)
        self.assertIn(custody.PIPE_CONSUMER_STDERR, source)
        self.assertNotIn("gcloud-pipe-producer-stdout", source)
        self.assertIn("shell=False", source)
        self.assertNotIn("PIPE_SECRET_RE", source)


if __name__ == "__main__":
    unittest.main()
