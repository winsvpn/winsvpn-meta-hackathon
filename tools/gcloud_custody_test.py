#!/usr/bin/env python3

from __future__ import annotations

import copy
import dataclasses
from datetime import timedelta
import fcntl
import gzip
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import platform
import re
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


REAL_PINS = Path(__file__).with_name("toolchain-pins.json")
REAL_TRUST = Path(__file__).with_name("gcloud_custody.trust.json")
REAL_CONTROLLER = Path(__file__).with_name("gcloud_custody.py")
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


def sign_ed25519_for_test(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    def encode(point: tuple[int, int, int, int]) -> bytes:
        inverse = pow(point[2], custody._ED25519_P - 2, custody._ED25519_P)
        x = point[0] * inverse % custody._ED25519_P
        y = point[1] * inverse % custody._ED25519_P
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    hashed = bytearray(hashlib.sha512(seed).digest())
    hashed[0] &= 248
    hashed[31] &= 63
    hashed[31] |= 64
    scalar = int.from_bytes(hashed[:32], "little")
    public_key = encode(custody._ed25519_mul(custody._ED25519_BASE, scalar))
    nonce = int.from_bytes(hashlib.sha512(bytes(hashed[32:]) + message).digest(), "little")
    nonce %= custody._ED25519_L
    encoded_nonce = encode(custody._ed25519_mul(custody._ED25519_BASE, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_nonce + public_key + message).digest(), "little"
    ) % custody._ED25519_L
    signature_scalar = (nonce + challenge * scalar) % custody._ED25519_L
    return public_key, encoded_nonce + signature_scalar.to_bytes(32, "little")


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
        self.install_fixture_receipt()
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

    def write_receipt(self, root: Path | None = None, **overrides: object) -> Path:
        selected_root = root or self.root
        path = selected_root / custody.RECEIPT_NAME
        if path.exists():
            path.chmod(0o600)
            path.unlink()
        record: dict[str, object] = {
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
        record.update(overrides)
        path.write_text(json.dumps(record, sort_keys=True), encoding="ascii")
        path.chmod(custody.SEALED_PUBLIC_DATA_MODE)
        return path

    def install_fixture_receipt(self) -> None:
        retained = self.root / custody.CUSTODY_ARCHIVE_NAME
        if retained.exists():
            retained.chmod(0o600)
            retained.unlink()
        retained.write_bytes(self.archive_data)
        os.chmod(retained, custody.SEALED_PUBLIC_DATA_MODE)
        self.write_receipt()

    def bind_fixture(self) -> custody.VerifiedGcloud:
        pin = custody.parse_google_cloud_cli_pin_document(self.pin_path.read_bytes())
        return custody.bind_test_only_installed_gcloud(
            self.executable, pin, self.pin_path
        )

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

    def signed_owner_issuance(
        self, *, issued_utc: str | None = None
    ) -> tuple[dict[str, object], bytes, str]:
        issued = custody._utc_now()
        issued_text = issued_utc or issued.strftime("%Y-%m-%dT%H:%M:%SZ")
        expires_text = (issued + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if issued_utc is not None:
            expires_text = "2000-01-01T01:00:00Z"
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        receipt: dict[str, object] = {
            "schema_version": 1,
            "contract": custody.RECEIPT_CONTRACT,
            "version": self.pin["version"],
            "platform": self.platform_key,
            "archive_name": self.pin["archive_name"][self.platform_key],
            "archive_sha256": self.pin["archive_sha256"][self.platform_key],
            "install_tree_sha256": custody.install_tree_sha256(self.root),
            "executable_path": "bin/gcloud",
            "install_root_sha256": hashlib.sha256(
                str(self.root.resolve(strict=True)).encode("utf-8")
            ).hexdigest(),
            "issued_utc": issued_text,
            "expires_utc": expires_text,
            "issuance_id": "a" * 32,
            "authority_key_id": "",
            "controller_sha256": "b" * 64,
            "manifest_sha256": "c" * 64,
            "trust_anchor_sha256": "d" * 64,
        }
        public_key, _unused = sign_ed25519_for_test(seed, b"")
        key_id = hashlib.sha256(public_key).hexdigest()
        receipt["authority_key_id"] = key_id
        _public_key, signature = sign_ed25519_for_test(
            seed, custody._owner_receipt_message(receipt)
        )
        issuance: dict[str, object] = {
            "contract": custody.OWNER_ISSUANCE_CONTRACT,
            "schema_version": 1,
            "issuer": custody.OWNER_ISSUANCE_ISSUER,
            "algorithm": custody.OWNER_SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "receipt": receipt,
            "signature": signature.hex(),
        }
        return issuance, public_key, key_id

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

    def test_repository_pin_schema_is_exact_and_generated_go_pin_is_current(self) -> None:
        pin = custody.parse_google_cloud_cli_pin_document(REAL_PINS.read_bytes())
        self.assertEqual(pin["version"], "582.0.0")
        generated = Path(__file__).with_name("gcp_proof_client") / "gcloud_pin_generated.go"
        self.assertIn(pin["archive_sha256"]["linux_amd64"], generated.read_text())

    def test_trust_anchor_matches_controller_and_manifest_bytes(self) -> None:
        trust = json.loads(REAL_TRUST.read_text(encoding="utf-8"))
        self.assertEqual(set(trust), set(custody.TRUST_KEYS))
        self.assertIs(type(trust["schema_version"]), int)
        controller = hashlib.sha256(REAL_CONTROLLER.read_bytes()).hexdigest()
        manifest = hashlib.sha256(REAL_PINS.read_bytes()).hexdigest()
        python_custody = hashlib.sha256(
            REAL_CONTROLLER.with_name(custody.PYTHON_CUSTODY_NAME).read_bytes()
        ).hexdigest()
        if (
            controller != trust["controller_sha256"]
            or manifest != trust["manifest_sha256"]
            or python_custody != trust["python_custody_sha256"]
        ):
            with self.assertRaisesRegex(
                custody.GcloudCustodyError,
                r"(?:controller|pin manifest|release Python custody) digest does not match the trust-anchor|custody component digest mismatch",
            ):
                custody.validate_google_cloud_cli_pin(REAL_PINS)
            return
        self.assertEqual(controller, trust["controller_sha256"])
        self.assertEqual(manifest, trust["manifest_sha256"])
        self.assertEqual(python_custody, trust["python_custody_sha256"])
        parsed = custody._parse_trust_anchor(REAL_TRUST.read_bytes())
        repo = REAL_CONTROLLER.parent.parent
        custody._verify_trust_anchor_components(repo, parsed)
        with self.assertRaisesRegex(
            custody.GcloudCustodyError,
            "owner blocker: reviewed GCP custody artifact is stale",
        ):
            custody._verify_trust_anchor_components(
                repo, parsed, require_artifacts=True
            )

    def test_trust_anchor_component_inventory_is_exact_and_has_no_self_hash_cycle(self) -> None:
        trust = json.loads(REAL_TRUST.read_text(encoding="utf-8"))
        self.assertEqual(
            [(item["kind"], item["path"]) for item in trust["components"]],
            list(custody.TRUST_COMPONENTS),
        )
        self.assertNotIn(
            "tools/gcloud_custody.trust.json",
            {item["path"] for item in trust["components"]},
        )
        for name, mutate in (
            ("kind", lambda item: item["components"][0].__setitem__("kind", "artifact")),
            ("path", lambda item: item["components"][0].__setitem__("path", "tools/other.go")),
            ("digest", lambda item: item["components"][0].__setitem__("sha256", "0" * 64)),
            ("missing", lambda item: item["components"].pop()),
        ):
            with self.subTest(name=name):
                hostile = copy.deepcopy(trust)
                mutate(hostile)
                with self.assertRaises(custody.GcloudCustodyError):
                    custody._parse_trust_anchor(
                        json.dumps(hostile, sort_keys=True).encode("ascii")
                    )

    def test_production_pin_bind_requires_external_authenticated_trust_root(self) -> None:
        refusal = r"owner-blocked|(?:controller|release Python custody) digest does not match the trust-anchor|custody component digest mismatch"
        with self.assertRaisesRegex(custody.GcloudCustodyError, refusal):
            custody.validate_google_cloud_cli_pin(REAL_PINS)
        with self.assertRaisesRegex(custody.GcloudCustodyError, refusal):
            custody.authorize_repository_google_cloud_cli_pin(REAL_PINS)
        with self.assertRaisesRegex(custody.GcloudCustodyError, refusal):
            custody.verify_installed_gcloud(self.executable, pin_manifest=REAL_PINS)

    def test_caller_self_authored_synthetic_pin_is_rejected(self) -> None:
        with self.assertRaisesRegex(custody.GcloudCustodyError, "self-authored synthetic"):
            custody.validate_google_cloud_cli_pin(self.pin_path)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "self-authored synthetic"):
            custody.verify_installed_gcloud(self.executable, pin_manifest=self.pin_path)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "self-authored synthetic"):
            custody.bind_production_runner(
                object(), self.executable, self.good_credential, pin_manifest=self.pin_path
            )

    def test_duplicate_keys_and_schema_mutations_fail(self) -> None:
        base = json.dumps({"tools": {"google_cloud_cli": self.pin}})
        duplicate = base.replace('"version": "582.0.0"', '"version":"582.0.0","version":"582.0.0"')
        cases = [
            ("duplicate", duplicate.encode(), None),
            ("unstable version", None, ("version", "582.0.0-rc1")),
            ("extra key", None, ("extra", True)),
            ("bool note", None, ("note", True)),
            ("bool version", None, ("version", True)),
            ("missing platform", None, ("missing", "linux_arm64")),
            ("wrong filename", None, ("filename", "unreviewed.tar.gz")),
            ("zero hash", None, ("hash", "0" * 64)),
            ("bool hash", None, ("bool-hash", True)),
        ]
        for name, raw, mutation in cases:
            with self.subTest(name=name):
                if raw is not None:
                    payload = raw
                else:
                    pin = copy.deepcopy(self.pin)
                    assert mutation is not None
                    if mutation[0] == "missing":
                        pin["archive_name"].pop(mutation[1])
                    elif mutation[0] == "filename":
                        pin["archive_name"]["linux_amd64"] = mutation[1]
                    elif mutation[0] == "hash":
                        pin["archive_sha256"]["linux_amd64"] = mutation[1]
                    elif mutation[0] == "bool-hash":
                        pin["archive_sha256"]["linux_amd64"] = mutation[1]
                    else:
                        pin[mutation[0]] = mutation[1]
                    payload = json.dumps({"tools": {"google_cloud_cli": pin}}).encode()
                with self.assertRaises(custody.GcloudCustodyError):
                    custody.parse_google_cloud_cli_pin_document(payload)

    def test_stale_extra_bool_and_wrong_type_receipts_are_rejected(self) -> None:
        pin = custody.parse_google_cloud_cli_pin_document(self.pin_path.read_bytes())
        cases = [
            ("stale", {"version": "580.0.0"}, "stale"),
            ("extra", {"extra": "field"}, "extra keys"),
            ("bool schema", {"schema_version": True}, "wrong type"),
            ("float schema", {"schema_version": 1.0}, "wrong type"),
            ("bool tree", {"install_tree_sha256": True}, "wrong type"),
            ("int executable", {"executable_path": 1}, "wrong type"),
        ]
        for name, override, pattern in cases:
            with self.subTest(name=name):
                record = {
                    "schema_version": 1,
                    "contract": custody.RECEIPT_CONTRACT,
                    "version": self.pin["version"],
                    "platform": self.platform_key,
                    "archive_name": self.pin["archive_name"][self.platform_key],
                    "archive_sha256": self.pin["archive_sha256"][self.platform_key],
                    "install_tree_sha256": custody.install_tree_sha256(self.root),
                    "executable_path": "bin/gcloud",
                    "test_only": True,
                }
                record.update(override)
                with self.assertRaisesRegex(custody.GcloudCustodyError, pattern):
                    custody._validate_receipt(record, pin, self.platform_key, "gcloud")

    def test_python_and_go_production_receipt_schemas_are_lockstep(self) -> None:
        source = (
            Path(__file__).with_name("gcp_proof_client") / "gcloud_custody.go"
        ).read_text(encoding="utf-8")
        match = re.search(
            r"type gcloudReceipt struct \{(?P<body>.*?)\n\}", source, re.DOTALL
        )
        self.assertIsNotNone(match)
        assert match is not None
        go_keys = set(re.findall(r'`json:"([a-z0-9_]+)"`', match.group("body")))
        self.assertEqual(go_keys, custody.RECEIPT_KEYS)

    def test_valid_installation_is_bound_to_receipt_and_tree(self) -> None:
        verified = self.bind_fixture()
        self.assertEqual(verified.tree_sha256, custody.install_tree_sha256(self.root))
        self.assertEqual(verified.archive_bytes, self.archive_data)
        self.assertEqual(verified.runtime_tree_sha256, custody.install_tree_sha256(self.archive_source))
        verified.verify_unchanged()

    def test_nested_receipt_name_is_never_hash_blind(self) -> None:
        nested = self.root / "lib" / custody.RECEIPT_NAME
        nested.write_text("hostile nested receipt\n", encoding="ascii")
        nested.chmod(custody.SEALED_PUBLIC_DATA_MODE)
        with self.assertRaisesRegex(
            custody.GcloudCustodyError, "nested.*receipt"
        ):
            custody.install_tree_sha256(self.root)
        root_fd = os.open(self.root, custody._DIR_FLAGS)
        try:
            with self.assertRaisesRegex(
                custody.GcloudCustodyError, "nested.*receipt"
            ):
                custody.install_tree_sha256_from_fd(root_fd)
        finally:
            os.close(root_fd)

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
        pin = custody.parse_google_cloud_cli_pin_document(self.pin_path.read_bytes())
        with self.assertRaisesRegex(
            custody.GcloudCustodyError,
            "installation tree does not match its reviewed archive",
        ):
            custody._bind_installed_gcloud_to_authenticated_pin(
                forged_executable, pin, self.pin_path, test_only=True
            )

    def test_pathname_swapped_gcloud_never_executes_substituted_bytes(self) -> None:
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
                    target.chmod(0o700)
                    target.write_text("#!/bin/sh\nprintf 'MALICIOUS\\n'\n", encoding="ascii")
                    target.chmod(0o755)
                    support = runtime.root / "lib" / "support.txt"
                    if support.exists():
                        support.chmod(0o600)
                        support.write_text("MALICIOUS_SUPPORT\n", encoding="ascii")
                    with self.assertRaisesRegex(
                        custody.GcloudCustodyError,
                        "owner/environment blocker",
                    ) as raised:
                        runtime.run([], timeout_seconds=5)
                    self.assertNotIn("MALICIOUS", str(raised.exception))
                    self.assert_no_secret(str(raised.exception))
        self.assertEqual(spawned, [])

    def test_uf_immutable_is_not_a_genuine_runtime_boundary(self) -> None:
        path = Path(self.temporary.name) / "uf-probe"
        path.write_text("#!/bin/sh\nprintf SUBSTITUTED\\n", encoding="ascii")
        path.chmod(0o500)
        os.chflags(path, stat.UF_IMMUTABLE)
        os.chflags(path, 0)
        path.chmod(0o700)
        path.write_text("#!/bin/sh\nprintf SUBSTITUTED\\n", encoding="ascii")
        self.assertFalse(custody._same_user_cannot_replace(path))
        source = REAL_CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("UF_IMMUTABLE is insufficient", source)
        self.assertIn("SF_IMMUTABLE", source)
        self.assertIn("fclonefileat", source)
        self.assertIn("posix_spawn", source)
        self.assertIn("/proc/self/fd", source)
        self.assertIn("posix_spawn_file_actions_addfchdir_np", source)
        self.assertIn("OWNER_ISSUANCE_PATH", source)
        self.assertIn("issued_utc", source)
        self.assertIn("DOCKER_CONFIG", source)
        self.assertIn("KUBECONFIG", source)
        self.assertIn("NETRC", source)
        self.assertIn("SSH_AUTH_SOCK", source)
        self.assertNotIn("release_source_freeze", source)
        self.assertNotIn('executable="bin/gcloud"', source)
        self.assertNotIn("preexec_fn=enter_verified_root", source)

    def test_host_without_kernel_immutable_boundary_fails_closed_before_spawn(self) -> None:
        verified = self.bind_fixture()
        with verified.private_runtime(self.good_credential) as runtime:
            self.assertFalse(runtime.sealed)
            with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
                runtime.run(["version"], timeout_seconds=5)

    def test_missing_credential_is_an_owner_blocker_at_the_production_api(self) -> None:
        verified = self.bind_fixture()
        with self.assertRaisesRegex(
            custody.GcloudCustodyError,
            r"owner blocker:.*credential or workload identity",
        ):
            custody.CustodyRunner(object(), verified)
        with self.assertRaisesRegex(
            custody.GcloudCustodyError,
            r"owner blocker:.*credential or workload identity",
        ):
            custody.CustodyRunner(object(), verified, credential="not-an-input")  # type: ignore[arg-type]
        with self.assertRaisesRegex(
            custody.GcloudCustodyError,
            r"owner blocker:.*credential or workload identity",
        ):
            custody.bind_production_runner(object(), self.executable, "not-an-input")  # type: ignore[arg-type]

    def test_service_account_and_workload_identity_are_descriptor_authenticated(self) -> None:
        custody.authenticate_credential(self.good_credential)
        custody.authenticate_credential(self.workload_credential)
        wrong = self.write_credential(
            "wrong-sa.json",
            self.service_account_payload(OTHER_ACCOUNT, PROJECT),
        )
        with self.assertRaises(custody.GcloudCustodyError) as raised:
            custody.authenticate_credential(wrong)
        self.assertIn("does not match the bound identity", str(raised.exception))
        self.assert_no_secret(str(raised.exception))
        self.assertNotIn(PROJECT, str(raised.exception))

    def test_unsafe_credential_mode_is_refused(self) -> None:
        unsafe = self.write_credential(
            "unsafe-sa.json",
            self.service_account_payload(ACCOUNT, PROJECT),
            mode=0o644,
        )
        with self.assertRaisesRegex(custody.GcloudCustodyError, "immutable mode 0400"):
            custody.authenticate_credential(unsafe)

    def test_delegated_non_gcloud_executable_gets_sanitized_credential_environment(self) -> None:
        verified = self.bind_fixture()
        captured: dict[str, str] = {}

        class RecordingDelegate:
            def run(inner_self, argv, *, timeout_seconds):
                captured.update(dict(os.environ))
                captured["_argv"] = " ".join(argv)
                captured["_timeout"] = str(timeout_seconds)
                return custody.CustodyRunResult(b"ok", b"", 0)

        attacker_home = Path(self.temporary.name) / "attacker-home"
        (attacker_home / ".config" / "gcloud").mkdir(parents=True)
        (attacker_home / ".config" / "gcloud" / "application_default_credentials.json").write_text(
            '{"type":"authorized_user","refresh_token":"attacker-sentinel"}',
            encoding="ascii",
        )
        attacker_key = Path(self.temporary.name) / "attacker-sentinel.json"
        attacker_key.write_text(
            json.dumps(self.service_account_payload(OTHER_ACCOUNT, PROJECT)),
            encoding="ascii",
        )
        poisoned = {
            "HOME": str(attacker_home),
            "GOOGLE_APPLICATION_CREDENTIALS": str(attacker_key),
            "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": str(attacker_key),
            "CLOUDSDK_CONFIG": str(attacker_home / ".config" / "gcloud"),
            "PYTHONPATH": "/tmp/attacker-sentinel",
            "AWS_SECRET_ACCESS_KEY": "attacker-sentinel",
            "DOCKER_CONFIG": "/tmp/attacker-sentinel-docker",
            "KUBECONFIG": "/tmp/attacker-sentinel-kube",
            "NETRC": "/tmp/attacker-sentinel-netrc",
            "SSH_AUTH_SOCK": "/tmp/attacker-sentinel-ssh",
        }
        wrapped = custody.CustodyRunner(RecordingDelegate(), verified, self.good_credential)
        with mock.patch.dict(os.environ, poisoned, clear=False):
            result = wrapped.run(["gsutil", "ls"], timeout_seconds=5)
            self.assertEqual(os.environ["GOOGLE_APPLICATION_CREDENTIALS"], str(attacker_key))
        self.assertEqual(result.stdout, b"ok")
        self.assertEqual(captured["_argv"], "gsutil ls")
        self.assertNotEqual(captured.get("HOME"), str(attacker_home))
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", captured)
        self.assertNotIn("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", captured)
        self.assertNotIn("PYTHONPATH", captured)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", captured)
        self.assertNotIn("DOCKER_CONFIG", captured)
        self.assertNotIn("KUBECONFIG", captured)
        self.assertNotIn("NETRC", captured)
        self.assertNotIn("SSH_AUTH_SOCK", captured)
        self.assertNotIn("attacker-sentinel", captured.get("HOME", ""))
        self.assertNotIn("attacker-sentinel", captured.get("CLOUDSDK_CONFIG", ""))

    def test_gcloud_argv_does_not_fall_through_to_the_pathname_delegate(self) -> None:
        verified = self.bind_fixture()

        class PathDelegateMustNotRun:
            def run(inner_self, argv, *, timeout_seconds):
                raise AssertionError(f"pathname delegate executed: {argv!r} {timeout_seconds}")

        wrapped = custody.CustodyRunner(PathDelegateMustNotRun(), verified, self.good_credential)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
            wrapped.run([str(self.executable), "version"], timeout_seconds=5)

    def test_wrong_identity_is_refused_without_printing_values(self) -> None:
        wrong = self.write_credential(
            "wrong-sa-runtime.json",
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

    def test_python_39_is_an_honest_owner_blocker_not_a_false_green(self) -> None:
        fake = SimpleNamespace(major=3, minor=9, micro=6, releaselevel="final", serial=0)
        with mock.patch.object(sys, "version_info", fake):
            with self.assertRaisesRegex(
                custody.GcloudCustodyError,
                r"owner blocker: Python 3\.9.*false-green",
            ):
                custody.require_compatible_python()

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
                custody.extract_official_archive_bytes(
                    self.archive_data, self.archive.name, Path(self.temporary.name) / "outer"
                )

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
                custody.extract_official_archive_bytes(
                    count_bomb, "google-cloud-cli.tar.gz", Path(self.temporary.name) / "count"
                )

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

    def test_bool_trust_anchor_schema_version_is_rejected(self) -> None:
        record = json.loads(REAL_TRUST.read_text(encoding="utf-8"))
        record["schema_version"] = True
        raw = json.dumps(record).encode()
        with self.assertRaisesRegex(custody.GcloudCustodyError, "wrong type"):
            custody._parse_trust_anchor(raw)


    def test_same_uid_issuance_and_in_repo_issuance_are_owner_blocked(self) -> None:
        inside = Path(self.temporary.name) / "gcloud-owner-issuance.json"
        payload = {
            "contract": custody.OWNER_ISSUANCE_CONTRACT,
            "schema_version": 1,
            "authenticated": True,
            "issuer": custody.OWNER_ISSUANCE_ISSUER,
            "issuance_id": "a" * 32,
            "created_utc": custody._utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "controller": "tools/gcloud_custody.py",
            "controller_sha256": "a" * 64,
            "manifest": "tools/toolchain-pins.json",
            "manifest_sha256": "b" * 64,
            "trust_anchor": "tools/gcloud_custody.trust.json",
            "trust_anchor_sha256": "c" * 64,
        }
        inside.write_text(json.dumps(payload), encoding="ascii")
        os.chmod(inside, 0o444)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "owner-blocked"):
            custody._bind_owner_issuance(inside)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "owner-blocked"):
            custody._bind_owner_issuance(inside, repo=Path(self.temporary.name))
        missing = Path("/var/lib/winsvpn/gcloud-owner-issuance.json")
        with self.assertRaisesRegex(custody.GcloudCustodyError, "owner-blocked"):
            custody._bind_owner_issuance(missing)

    def test_year_2000_issuance_and_receipt_are_stale(self) -> None:
        issuance, public_key, key_id = self.signed_owner_issuance(
            issued_utc="2000-01-01T00:00:00Z"
        )
        raw = json.dumps(issuance, sort_keys=True, separators=(",", ":")).encode("ascii")
        with self.assertRaisesRegex(custody.GcloudCustodyError, "stale"):
            custody._parse_owner_issuance(
                raw, authority_key_id=key_id, public_key=public_key
            )

    def test_durable_receipt_requires_a_fresh_matching_external_issuance(self) -> None:
        issuance, _public_key, _key_id = self.signed_owner_issuance()
        durable = copy.deepcopy(issuance["receipt"])
        issued = custody._utc_now() - timedelta(hours=12)
        durable["issued_utc"] = issued.strftime("%Y-%m-%dT%H:%M:%SZ")
        durable["expires_utc"] = (issued + timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self.assertIs(
            custody._validate_signed_receipt_authorization(
                durable, require_fresh=False
            ),
            durable,
        )
        with self.assertRaisesRegex(custody.GcloudCustodyError, "stale"):
            custody._validate_signed_receipt_authorization(
                durable, require_fresh=True
            )

        fresh = copy.deepcopy(issuance["receipt"])
        fresh["issuance_id"] = "e" * 32
        custody._require_same_release_authorization(durable, fresh)
        for key in (
            "install_tree_sha256",
            "install_root_sha256",
            "controller_sha256",
            "manifest_sha256",
            "trust_anchor_sha256",
            "archive_sha256",
        ):
            with self.subTest(key=key):
                hostile = copy.deepcopy(fresh)
                hostile[key] = "f" * 64
                with self.assertRaisesRegex(
                    custody.GcloudCustodyError, "owner-blocked"
                ):
                    custody._require_same_release_authorization(
                        durable, hostile
                    )

    def test_production_receipt_reverification_retains_fresh_owner_authorization(self) -> None:
        tools = Path(self.temporary.name) / "authenticated-tools"
        tools.mkdir(mode=0o700)
        controller = tools / custody.CONTROLLER_NAME
        manifest = tools / custody.MANIFEST_NAME
        trust = tools / custody.TRUST_ANCHOR_NAME
        controller.write_bytes(REAL_CONTROLLER.read_bytes())
        manifest.write_bytes(self.pin_path.read_bytes())
        trust.write_bytes(b"authenticated-test-trust-anchor\n")

        issuance, public_key, key_id = self.signed_owner_issuance()
        fresh = copy.deepcopy(issuance["receipt"])
        fresh["controller_sha256"] = hashlib.sha256(controller.read_bytes()).hexdigest()
        fresh["manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        fresh["trust_anchor_sha256"] = hashlib.sha256(trust.read_bytes()).hexdigest()
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        _public_key, signature = sign_ed25519_for_test(
            seed, custody._owner_receipt_message(fresh)
        )
        durable = dict(fresh)
        durable["issuance_signature"] = signature.hex()
        receipt_path = self.root / custody.RECEIPT_NAME
        receipt_path.chmod(0o600)
        receipt_path.write_bytes(custody._canonical_json_bytes(durable) + b"\n")
        receipt_path.chmod(custody.SEALED_PUBLIC_DATA_MODE)

        authority = Path(self.temporary.name) / "owner-authority.json"
        authority.write_bytes(
            custody._canonical_json_bytes(
                {
                    "algorithm": custody.OWNER_SIGNATURE_ALGORITHM,
                    "contract": custody.OWNER_AUTHORITY_CONTRACT,
                    "key_id": key_id,
                    "owner_uid": os.geteuid(),
                    "public_key": public_key.hex(),
                    "schema_version": 1,
                }
            )
        )
        authority.chmod(0o400)

        issuance_path = Path(self.temporary.name) / "owner-issuance.json"
        live_issuance = dict(issuance)
        live_issuance["receipt"] = fresh
        live_issuance["signature"] = signature.hex()
        issuance_path.write_bytes(custody._canonical_json_bytes(live_issuance) + b"\n")
        issuance_path.chmod(0o400)

        pin = custody.parse_google_cloud_cli_pin_document(manifest.read_bytes())
        verified = custody._bind_installed_gcloud_to_authenticated_pin(
            self.executable,
            pin,
            manifest,
            test_only=False,
            fresh_authorization=fresh,
            authority_path=authority,
            authority_owner_uid=os.geteuid(),
            issuance_path=issuance_path,
            issuance_repo=tools,
        )
        with mock.patch.object(custody.os, "geteuid", return_value=-1):
            verified.verify_unchanged()
        without_fresh = dataclasses.replace(verified, issuance_path=None)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "owner-blocked"):
            without_fresh.verify_unchanged()

        expired = dict(fresh)
        expired_issued = custody._utc_now() - timedelta(hours=2)
        expired["issued_utc"] = expired_issued.strftime("%Y-%m-%dT%H:%M:%SZ")
        expired["expires_utc"] = (
            expired_issued + timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        expired["issuance_id"] = "e" * 32
        _public_key, expired_signature = sign_ed25519_for_test(
            seed, custody._owner_receipt_message(expired)
        )
        expired_issuance = dict(live_issuance)
        expired_issuance["receipt"] = expired
        expired_issuance["signature"] = expired_signature.hex()
        issuance_path.chmod(0o600)
        issuance_path.write_bytes(
            custody._canonical_json_bytes(expired_issuance) + b"\n"
        )
        issuance_path.chmod(0o400)
        with mock.patch.object(custody.os, "geteuid", return_value=-1):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "expired|stale"):
                verified.verify_unchanged()
        issuance_path.chmod(0o600)
        issuance_path.write_bytes(custody._canonical_json_bytes(live_issuance) + b"\n")
        issuance_path.chmod(0o400)

        original_controller = controller.read_bytes()
        controller.write_bytes(bytes([original_controller[0] ^ 1]) + original_controller[1:])
        live_hashes = (
            hashlib.sha256(controller.read_bytes()).hexdigest(),
            hashlib.sha256(manifest.read_bytes()).hexdigest(),
            hashlib.sha256(trust.read_bytes()).hexdigest(),
        )
        substituted_hashes = dataclasses.replace(
            verified, custody_hashes=live_hashes
        )
        with self.assertRaisesRegex(custody.GcloudCustodyError, "components changed"):
            substituted_hashes.verify_unchanged()
        controller.write_bytes(original_controller)

        original_manifest = manifest.read_bytes()
        parsed_manifest = json.loads(original_manifest)
        parsed_manifest["tools"]["python"]["version"] = "substituted-version"
        manifest.write_bytes(json.dumps(parsed_manifest).encode("ascii"))
        with self.assertRaisesRegex(custody.GcloudCustodyError, "components changed"):
            verified.verify_unchanged()
        manifest.write_bytes(original_manifest)

        original_trust = trust.read_bytes()
        trust.write_bytes(original_trust[:-1] + b"!")
        with self.assertRaisesRegex(custody.GcloudCustodyError, "components changed"):
            verified.verify_unchanged()
        trust.write_bytes(original_trust)
        with mock.patch.object(custody.os, "geteuid", return_value=-1):
            verified.verify_unchanged()

    def test_ed25519_rfc_vector_and_signed_issuance_mutations(self) -> None:
        public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(custody._verify_ed25519(public_key, b"", signature))
        self.assertFalse(custody._verify_ed25519(public_key, b"x", signature))

        issuance, authority_public_key, key_id = self.signed_owner_issuance()
        encoded = json.dumps(issuance, sort_keys=True, separators=(",", ":")).encode("ascii")
        parsed = custody._parse_owner_issuance(
            encoded, authority_key_id=key_id, public_key=authority_public_key
        )
        self.assertEqual(parsed["receipt"]["issuance_id"], "a" * 32)
        for name, mutate in (
            ("receipt", lambda item: item["receipt"].__setitem__("archive_sha256", "e" * 64)),
            ("key", lambda item: item.__setitem__("key_id", "f" * 64)),
            ("signature", lambda item: item.__setitem__("signature", "0" * 128)),
        ):
            with self.subTest(name=name):
                hostile = copy.deepcopy(issuance)
                mutate(hostile)
                with self.assertRaisesRegex(custody.GcloudCustodyError, "owner-blocked"):
                    custody._parse_owner_issuance(
                        json.dumps(hostile).encode("ascii"),
                        authority_key_id=key_id,
                        public_key=authority_public_key,
                    )

    def test_test_only_receipt_cannot_satisfy_production_verify(self) -> None:
        verified = self.bind_fixture()
        self.assertTrue(verified.test_only)
        pin = custody.parse_google_cloud_cli_pin_document(self.pin_path.read_bytes())
        with self.assertRaisesRegex(custody.GcloudCustodyError, "test-only"):
            custody._bind_installed_gcloud_to_authenticated_pin(
                self.executable, pin, self.pin_path, test_only=False
            )
        with self.assertRaisesRegex(
            custody.GcloudCustodyError,
            r"owner-blocked|(?:controller|release Python custody) digest does not match the trust-anchor|custody component digest mismatch",
        ):
            custody.verify_installed_gcloud(self.executable, pin_manifest=REAL_PINS)
        runner = custody.CustodyRunner(object(), verified, self.good_credential)
        self.assertTrue(runner.test_only)
        self.assertFalse(runner.production_pass_allowed())
        self.assertFalse(custody.runner_may_emit_production_pass(runner))

        class Arbitrary:
            def run(self, argv, *, timeout_seconds):
                raise AssertionError("arbitrary runner executed")

        self.assertFalse(custody.runner_may_emit_production_pass(Arbitrary()))

    def test_only_bind_production_runner_can_authorize_production_pass(self) -> None:
        verified = self.bind_fixture()
        forged_production = dataclasses.replace(verified, test_only=False)
        direct = custody.CustodyRunner(
            object(), forged_production, self.good_credential
        )
        self.assertFalse(direct.production_pass_allowed())
        self.assertFalse(custody.runner_may_emit_production_pass(direct))
        direct.test_only = False
        self.assertFalse(custody.runner_may_emit_production_pass(direct))

        with mock.patch.object(
            custody, "verify_installed_gcloud", return_value=forged_production
        ):
            bound = custody.bind_production_runner(
                object(), self.executable, self.good_credential
            )
        self.assertFalse(bound.production_pass_allowed())
        self.assertFalse(custody.runner_may_emit_production_pass(bound))

        runtime = mock.Mock()
        runtime.run.return_value = custody.CustodyRunResult(b"{}\n", b"", 0)
        private_runtime = mock.MagicMock()
        private_runtime.return_value.__enter__.return_value = runtime
        with mock.patch.object(
            custody.VerifiedGcloud, "verify_unchanged", autospec=True
        ) as live_verify:
            with mock.patch.object(
                custody.VerifiedGcloud,
                "private_runtime",
                private_runtime,
            ):
                bound.run([str(self.executable), "version"], timeout_seconds=5)
                self.assertTrue(bound.production_pass_allowed())
                self.assertTrue(custody.runner_may_emit_production_pass(bound))
        self.assertGreaterEqual(live_verify.call_count, 4)
        runtime.run.side_effect = custody.GcloudCustodyError(
            custody.EXECUTION_BLOCKER
        )
        with mock.patch.object(
            custody.VerifiedGcloud, "verify_unchanged", autospec=True
        ):
            with mock.patch.object(
                custody.VerifiedGcloud,
                "private_runtime",
                private_runtime,
            ):
                with self.assertRaises(custody.GcloudCustodyError):
                    bound.run(
                        [str(self.executable), "version"], timeout_seconds=5
                    )
        self.assertFalse(custody.runner_may_emit_production_pass(bound))
        bound.verified = verified
        self.assertFalse(custody.runner_may_emit_production_pass(bound))

    def test_nonzero_result_never_authorizes_production_pass(self) -> None:
        verified = dataclasses.replace(self.bind_fixture(), test_only=False)
        with mock.patch.object(
            custody, "verify_installed_gcloud", return_value=verified
        ):
            bound = custody.bind_production_runner(
                object(), self.executable, self.good_credential
            )
        runtime = mock.Mock()
        runtime.run.return_value = custody.CustodyRunResult(b"partial\n", b"failed\n", 9)
        private_runtime = mock.MagicMock()
        private_runtime.return_value.__enter__.return_value = runtime
        with mock.patch.object(
            custody.VerifiedGcloud, "verify_unchanged", autospec=True
        ), mock.patch.object(
            custody.VerifiedGcloud, "private_runtime", private_runtime
        ):
            result = bound.run([str(self.executable), "version"], timeout_seconds=5)
        self.assertEqual(result.exit_code, 9)
        self.assertFalse(bound.production_pass_allowed())
        self.assertFalse(custody.runner_may_emit_production_pass(bound))

    def test_eligibility_query_freshly_revalidates_and_clears_stale_attestation(self) -> None:
        verified = dataclasses.replace(self.bind_fixture(), test_only=False)
        with mock.patch.object(
            custody, "verify_installed_gcloud", return_value=verified
        ):
            bound = custody.bind_production_runner(
                object(), self.executable, self.good_credential
            )
        runtime = mock.Mock()
        runtime.run.return_value = custody.CustodyRunResult(b"{}\n", b"", 0)
        private_runtime = mock.MagicMock()
        private_runtime.return_value.__enter__.return_value = runtime
        real_authenticate = custody.authenticate_credential
        with mock.patch.object(
            custody.VerifiedGcloud, "verify_unchanged", autospec=True
        ) as live_verify, mock.patch.object(
            custody.VerifiedGcloud, "private_runtime", private_runtime
        ), mock.patch.object(
            custody,
            "authenticate_credential",
            wraps=real_authenticate,
        ) as live_credential:
            bound.run([str(self.executable), "version"], timeout_seconds=5)
            credential_calls = live_credential.call_count
            self.assertTrue(bound.production_pass_allowed())
            self.assertGreater(live_credential.call_count, credential_calls)

            for message in (
                "Google Cloud CLI fresh owner authorization is stale",
                "Google Cloud CLI custody components changed during execution",
            ):
                with self.subTest(message=message):
                    bound.run(
                        [str(self.executable), "version"], timeout_seconds=5
                    )
                    live_verify.side_effect = custody.GcloudCustodyError(message)
                    self.assertFalse(bound.production_pass_allowed())
                    live_verify.side_effect = None
                    self.assertFalse(bound.production_pass_allowed())

    def test_bound_runner_failure_never_authorizes_production_pass(self) -> None:
        verified = dataclasses.replace(self.bind_fixture(), test_only=False)
        with mock.patch.object(
            custody, "verify_installed_gcloud", return_value=verified
        ):
            bound = custody.bind_production_runner(
                object(), self.executable, self.good_credential
            )
        runtime = mock.Mock()
        runtime.run.side_effect = custody.GcloudCustodyError(custody.EXECUTION_BLOCKER)
        private_runtime = mock.MagicMock()
        private_runtime.return_value.__enter__.return_value = runtime
        with mock.patch.object(
            custody.VerifiedGcloud, "verify_unchanged", autospec=True
        ):
            with mock.patch.object(
                custody.VerifiedGcloud,
                "private_runtime",
                private_runtime,
            ):
                with self.assertRaisesRegex(
                    custody.GcloudCustodyError, "owner/environment blocker"
                ):
                    bound.run([str(self.executable), "version"], timeout_seconds=5)
        self.assertFalse(bound.production_pass_allowed())
        self.assertFalse(custody.runner_may_emit_production_pass(bound))

    def test_immutable_tree_verifier_uses_explicit_required_paths(self) -> None:
        root = Path(self.temporary.name) / "explicit-seal-root"
        identity = root / "identity"
        identity.mkdir(parents=True)
        credential = identity / "credential.json"
        credential.write_text("{}\n", encoding="ascii")
        with mock.patch.object(
            custody, "_same_user_cannot_replace", return_value=True
        ) as cannot_replace:
            self.assertTrue(
                custody._same_user_cannot_replace_tree(root, credential)
            )
        checked = {call.args[0] for call in cannot_replace.call_args_list}
        self.assertEqual(checked, {root, identity, credential})
        self.assertFalse(custody._same_user_cannot_replace_tree(root))
        self.assertFalse(
            custody._same_user_cannot_replace_tree(
                root, Path(self.temporary.name) / "outside"
            )
        )
        self.assertFalse(
            custody._same_user_cannot_replace_tree(root, identity / "missing")
        )

    def test_exact_service_account_and_wif_semantics_are_required(self) -> None:
        broken_auth = self.service_account_payload(ACCOUNT, PROJECT)
        broken_auth["auth_uri"] = "https://example.invalid/auth"
        with self.assertRaisesRegex(custody.GcloudCustodyError, "invalid"):
            custody.authenticate_credential(self.write_credential("bad-auth.json", broken_auth))
        bare_key = self.service_account_payload(ACCOUNT, PROJECT)
        bare_key["private_key"] = "TEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL"
        with self.assertRaisesRegex(custody.GcloudCustodyError, "invalid"):
            custody.authenticate_credential(self.write_credential("bare-key.json", bare_key))
        wif = self.workload_identity_payload(ACCOUNT)
        wif["token_url"] = "https://example.invalid/token"
        with self.assertRaisesRegex(custody.GcloudCustodyError, "invalid"):
            custody.authenticate_credential(self.write_credential("bad-wif.json", wif))
        wif_file = self.workload_identity_payload(ACCOUNT)
        wif_file["credential_source"] = {"file": "relative-token"}
        with self.assertRaisesRegex(custody.GcloudCustodyError, "invalid"):
            custody.authenticate_credential(self.write_credential("rel-wif.json", wif_file))

    def test_wif_subject_token_is_snapshotted_and_rewritten_to_sealed_custody(self) -> None:
        payload = self.workload_identity_payload(ACCOUNT)
        credential = self.write_credential("descriptor-wif.json", payload)
        source = Path(payload["credential_source"]["file"])  # type: ignore[index]
        authenticated = custody.authenticate_credential(credential)
        self.assertEqual(authenticated.subject_token, b"fixture-signed-subject-token\n")
        hidden = source.with_name("subject-token-original")
        source.rename(hidden)
        source.write_text("attacker-subject-token\n", encoding="ascii")
        source.chmod(0o400)

        snapshot_path = Path(self.temporary.name) / "sealed" / "bound-subject-token"
        rewritten = custody._credential_snapshot_bytes(authenticated, snapshot_path)
        parsed = json.loads(rewritten)
        self.assertEqual(parsed["credential_source"], {"file": str(snapshot_path)})
        self.assertNotIn(str(source), rewritten.decode("ascii"))

        verified = self.bind_fixture()
        with mock.patch.object(custody, "authenticate_credential", return_value=authenticated):
            with verified.private_runtime(credential) as runtime:
                self.assertIsNotNone(runtime.subject_token_file)
                assert runtime.subject_token_file is not None
                self.assertEqual(
                    runtime.subject_token_file.read_bytes(),
                    b"fixture-signed-subject-token\n",
                )
                credential_snapshot = json.loads(runtime.credential_file.read_bytes())
                self.assertEqual(
                    credential_snapshot["credential_source"]["file"],
                    str(runtime.subject_token_file),
                )

    def test_wif_subject_token_rejects_mutable_mode_and_extra_link(self) -> None:
        payload = self.workload_identity_payload(ACCOUNT)
        credential = self.write_credential("hostile-wif.json", payload)
        source = Path(payload["credential_source"]["file"])  # type: ignore[index]
        source.chmod(0o600)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "subject token.*0400"):
            custody.authenticate_credential(credential)
        source.chmod(0o400)
        extra_link = source.with_name("hostile-wif-extra-link")
        os.link(source, extra_link)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "single-link"):
            custody.authenticate_credential(credential)

    def test_controller_python_is_exactly_bound_to_manifest_path_and_digest(self) -> None:
        authenticated = custody._controller_python(self.pin_path)
        self.assertEqual(authenticated.path, Path(sys.executable).resolve(strict=True))
        self.assertEqual(hashlib.sha256(authenticated.data).hexdigest(), authenticated.sha256)
        document = json.loads(self.pin_path.read_text(encoding="utf-8"))
        document["tools"]["python"]["executable_sha256"][self.platform_key] = "e" * 64
        self.pin_path.write_text(json.dumps(document), encoding="ascii")
        with self.assertRaisesRegex(custody.GcloudCustodyError, "manifest digest"):
            custody._controller_python(self.pin_path)

    def test_cleanup_unlinks_substituted_symlink_without_following_it(self) -> None:
        sentinel = Path(self.temporary.name) / "outside-sentinel"
        sentinel.write_text("keep\n", encoding="ascii")
        tree = Path(self.temporary.name) / "runtime-tree"
        tree.mkdir()
        link = tree / "trap"
        link.symlink_to(sentinel)
        custody._destroy_runtime_tree(tree)
        self.assertTrue(sentinel.exists())
        self.assertEqual(sentinel.read_text(encoding="ascii"), "keep\n")
        self.assertFalse(tree.exists())

    def test_macos_spawn_requires_parent_bind_before_candidate_execution(self) -> None:
        source = REAL_CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("posix_spawn_file_actions_addfchdir_np", source)
        self.assertIn("root_fd", source)
        if sys.platform == "darwin":
            self.assertIsNotNone(custody._LIBC)
            self.assertTrue(hasattr(custody._LIBC, "posix_spawn_file_actions_addfchdir_np"))
        verified = self.bind_fixture()
        with verified.private_runtime(self.good_credential) as runtime:
            self.assertFalse(runtime.sealed)
            with self.assertRaisesRegex(custody.GcloudCustodyError, "owner/environment blocker"):
                runtime.run(["version"], timeout_seconds=5)

    def test_macos_command_capture_reads_held_descriptors_after_path_replacement(self) -> None:
        source = inspect.getsource(custody._posix_spawn)
        self.assertIn("posix_spawn_file_actions_adddup2", source)
        self.assertNotIn("stdout_path", source)
        self.assertNotIn("stderr_path", source)
        capture = Path(self.temporary.name) / "capture"
        descriptor = os.open(
            capture,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.write(descriptor, b"REVIEWED\n")
            capture.rename(capture.with_name("held-capture"))
            capture.write_bytes(b"MALICIOUS\n")
            self.assertEqual(custody._read_capture_fd(descriptor, "stdout"), b"REVIEWED\n")
        finally:
            os.close(descriptor)

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

    def test_ordinary_command_capture_is_kernel_held_and_bounded(self) -> None:
        def execute(source: str, *, timeout_seconds: int = 5) -> custody.CustodyRunResult:
            def spawn(
                stdin_fd: int, stdout_fd: int, stderr_fd: int
            ) -> custody._SpawnedChild:
                return custody._popen_stdio(
                    (sys.executable, "-c", source),
                    env=self.pipe_env(),
                    cwd=None,
                    stdin=stdin_fd,
                    stdout=stdout_fd,
                    stderr=stderr_fd,
                    pass_fds=(),
                    executable=sys.executable,
                )

            return custody._execute_bounded_command(
                spawn=spawn,
                timeout_seconds=timeout_seconds,
            )

        result = execute(
            "import sys; sys.stdout.buffer.write(b'OUT'); "
            "sys.stderr.buffer.write(b'ERR'); raise SystemExit(7)"
        )
        self.assertEqual(result, custody.CustodyRunResult(b"OUT", b"ERR", 7))

        limit = 4096
        with mock.patch.object(custody, "MAX_COMMAND_CAPTURE", limit):
            with self.assertRaisesRegex(custody.GcloudCustodyError, "size limit"):
                execute(
                    "import sys; sys.stdout.buffer.write(b'x' * "
                    f"{limit + 1}); sys.stdout.buffer.flush()"
                )
        with self.assertRaisesRegex(custody.GcloudCustodyError, "timeout.*invalid"):
            execute("pass", timeout_seconds=True)
        run_source = inspect.getsource(custody.PrivateGcloudRuntime.run)
        self.assertIn("_execute_bounded_command", run_source)
        self.assertNotIn("subprocess.PIPE", run_source)

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

    def test_production_runtime_root_is_exactly_tree_bound(self) -> None:
        tree = "a" * 64
        with mock.patch.object(custody, "current_platform_key", return_value="linux_amd64"):
            expected = custody._expected_production_runtime_root(tree)
            self.assertEqual(
                expected,
                Path("/var/lib/winsvpn/gcloud-runtime-v1") / tree,
            )
            for hostile in ("", "0" * 64, "A" * 64, "../" + tree):
                with self.assertRaises(custody.GcloudCustodyError):
                    custody._expected_production_runtime_root(hostile)

    def test_linux_capability_probe_rejects_ambiguous_or_hostile_status(self) -> None:
        with mock.patch.object(
            Path,
            "read_bytes",
            return_value=b"Name:\twinsproof\nCapEff:\t0000000000000200\n",
        ):
            self.assertEqual(
                custody._linux_effective_capabilities(),
                1 << custody.LINUX_CAP_IMMUTABLE,
            )
        for hostile in (
            b"",
            b"Name:\twinsproof\n",
            b"CapEff:\t0\nCapEff:\t0\n",
            b"CapEff:\tnot-hex\n",
            b"CapEff:\t00000000000000000\n",
            b"CapEff:\t0\0\n",
        ):
            with mock.patch.object(Path, "read_bytes", return_value=hostile):
                with self.assertRaises(custody.GcloudCustodyError):
                    custody._linux_effective_capabilities()

    def test_production_runtime_source_never_creates_or_seals_a_mutable_sdk_copy(self) -> None:
        source = inspect.getsource(custody.VerifiedGcloud._production_private_runtime)
        for forbidden in (
            "extract_official_archive_bytes",
            "_snapshot_tree",
            "_clone_execution_tree",
            "_kernel_seal_tree",
            "_apply_linux_immutable",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "_verify_presealed_production_runtime",
            "_write_exclusive_held",
            "credential_fd",
            "subject_token_fd",
            "production_presealed=True",
        ):
            self.assertIn(required, source)

    def test_production_tree_modes_are_nonroot_readable_and_never_writable(self) -> None:
        root = Path(self.temporary.name) / "production-mode-contract"
        root.mkdir()
        data = root / "data"
        data.write_text("fixture\n", encoding="ascii")
        executable = root / "executable"
        executable.write_text("#!/bin/sh\n", encoding="ascii")

        root.chmod(custody.SEALED_PUBLIC_DIR_MODE)
        data.chmod(custody.SEALED_PUBLIC_DATA_MODE)
        executable.chmod(custody.SEALED_PUBLIC_EXEC_MODE)
        self.assertTrue(custody._production_public_mode_allowed(root.lstat()))
        self.assertTrue(custody._production_public_mode_allowed(data.lstat()))
        self.assertTrue(custody._production_public_mode_allowed(executable.lstat()))

        for path, hostile_modes in (
            (root, (0o500, 0o755, 0o777)),
            (data, (0o400, 0o600, 0o644, 0o666)),
            (executable, (0o500, 0o700, 0o755, 0o777)),
        ):
            for hostile_mode in hostile_modes:
                with self.subTest(path=path.name, mode=oct(hostile_mode)):
                    path.chmod(hostile_mode)
                    self.assertFalse(
                        custody._production_public_mode_allowed(path.lstat())
                    )

    def test_private_runtime_environment_uses_held_identity_descriptors(self) -> None:
        verified = self.bind_fixture()
        with verified.private_runtime(self.good_credential) as runtime:
            linux_runtime = dataclasses.replace(runtime, production_presealed=True)
            with mock.patch.object(sys, "platform", "linux"):
                linux_env = linux_runtime._environment()
            self.assertEqual(
                linux_env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"],
                f"/proc/self/fd/{runtime.credential_fd}",
            )
            self.assertEqual(
                linux_env["CLOUDSDK_ROOT_DIR"],
                f"/proc/self/fd/{runtime.root_fd}",
            )
            self.assertEqual(
                linux_env["CLOUDSDK_PYTHON"],
                f"/proc/self/fd/{runtime.root_fd}/{custody.LINUX_BUNDLED_PYTHON_RELATIVE}",
            )
            with mock.patch.object(sys, "platform", "darwin"):
                darwin_env = linux_runtime._environment()
            self.assertEqual(
                darwin_env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"],
                f"/dev/fd/{custody.DARWIN_CREDENTIAL_CHILD_FD}",
            )

    def test_held_credential_cleanup_does_not_overwrite_swapped_path(self) -> None:
        directory = Path(self.temporary.name) / "held-cleanup"
        directory.mkdir()
        original = directory / "credential.json"
        original.write_bytes(b"S" * 64)
        fd = os.open(original, os.O_RDWR | os.O_CLOEXEC)
        hidden = directory / "credential.original"
        victim = directory / "victim.json"
        victim.write_bytes(b"V" * 64)
        os.rename(original, hidden)
        os.rename(victim, original)
        try:
            custody._secure_unlink_held(fd, original, max_size=64)
            self.assertEqual(original.read_bytes(), b"V" * 64)
            self.assertEqual(hidden.read_bytes(), b"\0" * 64)
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
