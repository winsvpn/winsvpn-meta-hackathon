#!/usr/bin/env python3
"""Adversarial fixture tests for release Go archive custody.

importlib loading of the controller is a unit-test seam only. Production
execution binds controller bytes through isolated authenticated Python
custody and stdin; it never executes the controller path before
authorization.
"""

from __future__ import annotations

import datetime as dt
import base64
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
from types import SimpleNamespace
import unicodedata
import unittest
from unittest import mock
import ctypes


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "release_go_archive_custody.py"
SHELL = ROOT / "tools" / "release_go_archive_custody.sh"
PROVISIONER = ROOT / "tools" / "provision_macos_release_go_runtime.sh"
PIN_MANIFEST = ROOT / "tools" / "toolchain-pins.json"
TRUST_ANCHOR = ROOT / "tools" / "release_go_archive_custody.trust.json"
VERSION = "1.25.0"
REAL_VERSION = "1.27.1"
TOP = "go"
REAL_ARCHIVE = Path("/Users/owner/Downloads") / f"go{REAL_VERSION}.darwin-arm64.tar.gz"
REAL_ARCHIVE_SHA256 = "ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12"
REAL_ARCHIVE_SIZE = 68_100_347
REAL_TREE_SHA256 = "f8de74060cc6cfa4a52c3768a6999c0eb4119dec0281d75d225d44a35a2975ac"
REAL_BINARY_SHA256 = "132b69336a1f809932a8a20b0201dbbb980e86e3a323ae32e893639d83d71598"

SPEC = importlib.util.spec_from_file_location("release_go_archive_custody", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release Go custody module")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def production_trust_delta() -> bool:
    trust = json.loads(TRUST_ANCHOR.read_text(encoding="ascii"))
    return (
        trust.get("controller_sha256") != file_sha256(TOOL)
        or trust.get("wrapper_sha256") != file_sha256(SHELL)
    )


def synthetic_owner_fixture_xattr_patch(
    fixture: Path,
) -> contextlib.AbstractContextManager[object]:
    """Mask only runner-injected provenance inside one disposable fixture."""
    private_tmp = MODULE._private_tmp().resolve(strict=True)
    if fixture.is_symlink():
        raise AssertionError("owner fixture metadata seam found a symlink")
    resolved_fixture = fixture.resolve(strict=True)
    try:
        relative = resolved_fixture.relative_to(private_tmp)
    except ValueError as exc:
        raise AssertionError("owner fixture metadata seam escaped private tmp") from exc
    if not relative.parts or not relative.parts[0].startswith("wins-go-owner-fixture."):
        raise AssertionError("owner fixture metadata seam has the wrong prefix")
    real_xattr_names = MODULE._xattr_names

    def normalized_xattr_names(path: Path) -> list[bytes]:
        names = real_xattr_names(path)
        if path.is_symlink():
            return names
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(resolved_fixture)
        except (FileNotFoundError, RuntimeError, ValueError):
            return names
        return [name for name in names if name != b"com.apple.provenance"]

    return mock.patch.object(MODULE, "_xattr_names", side_effect=normalized_xattr_names)


def issuance_parent() -> Path:
    private = Path("/private/tmp") if sys.platform == "darwin" else Path("/var/tmp")
    return Path(tempfile.mkdtemp(prefix="wins-go-issuance.", dir=str(private)))


TEST_AUTHORITIES: dict[Path, Path] = {}


def _generate_test_authority(directory: Path, issuance_id: str, sequence: int) -> tuple[Path, Path]:
    private_key = directory / "fixture-authority-private.pem"
    public_key = directory / "fixture-authority-public.pem"
    generated = subprocess.run(
        ["/usr/bin/openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    if generated.returncode != 0:
        raise AssertionError(generated.stderr.decode("utf-8", "replace"))
    private_key.write_bytes(generated.stdout)
    private_key.chmod(0o600)
    exported = subprocess.run(
        ["/usr/bin/openssl", "ec", "-pubout", "-in", str(private_key)],
        capture_output=True,
        timeout=10,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "OPENSSL_CONF": "/dev/null"},
    )
    if exported.returncode != 0:
        raise AssertionError(exported.stderr.decode("utf-8", "replace"))
    public_key.write_bytes(exported.stdout)
    public_key.chmod(0o444)
    authority_prefix = directory / "authority" / "v1"
    authority_prefix.mkdir(parents=True)
    public_bytes = public_key.read_bytes()
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    authority = {
        "contract": MODULE.AUTHORITY_CONTRACT,
        "schema_version": 1,
        "key_id": hashlib.sha256(public_bytes).hexdigest(),
        "signature_algorithm": MODULE.SIGNATURE_ALGORITHM,
        "public_key_pem_base64": base64.b64encode(public_bytes).decode("ascii"),
        "active_issuance_id": issuance_id,
        "active_sequence": sequence,
        "not_before_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    authority_path = authority_prefix / "authority.json"
    authority_path.write_bytes(MODULE._canonical_json_bytes(authority))
    authority_path.chmod(0o444)
    authority_prefix.chmod(0o555)
    authority_prefix.parent.chmod(0o555)
    return private_key, authority_path


@contextlib.contextmanager
def issuance_authority(issuance: Path):
    authority_path = TEST_AUTHORITIES[issuance]
    with (
        mock.patch.object(MODULE, "OWNER_AUTHORITY_PREFIX", authority_path.parent),
        mock.patch.object(MODULE, "OWNER_AUTHORITY_PATH", authority_path),
        mock.patch.object(
            MODULE,
            "_verify_authority_path",
            return_value=authority_path.read_bytes(),
        ),
    ):
        yield


def write_issuance(
    directory: Path,
    *,
    controller: Path = TOOL,
    wrapper: Path = SHELL,
    provisioner: Path = PROVISIONER,
    manifest: Path = PIN_MANIFEST,
    trust: Path = TRUST_ANCHOR,
    freeze: Path | None = None,
    **overrides: object,
) -> Path:
    freeze = freeze or (ROOT / "tools" / "release_source_freeze.py")
    now = dt.datetime.now(dt.timezone.utc)
    created = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = (now + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    issuance_id = str(overrides.pop("issuance_id", "a" * 32))
    sequence = int(overrides.pop("sequence", 1))
    private_key, authority_path = _generate_test_authority(
        directory, issuance_id, sequence
    )
    authority = json.loads(authority_path.read_text(encoding="ascii"))
    payload: dict[str, object] = {
        "contract": MODULE.ISSUANCE_CONTRACT,
        "schema_version": 2,
        "issuance_id": issuance_id,
        "sequence": sequence,
        "created_utc": created,
        "expires_utc": expires,
        "issuer": "winsvpn-go-archive-custody",
        "authority_key_id": authority["key_id"],
        "signature_algorithm": MODULE.SIGNATURE_ALGORITHM,
        "controller": "tools/release_go_archive_custody.py",
        "wrapper": "tools/release_go_archive_custody.sh",
        "provisioner": "tools/provision_macos_release_go_runtime.sh",
        "manifest": "tools/toolchain-pins.json",
        "trust_anchor": "tools/release_go_archive_custody.trust.json",
        "source_freeze_producer": "tools/release_source_freeze.py",
        "controller_sha256": file_sha256(controller),
        "wrapper_sha256": file_sha256(wrapper),
        "provisioner_sha256": file_sha256(provisioner),
        "manifest_sha256": file_sha256(manifest),
        "trust_anchor_sha256": file_sha256(trust),
        "source_freeze_producer_sha256": file_sha256(freeze),
    }
    payload.update(overrides)
    signed = MODULE._canonical_json_bytes(payload)
    signature_path = directory / "fixture-issuance.sig"
    signed_result = subprocess.run(
        [
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(private_key),
            "-out",
            str(signature_path),
        ],
        input=signed,
        capture_output=True,
        timeout=10,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "OPENSSL_CONF": "/dev/null"},
    )
    if signed_result.returncode != 0:
        raise AssertionError(signed_result.stderr.decode("utf-8", "replace"))
    payload["signature_base64"] = base64.b64encode(signature_path.read_bytes()).decode(
        "ascii"
    )
    path = directory / "go-custody-issuance.json"
    if path.exists() or path.is_symlink():
        path.unlink()
    path.write_bytes(MODULE._canonical_json_bytes(payload))
    path.chmod(0o444)
    TEST_AUTHORITIES[path] = authority_path
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_fields(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("|")
        if not separator or key in result:
            raise AssertionError(f"malformed custody output: {line!r}")
        result[key] = value
    return result


def pax_record(path: str) -> bytes:
    body = f"path={path}\n".encode("utf-8")
    for width in range(1, 5):
        length = width + 1 + len(body)
        encoded = str(length).encode("ascii")
        if len(encoded) == width:
            return encoded + b" " + body
    raise AssertionError(f"PAX path is too long: {path}")


def real_archive_ready() -> bool:
    try:
        MODULE.require_safe_input(REAL_ARCHIVE, f"go{REAL_VERSION}.darwin-arm64.tar.gz")
    except (MODULE.Refused, FileNotFoundError):
        # An absent operator download is "unavailable", not a failure; a
        # present archive that is unsafe or wrong still refuses or fails below.
        return False
    info = REAL_ARCHIVE.lstat()
    return (
        info.st_size == REAL_ARCHIVE_SIZE
        and MODULE.digest_file(REAL_ARCHIVE) == REAL_ARCHIVE_SHA256
    )


@unittest.skipUnless(sys.platform == "darwin", "macOS arm64 Go custody target required")
class ReleaseGoArchiveCustodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if subprocess.run(["/usr/bin/uname", "-m"], capture_output=True, text=True).stdout.strip() != "arm64":
            raise unittest.SkipTest("arm64 host required")
        cls.base = Path(tempfile.mkdtemp(prefix="wins-go-custody-test.", dir="/private/tmp"))
        cls.base.chmod(0o700)
        cls.inputs = cls.base / "inputs"
        cls.inputs.mkdir(mode=0o700)
        cls.go = cls._compile_go_fixture()
        cls.archive = cls.inputs / f"go{VERSION}.darwin-arm64.tar.gz"
        cls._write_archive(cls.archive, cls._normal_entries())
        cls.archive.chmod(0o444)
        cls.reference = cls.base / "reference" / TOP
        cls._write_reference_tree(cls.reference)
        cls.tree_sha = MODULE.tree_hash(cls.reference)
        cls.go_sha = sha256(cls.go)

    @classmethod
    def tearDownClass(cls) -> None:
        for path in cls.base.rglob("*"):
            if not path.is_symlink():
                try:
                    path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
                except FileNotFoundError:
                    pass
        shutil.rmtree(cls.base, ignore_errors=True)

    @classmethod
    def _compile_go_fixture(cls) -> Path:
        source = cls.base / "go-fixture.c"
        binary = cls.base / "go"
        source.write_text(
            textwrap.dedent(
                """
                #include <stdio.h>
                #include <stdlib.h>
                #include <string.h>
                #include <sys/stat.h>

                int main(int argc, char **argv) {
                  if (argc == 2 && strcmp(argv[1], "version") == 0) {
                    puts("go version go1.25.0 darwin/arm64");
                    return 0;
                  }
                  if (argc == 3 && strcmp(argv[1], "env") == 0) {
                    if (strcmp(argv[2], "GOVERSION") == 0) {
                      puts("go1.25.0");
                      return 0;
                    }
                    if (strcmp(argv[2], "GOHOSTOS") == 0) {
                      puts("darwin");
                      return 0;
                    }
                    if (strcmp(argv[2], "GOHOSTARCH") == 0) {
                      puts("arm64");
                      return 0;
                    }
                    if (strcmp(argv[2], "GOTOOLCHAIN") == 0) {
                      const char *value = getenv("GOTOOLCHAIN");
                      if (!value) return 80;
                      puts(value);
                      return 0;
                    }
                    return 81;
                  }
                  if (argc == 2 && strcmp(argv[1], "--probe-env") == 0) {
                    const char *home = getenv("HOME");
                    const char *tmp = getenv("TMPDIR");
                    const char *path = getenv("PATH");
                    const char *toolchain = getenv("GOTOOLCHAIN");
                    const char *goenv = getenv("GOENV");
                    if (getenv("ATTACKER") || getenv("GOPATH") ||
                        getenv("GOFLAGS") || getenv("GO111MODULE")) return 71;
                    if (!home || !tmp || !path || !toolchain || !goenv) return 72;
                    if (strstr(home, "/private/tmp/wins-release-go.") != home) return 73;
                    if (strstr(tmp, "/private/tmp/wins-release-go.") != tmp) return 74;
                    if (strcmp(toolchain, "local") != 0) return 82;
                    if (strcmp(goenv, "off") != 0) return 83;
                    const char *goroot = getenv("GOROOT");
                    if (!goroot || strstr(goroot, "/private/tmp/wins-release-go.") != goroot) return 84;
                    if (strstr(goroot, "/exec/tree") == NULL) return 85;
                    puts("clean-go-env");
                    return 0;
                  }
                  if (argc == 2 && strcmp(argv[1], "--mutate-self") == 0) {
                    if (chmod(argv[0], 0700) != 0) return 75;
                    FILE *stream = fopen(argv[0], "ab");
                    if (!stream) return 76;
                    if (fputc(1, stream) == EOF || fclose(stream) != 0) return 77;
                    if (chmod(argv[0], 0500) != 0) return 78;
                    return 0;
                  }
                  if (argc == 2 && strcmp(argv[1], "--mutate-restore-goroot") == 0) {
                    const char *goroot = getenv("GOROOT");
                    if (!goroot) return 86;
                    char target[1024];
                    if (snprintf(target, sizeof target, "%s/src/LICENSE", goroot) >= (int)sizeof target) return 86;
                    if (chmod(target, 0600) != 0) return 87;
                    FILE *stream = fopen(target, "ab");
                    if (!stream) return 88;
                    if (fputc('X', stream) == EOF || fclose(stream) != 0) return 89;
                    if (chmod(target, 0400) != 0) return 90;
                    return 0;
                  }
                  return 79;
                }
                """
            ).lstrip(),
            encoding="ascii",
        )
        subprocess.run(
            ["/usr/bin/clang", "-Os", "-arch", "arm64", "-o", str(binary), str(source)],
            check=True,
            capture_output=True,
            text=True,
        )
        return binary

    @classmethod
    def _normal_entries(cls) -> list[tuple[str, str, bytes | str]]:
        return [
            (TOP, "dir", b""),
            (f"{TOP}/bin", "dir", b""),
            (f"{TOP}/src", "dir", b""),
            (f"{TOP}/bin/go", "file", cls.go.read_bytes()),
            (f"{TOP}/src/LICENSE", "file", b"synthetic fixture only\n"),
            (f"{TOP}/src/helper.sh", "file", b"echo fixture\n"),
            (f"{TOP}/bin/gofmt", "symlink", "../src/helper.sh"),
        ]

    @classmethod
    def _write_archive(
        cls, path: Path, entries: list[tuple[str, str, bytes | str]]
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as bundle:
            for name, kind, payload in entries:
                member = tarfile.TarInfo(name)
                member.uid = 0
                member.gid = 0
                member.uname = "root"
                member.gname = "wheel"
                member.mtime = 0
                if kind == "dir":
                    member.type = tarfile.DIRTYPE
                    member.mode = 0o755
                    bundle.addfile(member)
                elif kind == "file":
                    data = bytes(payload)
                    member.type = tarfile.REGTYPE
                    member.mode = 0o755 if name == f"{TOP}/bin/go" else 0o644
                    member.size = len(data)
                    bundle.addfile(member, io.BytesIO(data))
                elif kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = str(payload)
                    bundle.addfile(member)
                elif kind == "hardlink":
                    member.type = tarfile.LNKTYPE
                    member.linkname = str(payload)
                    bundle.addfile(member)
                elif kind == "fifo":
                    member.type = tarfile.FIFOTYPE
                    member.mode = 0o644
                    bundle.addfile(member)
                elif kind == "pax":
                    data = bytes(payload)
                    member.type = tarfile.XHDTYPE
                    member.mode = 0o644
                    member.size = len(data)
                    bundle.addfile(member, io.BytesIO(data))
                elif kind == "pax-global":
                    data = bytes(payload)
                    member.type = tarfile.XGLTYPE
                    member.mode = 0o644
                    member.size = len(data)
                    bundle.addfile(member, io.BytesIO(data))
                else:
                    raise AssertionError(f"unknown fixture kind: {kind}")

    @classmethod
    def _write_reference_tree(cls, root: Path) -> None:
        (root / "bin").mkdir(parents=True)
        (root / "src").mkdir()
        shutil.copyfile(cls.go, root / "bin/go")
        (root / "src/LICENSE").write_bytes(b"synthetic fixture only\n")
        (root / "src/helper.sh").write_bytes(b"echo fixture\n")
        (root / "bin/gofmt").symlink_to("../src/helper.sh")
        (root / "bin/go").chmod(0o500)
        (root / "src/LICENSE").chmod(0o400)
        (root / "src/helper.sh").chmod(0o400)
        (root / "bin").chmod(0o500)
        (root / "src").chmod(0o500)
        root.chmod(0o500)

    def setUp(self) -> None:
        self.case = Path(tempfile.mkdtemp(prefix="case.", dir=self.base))
        self.case.chmod(0o700)

    def tearDown(self) -> None:
        for path in self.case.rglob("*"):
            if not path.is_symlink():
                try:
                    path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
                except FileNotFoundError:
                    pass
        shutil.rmtree(self.case, ignore_errors=True)

    def _copy_archive(self, name: str | None = None) -> Path:
        destination = self.case / (name or self.archive.name)
        shutil.copyfile(self.archive, destination)
        destination.chmod(0o444)
        return destination

    def _go_object(
        self,
        archive: Path | None = None,
        *,
        archive_sha: str | None = None,
        tree_sha: str | None = None,
        binary_sha: str | None = None,
        archive_format: str = "tar.gz",
        version: str = VERSION,
        extra: dict[str, object] | None = None,
    ) -> dict[str, object]:
        archive = archive or self.archive
        darwin = archive_sha or sha256(archive)
        go: dict[str, object] = {
            "version": version,
            "platform": "darwin-arm64",
            "architecture": "arm64",
            "archive_format": archive_format,
            "archive_path": {"darwin_arm64": str(archive)},
            "archive_sha256": {
                "darwin_amd64": "d" * 64,
                "darwin_arm64": darwin,
                "linux_amd64": "a" * 64,
                "linux_arm64": "b" * 64,
                "windows_amd64": "c" * 64,
                "windows_arm64": "e" * 64,
            },
            "install_tree_sha256": {"darwin_arm64": tree_sha or self.tree_sha},
            "top_level_root": TOP,
            "executable": "bin/go",
            "executable_sha256": binary_sha or self.go_sha,
            "review_status": "upgrade_validation_in_progress",
            "note": "synthetic fixture pin",
            "compatibility_note": "fixture only",
        }
        if extra:
            go.update(extra)
        return go

    def _manifest(
        self,
        archive: Path | None = None,
        *,
        archive_sha: str | None = None,
        tree_sha: str | None = None,
        binary_sha: str | None = None,
        archive_format: str = "tar.gz",
        version: str = VERSION,
        extra: dict[str, object] | None = None,
    ) -> Path:
        data = {"tools": {"go": self._go_object(
            archive,
            archive_sha=archive_sha,
            tree_sha=tree_sha,
            binary_sha=binary_sha,
            archive_format=archive_format,
            version=version,
            extra=extra,
        )}}
        manifest = self.case / "pins.json"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        manifest.chmod(0o600)
        return manifest

    def _cli(
        self,
        *arguments: str,
        env: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def _install(self, manifest: Path) -> dict[str, str]:
        pin = MODULE.parse_pin_bytes(manifest.read_bytes())
        fields = MODULE.install_extracted_runtime(pin)
        self.addCleanup(self._cleanup_if_present, fields)
        return fields

    def _verification(self, fields: dict[str, str]) -> list[str]:
        return [
            fields["RUNTIME"],
            fields["RUNTIME_ID"],
            fields["ROOT"],
            fields["TREE_SHA256"],
            fields["BINARY"],
            fields["BINARY_SHA256"],
        ]

    def _cleanup_if_present(self, fields: dict[str, str]) -> None:
        runtime = Path(fields["RUNTIME"])
        if runtime.exists() and not runtime.is_symlink():
            self._cli("cleanup", fields["RUNTIME"], fields["RUNTIME_ID"])

    def test_prepare_verify_run_and_cleanup(self) -> None:
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        verified = self._cli("verify", *self._verification(fields))
        self.assertEqual(verified.returncode, 0, verified.stderr)
        ran = self._cli("run", *self._verification(fields), "--", "--probe-env")
        self.assertNotEqual(ran.returncode, 0)
        self.assertIn("private Darwin Go execution is refused", ran.stderr)
        self.assertNotIn("clean-go-env", ran.stdout)
        missing = self._cli("run", *self._verification(fields))
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("argument separator", missing.stderr)
        prepared = self._cli("prepare", str(ROOT), str(self._manifest(archive)))
        self.assertNotEqual(prepared.returncode, 0)
        self.assertIn("cannot self-authorize", prepared.stderr)
        self.assertNotIn("RUNTIME|", prepared.stdout)
        malformed = self._cli("prepare", str(self._manifest(archive)))
        self.assertNotEqual(malformed.returncode, 0)
        self.assertIn("malformed", malformed.stderr)
        cleaned = self._cli("cleanup", fields["RUNTIME"], fields["RUNTIME_ID"])
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertFalse(Path(fields["RUNTIME"]).exists())

    def test_shell_wrapper_rejects_malicious_controller(self) -> None:
        archive = self._copy_archive()
        manifest = self._manifest(archive)
        controller = self.case / "controller.py"
        shutil.copyfile(TOOL, controller)
        controller.chmod(0o600)
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex.quote(str(SHELL))}
            wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
            wins_release_go_prepare {shlex.quote(str(controller))} {shlex.quote(str(manifest))}
            """
        )
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("malicious or substituted Go custody controller rejected", completed.stderr)
        self.assertNotIn("clean-go-env", completed.stdout)
        self.assertNotIn("RUNTIME|", completed.stdout)

    def test_shell_wrapper_rejects_replacement_manifest(self) -> None:
        archive = self._copy_archive()
        manifest = self._manifest(archive)
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex.quote(str(SHELL))}
            wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
            wins_release_go_prepare {shlex.quote(str(TOOL))} {shlex.quote(str(manifest))}
            """
        )
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot self-authorize", completed.stderr)
        self.assertNotIn("RUNTIME|", completed.stdout)

    def test_shell_requires_authenticated_python_function(self) -> None:
        script = f"source {shlex.quote(str(SHELL))}; _wins_rg_python verify"
        completed = subprocess.run(
            ["/bin/bash", "-c", script], capture_output=True, text=True
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("authenticated release Python custody is required", completed.stderr)

    def test_shell_run_requires_prepared_runtime(self) -> None:
        script = textwrap.dedent(
            f"""
            source {shlex.quote(str(SHELL))}
            wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
            wins_release_go_run version
            """
        )
        completed = subprocess.run(
            ["/bin/bash", "-c", script], capture_output=True, text=True
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Go custody is not prepared", completed.stderr)

    def test_safe_relative_symlink_is_authenticated(self) -> None:
        destination = self.case / "expanded-safe-link"
        root = MODULE.safe_extract(self.archive, destination, TOP)
        link = root / "bin/gofmt"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "../src/helper.sh")
        self.assertEqual(MODULE.tree_hash(root), self.tree_sha)

    def test_pax_path_is_authenticated(self) -> None:
        archive = self.case / "pax.tar.gz"
        thorn = f"{TOP}/src/\u00defile.go"
        entries = self._normal_entries()
        entries.extend(
            [
                (f"{TOP}/src/PaxHeaders.0/file.go", "pax", pax_record(thorn)),
                (f"{TOP}/src/file.go", "file", b"package pax\n"),
            ]
        )
        self._write_archive(archive, entries)
        root = MODULE.safe_extract(archive, self.case / "expanded-pax", TOP)
        self.assertTrue((root / "src/\u00defile.go").is_file())
        self.assertFalse((root / "src/file.go").exists())
        self.assertEqual((root / "src/\u00defile.go").read_bytes(), b"package pax\n")

    def test_escaping_symlink_hardlink_and_specials_are_rejected(self) -> None:
        cases = (
            ("absolute-symlink", "symlink", "/private/tmp/attacker"),
            ("escaping-symlink", "symlink", "../../attacker"),
            ("hardlink", "hardlink", "bin/go"),
            ("fifo", "fifo", b""),
            ("pax-global", "pax-global", pax_record(f"{TOP}/src/evil.go")),
        )
        for label, kind, target in cases:
            with self.subTest(label=label):
                archive = self.case / f"{label}.tar.gz"
                entries = self._normal_entries()
                entries.append((f"{TOP}/unsafe-{label}", kind, target))
                self._write_archive(archive, entries)
                with self.assertRaises(MODULE.Refused):
                    MODULE.safe_extract(archive, self.case / f"expanded-{label}", TOP)

    def test_path_traversal_duplicate_and_case_collision_are_rejected(self) -> None:
        cases = {
            "traversal": self._normal_entries() + [(f"{TOP}/../escape", "file", b"x")],
            "collision": self._normal_entries()
            + [(f"{TOP}/Readme", "file", b"a"), (f"{TOP}/README", "file", b"b")],
        }
        for label, entries in cases.items():
            with self.subTest(label=label):
                archive = self.case / f"{label}.tar.gz"
                self._write_archive(archive, entries)
                with self.assertRaises(MODULE.Refused):
                    MODULE.safe_extract(archive, self.case / f"expanded-{label}", TOP)
        duplicate = self.case / "duplicate.tar.gz"
        entries = self._normal_entries() + [(f"{TOP}/src/LICENSE", "file", b"second\n")]
        self._write_archive(duplicate, entries)
        with self.assertRaisesRegex(MODULE.Refused, "duplicate"):
            MODULE.safe_extract(duplicate, self.case / "expanded-duplicate", TOP)

    def test_unicode_and_depth_are_rejected(self) -> None:
        nfd = unicodedata.normalize("NFD", "cafe\u0301")
        archive = self.case / "unicode.tar.gz"
        self._write_archive(
            archive,
            self._normal_entries() + [(f"{TOP}/src/{nfd}", "file", b"x")],
        )
        with self.assertRaisesRegex(MODULE.Refused, "non-canonical"):
            MODULE.safe_extract(archive, self.case / "expanded-unicode", TOP)
        deep = self.case / "deep.tar.gz"
        deep_name = "/".join([TOP, *(["deep"] * 32)])
        self._write_archive(deep, [(TOP, "dir", b""), (deep_name, "file", b"x")])
        with self.assertRaisesRegex(MODULE.Refused, "depth"):
            MODULE.safe_extract(deep, self.case / "expanded-deep", TOP)

    def test_gzip_trailing_data_and_nonzero_tar_trailer_are_rejected(self) -> None:
        trailing = self.case / "trailing.tar.gz"
        shutil.copyfile(self.archive, trailing)
        with trailing.open("ab") as stream:
            stream.write(b"archive-comment")
        with self.assertRaisesRegex(MODULE.Refused, "trailing data"):
            MODULE.safe_extract(trailing, self.case / "expanded-trailing", TOP)

        raw = bytearray()
        with gzip.open(self.archive, "rb") as stream:
            raw.extend(stream.read())
        raw[-1] = 1
        nonzero = self.case / "nonzero.tar.gz"
        with nonzero.open("wb") as output, gzip.GzipFile(
            filename="", mode="wb", fileobj=output, mtime=0
        ) as compressed:
            compressed.write(bytes(raw))
        with self.assertRaisesRegex(MODULE.Refused, "trailer|trailing"):
            MODULE.safe_extract(nonzero, self.case / "expanded-nonzero", TOP)

        concatenated = self.case / "concatenated.tar.gz"
        shutil.copyfile(self.archive, concatenated)
        with concatenated.open("ab") as stream, gzip.GzipFile(
            filename="", mode="wb", fileobj=stream, mtime=0
        ) as extra:
            extra.write(b"second-member")
        with self.assertRaisesRegex(MODULE.Refused, "concatenated|trailing"):
            MODULE.safe_extract(concatenated, self.case / "expanded-concatenated", TOP)

    def test_gzip_comment_flag_is_rejected(self) -> None:
        mutated = self.case / "comment-flag.tar.gz"
        payload = bytearray(self.archive.read_bytes())
        payload[3] |= 0x10
        mutated.write_bytes(payload)
        with self.assertRaisesRegex(MODULE.Refused, "comments"):
            MODULE.safe_extract(mutated, self.case / "expanded-comment-flag", TOP)

    def test_zip_bomb_equivalent_limits_are_fail_closed(self) -> None:
        archive = self.case / "size-limit.tar.gz"
        self._write_archive(archive, self._normal_entries())
        with mock.patch.object(MODULE, "MAX_MEMBER", 8):
            with self.assertRaisesRegex(MODULE.Refused, "member exceeds"):
                MODULE.safe_extract(archive, self.case / "expanded-size", TOP)
        with mock.patch.object(MODULE, "MAX_EXPANDED", 8):
            with self.assertRaisesRegex(MODULE.Refused, "expansion limit"):
                MODULE.safe_extract(archive, self.case / "expanded-gzip", TOP)
        zeros = self.case / "ratio.tar.gz"
        self._write_archive(
            zeros,
            [
                (TOP, "dir", b""),
                (f"{TOP}/zeros", "file", b"\0" * 4096),
            ],
        )
        with mock.patch.object(MODULE, "MAX_RATIO", 1):
            with self.assertRaisesRegex(MODULE.Refused, "expansion limit"):
                MODULE.safe_extract(zeros, self.case / "expanded-ratio", TOP)
        with mock.patch.object(MODULE, "MAX_MEMBERS", 1):
            with self.assertRaisesRegex(MODULE.Refused, "member-count"):
                MODULE.safe_extract(self.archive, self.case / "expanded-count", TOP)

    def test_writable_and_hardlinked_input_archives_are_rejected(self) -> None:
        writable = self._copy_archive()
        writable.chmod(0o644)
        with self.assertRaisesRegex(MODULE.Refused, "mode 0444"):
            MODULE.require_safe_input(writable, writable.name)
        hardlink = self.case / "hardlink.tar.gz"
        os.link(self.archive, hardlink)
        with self.assertRaisesRegex(MODULE.Refused, "one owner-controlled"):
            MODULE.require_safe_input(hardlink, hardlink.name)
        aliased = self.case / f"go{VERSION}.darwin-arm64-alias.tar.gz"
        aliased.symlink_to(self.archive)
        with self.assertRaises(MODULE.Refused):
            MODULE.require_safe_input(aliased, aliased.name)
        unversioned = self._copy_archive("go.tar.gz")
        with self.assertRaisesRegex(MODULE.Refused, "basename"):
            MODULE.require_safe_input(unversioned, f"go{VERSION}.darwin-arm64.tar.gz")

    def test_wrong_archive_tree_and_binary_hashes_fail_closed(self) -> None:
        archive = self._copy_archive()
        cases = (
            {"archive_sha": "0" * 64},
            {"tree_sha": "1" * 64},
            {"binary_sha": "2" * 64},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                pin = MODULE.parse_pin_bytes(self._manifest(archive, **overrides).read_bytes())
                with self.assertRaises(MODULE.Refused):
                    MODULE.install_extracted_runtime(pin)

    def test_zip_format_and_duplicate_manifest_keys_are_rejected(self) -> None:
        archive = self._copy_archive()
        manifest = self._manifest(archive, archive_format="zip")
        with self.assertRaisesRegex(MODULE.Refused, "tar.gz"):
            MODULE.load_pin(manifest)
        duplicate = self.case / "duplicate.json"
        duplicate.write_text(
            '{"tools":{"go":{"version":"1.2.3","version":"4.5.6"}}}',
            encoding="ascii",
        )
        duplicate.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, "duplicate JSON key"):
            MODULE.load_pin(duplicate)

    def test_oversized_manifest_is_rejected_before_json_parsing(self) -> None:
        oversized = self.case / "oversized.json"
        oversized.write_bytes(b" " * (MODULE.MAX_MANIFEST + 1))
        oversized.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, "manifest size"):
            MODULE.load_pin(oversized)

    def test_runtime_content_and_pointer_replacement_are_detected(self) -> None:
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        binary = Path(fields["BINARY"])
        binary.chmod(0o700)
        with binary.open("r+b") as stream:
            stream.seek(-1, os.SEEK_END)
            last = stream.read(1)
            stream.seek(-1, os.SEEK_END)
            stream.write(bytes([last[0] ^ 1]))
        binary.chmod(0o500)
        changed = self._cli("verify", *self._verification(fields))
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("changed", changed.stderr)
        pointers = self._verification(fields)
        pointers[2] = str(ROOT)
        escaped = self._cli("verify", *pointers)
        self.assertNotEqual(escaped.returncode, 0)

    def test_goroot_swap_restore_cannot_produce_runtime_pass(self) -> None:
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        root = Path(fields["ROOT"])
        runtime = Path(fields["RUNTIME"])
        with self.assertRaisesRegex(MODULE.Refused, "root-provisioned sealed tree"):
            MODULE.clone_execution_tree(root, runtime)
        with self.assertRaisesRegex(MODULE.Refused, "private Darwin Go execution is refused"):
            MODULE.authenticated_execution_image(
                Path(fields["BINARY"]), fields["BINARY_SHA256"], runtime
            )

    def test_runtime_state_symlink_replacement_is_detected(self) -> None:
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        home = Path(fields["RUNTIME"]) / "state/home"
        home.rmdir()
        home.symlink_to(self.case)
        completed = self._cli("verify", *self._verification(fields))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("state directory", completed.stderr)
        home.unlink()
        home.mkdir(mode=0o700)

    def test_unsafe_cleanup_is_rejected(self) -> None:
        outside = self.case / "outside"
        outside.mkdir()
        completed = self._cli("cleanup", str(outside), "0:0:0:0:0:0:0")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("refusing", completed.stderr)
        self.assertTrue(outside.exists())
        aliased = MODULE._private_tmp() / "wins-release-go.symlink-cleanup"
        if aliased.exists() or aliased.is_symlink():
            aliased.unlink()
        aliased.symlink_to(outside)
        try:
            replaced = self._cli("cleanup", str(aliased), "0:0:0:0:0:0:0")
            self.assertNotEqual(replaced.returncode, 0)
            self.assertTrue(outside.exists())
        finally:
            if aliased.is_symlink():
                aliased.unlink()

    def test_repo_pin_matches_real_macos_arm64_archive_identity(self) -> None:
        pin = MODULE.load_pin(PIN_MANIFEST)
        self.assertEqual(pin["version"], REAL_VERSION)
        self.assertEqual(pin["platform"], "darwin-arm64")
        self.assertEqual(pin["architecture"], "arm64")
        self.assertEqual(pin["archive_format"], "tar.gz")
        self.assertEqual(pin["root"], TOP)
        self.assertEqual(pin["executable"], "bin/go")
        self.assertEqual(pin["archive"], str(REAL_ARCHIVE))
        self.assertEqual(pin["archive_sha"], REAL_ARCHIVE_SHA256)
        self.assertEqual(pin["tree_sha"], REAL_TREE_SHA256)
        self.assertEqual(pin["executable_sha"], REAL_BINARY_SHA256)

    def test_real_macos_arm64_go_archive(self) -> None:
        if not real_archive_ready():
            self.skipTest("real Go 1.27.1 darwin-arm64 archive is unavailable")
        if shutil.disk_usage(MODULE._private_tmp()).free < 2 * 1024 * 1024 * 1024:
            self.skipTest("real Go archive extraction requires 2 GiB free scratch space")
        pin = MODULE.load_pin(PIN_MANIFEST)
        fields = MODULE.install_extracted_runtime(pin)
        self.addCleanup(self._cleanup_if_present, fields)
        root = Path(fields["ROOT"])
        tree_sha = MODULE.tree_hash(root)
        binary_sha = MODULE.digest_file(root / "bin/go")
        self.assertEqual(tree_sha, REAL_TREE_SHA256)
        self.assertEqual(binary_sha, REAL_BINARY_SHA256)
        self.assertTrue((root / "bin/go").is_file())
        self.assertEqual(
            (root / "VERSION").read_bytes().splitlines()[0],
            b"go1.27.1",
        )
        self.assertTrue((root / "test/fixedbugs/issue27836.dir/\u00defoo.go").is_file())
        self.assertEqual(fields["TREE_SHA256"], REAL_TREE_SHA256)
        self.assertEqual(fields["BINARY_SHA256"], REAL_BINARY_SHA256)
        verified = self._cli("verify", *self._verification(fields), timeout=180)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        probed = self._cli(
            "run", *self._verification(fields), "--", "version", timeout=60
        )
        self.assertNotEqual(probed.returncode, 0)
        self.assertIn("private Darwin Go execution is refused", probed.stderr)
        self.assertNotIn("go version go1.27.1", probed.stdout)
        with self.assertRaisesRegex(MODULE.Refused, "private Darwin Go execution is refused"):
            MODULE.authenticated_execution_image(
                Path(fields["BINARY"]),
                fields["BINARY_SHA256"],
                Path(fields["RUNTIME"]),
            )
        print(
            f"REAL_LAYOUT archive_sha256={REAL_ARCHIVE_SHA256} "
            f"install_tree_sha256={tree_sha} executable_sha256={binary_sha} "
            f"execution=FAIL_CLOSED",
            flush=True,
        )

    def test_p1_manifest_path_replacement_before_open_is_rejected(self) -> None:
        archive = self._copy_archive()
        good = self._manifest(archive)
        evil = self._manifest(
            archive,
            tree_sha="1" * 64,
            binary_sha="2" * 64,
        )
        evil_bytes = evil.read_bytes()
        real_open = os.open

        def replace_then_open(path, flags, *args):
            target = Path(path)
            if target == good and (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)) == 0:
                os.unlink(good)
                good.write_bytes(evil_bytes)
                good.chmod(0o600)
            return real_open(path, flags, *args)

        with mock.patch("os.open", replace_then_open):
            with self.assertRaisesRegex(MODULE.Refused, "replaced before it was opened"):
                MODULE.load_pin(good)

    def test_p1_controller_substitution_before_open_is_rejected(self) -> None:
        controller = self.case / "controller.py"
        shutil.copyfile(TOOL, controller)
        controller.chmod(0o600)
        manifest = self._manifest(self._copy_archive())
        attacker = b'raise SystemExit("replacement controller executed")\n'
        real_open = os.open

        def replace_controller(path, flags, *args):
            target = Path(path)
            if target == controller and (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)) == 0:
                os.unlink(controller)
                controller.write_bytes(attacker)
                controller.chmod(0o600)
            return real_open(path, flags, *args)

        with mock.patch("os.open", replace_controller):
            with self.assertRaisesRegex(MODULE.Refused, "replaced before it was opened"):
                MODULE.snapshot_trust_roots(controller, manifest)

    def test_private_execution_copy_cannot_execute(self) -> None:
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        binary = Path(fields["BINARY"])
        runtime = Path(fields["RUNTIME"])
        with self.assertRaisesRegex(MODULE.Refused, "private Darwin Go execution is refused"):
            MODULE.authenticated_execution_image(binary, fields["BINARY_SHA256"], runtime)

    def test_pax_symlink_target_uses_effective_pax_path(self) -> None:
        archive = self.case / "pax-link.tar.gz"
        entries = self._normal_entries() + [
            (f"{TOP}/src/src", "dir", b""),
            (f"{TOP}/src/src/helper.sh", "file", b"pax-effective-target\n"),
            (f"{TOP}/src/other", "dir", b""),
            (f"{TOP}/src/PaxHeaders.0/link", "pax", pax_record(f"{TOP}/src/other/link")),
            (f"{TOP}/bin/link", "symlink", "../src/helper.sh"),
        ]
        self._write_archive(archive, entries)
        root = MODULE.safe_extract(archive, self.case / "expanded-pax-link", TOP)
        link = root / "src/other/link"
        self.assertTrue(link.is_symlink())
        self.assertEqual((root / "src/other/link").resolve().read_bytes(), b"pax-effective-target\n")
        self.assertNotEqual((root / "src/helper.sh").read_bytes(), b"pax-effective-target\n")

    def test_acl_and_xattr_are_rejected_from_extracted_runtime(self) -> None:
        destination = self.case / "expanded-acl-xattr"
        root = MODULE.safe_extract(self.archive, destination, TOP)
        license_path = root / "src/LICENSE"
        os.chmod(license_path, 0o600)
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        libc.setxattr.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.c_int,
        ]
        libc.setxattr.restype = ctypes.c_int
        value = b"evil"
        rc = libc.setxattr(
            os.fsencode(license_path),
            b"com.winsvpn.test",
            value,
            len(value),
            0,
            0x0001,
        )
        self.assertEqual(rc, 0)
        os.chmod(license_path, 0o400)
        with self.assertRaisesRegex(MODULE.Refused, "extended attributes"):
            MODULE.tree_hash(root)
        os.chmod(license_path, 0o600)
        subprocess.run(
            ["/usr/bin/xattr", "-d", "com.winsvpn.test", str(license_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        acl = subprocess.run(
            ["/bin/chmod", "+a", "everyone deny delete", str(license_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(acl.returncode, 0, acl.stderr)
        os.chmod(license_path, 0o400)
        with self.assertRaisesRegex(MODULE.Refused, "ACL"):
            MODULE.tree_hash(root)

    def test_cleanup_refuses_hardlinked_and_external_inodes(self) -> None:
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        internal = Path(fields["ROOT"]) / "src/LICENSE"
        original_mode = stat.S_IMODE(internal.lstat().st_mode)
        original_bytes = internal.read_bytes()
        victim = self.case / "external-victim"
        os.link(internal, victim)
        try:
            completed = self._cli("cleanup", fields["RUNTIME"], fields["RUNTIME_ID"])
            self.assertNotEqual(completed.returncode, 0)
            self.assertRegex(completed.stderr, r"hardlink|external")
            self.assertTrue(Path(fields["RUNTIME"]).exists())
            self.assertEqual(stat.S_IMODE(victim.lstat().st_mode), original_mode)
            self.assertEqual(victim.read_bytes(), original_bytes)
        finally:
            if victim.exists():
                victim.unlink()

    def test_kernel_bound_exec_is_required_and_fail_closed(self) -> None:
        source = TOOL.read_text(encoding="utf-8")
        self.assertIn("FS_IMMUTABLE", source)
        self.assertIn("/dev/fd/", source)
        self.assertIn("/proc/self/fd/", source)
        self.assertIn("posix_spawn", source)
        self.assertIn("SF_IMMUTABLE", source)
        self.assertIn("owner/environment blocker: this host cannot make the Go tree", source)
        self.assertIn("immutable against same-user path replacement through execution", source)
        self.assertEqual(
            MODULE.EXECUTION_BLOCKER,
            "owner/environment blocker: this host cannot make the Go tree "
            "immutable against same-user path replacement through execution",
        )
        self.assertNotIn("sandbox-exec", source)
        self.assertNotIn("_spawn_sandboxed_go", source)
        self.assertIn("replaced before it was opened", source)
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        with mock.patch.object(MODULE.sys, "platform", "linux"):
            with self.assertRaisesRegex(MODULE.Refused, MODULE.LINUX_UNSUPPORTED):
                MODULE.authenticated_execution_image(
                    Path(fields["BINARY"]),
                    fields["BINARY_SHA256"],
                    Path(fields["RUNTIME"]),
                )
        with self.assertRaisesRegex(MODULE.Refused, "private Darwin Go execution is refused"):
            MODULE.authenticated_execution_image(
                Path(fields["BINARY"]),
                fields["BINARY_SHA256"],
                Path(fields["RUNTIME"]),
            )

    def test_noncanonical_tar_names_are_rejected(self) -> None:
        cases = {
            "doubled-separator": f"{TOP}//bin/go",
            "trailing-separator": f"{TOP}/bin/go/",
            "dot-component": f"{TOP}/./bin/go",
            "dot-dir": f"{TOP}/bin/.",
        }
        for label, name in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(MODULE.Refused, "non-canonical"):
                    MODULE._member_path(name, TOP, directory=False)
                archive = self.case / f"{label}.tar.gz"
                self._write_archive(
                    archive,
                    self._normal_entries() + [(name, "file", b"x")],
                )
                with self.assertRaisesRegex(MODULE.Refused, "non-canonical"):
                    MODULE.safe_extract(archive, self.case / f"expanded-{label}", TOP)

    def test_exact_go_bin_go_alias_names_are_rejected(self) -> None:
        for name in (f"{TOP}//bin/go", f"{TOP}/bin/go/"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(MODULE.Refused, "non-canonical"):
                    MODULE._member_path(name, TOP, directory=False)
                archive = self.case / f"alias-{hash(name) & 0xFFFF:x}.tar.gz"
                self._write_archive(
                    archive,
                    self._normal_entries() + [(name, "file", b"x")],
                )
                with self.assertRaisesRegex(MODULE.Refused, "non-canonical"):
                    MODULE.safe_extract(archive, self.case / f"expanded-alias-{hash(name) & 0xFFFF:x}", TOP)

    def test_manifest_mappings_are_recursively_exact(self) -> None:
        archive = self._copy_archive()
        good = self._go_object(archive)
        MODULE.parse_pin_bytes(json.dumps({"tools": {"go": good}}).encode("utf-8"))

        missing = dict(good)
        missing.pop("note")
        with self.assertRaisesRegex(MODULE.Refused, "absent"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": missing}}).encode("utf-8"))

        extra = dict(good)
        extra["attacker"] = "field"
        with self.assertRaisesRegex(MODULE.Refused, "unexpected Go pin field"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": extra}}).encode("utf-8"))

        duplicate = self.case / "duplicate-go.json"
        duplicate.write_text(
            '{"tools":{"go":{"version":"1.2.3","version":"4.5.6"}}}',
            encoding="ascii",
        )
        duplicate.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, "duplicate JSON key"):
            MODULE.load_pin(duplicate)

        bool_version = dict(good)
        bool_version["version"] = True
        with self.assertRaisesRegex(MODULE.Refused, "non-empty string"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": bool_version}}).encode("utf-8"))

        int_version = dict(good)
        int_version["version"] = 1
        with self.assertRaisesRegex(MODULE.Refused, "non-empty string"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": int_version}}).encode("utf-8"))

        list_paths = dict(good)
        list_paths["archive_path"] = [str(archive)]
        with self.assertRaisesRegex(MODULE.Refused, "must be an object"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": list_paths}}).encode("utf-8"))

        extra_path = dict(good)
        extra_path["archive_path"] = {"darwin_arm64": str(archive), "linux_amd64": str(archive)}
        with self.assertRaisesRegex(MODULE.Refused, "unexpected Go pin field"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": extra_path}}).encode("utf-8"))

        missing_hash = dict(good)
        hashes = dict(good["archive_sha256"])
        hashes.pop("linux_amd64")
        missing_hash["archive_sha256"] = hashes
        with self.assertRaisesRegex(MODULE.Refused, "absent"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": missing_hash}}).encode("utf-8"))

        extra_hash = dict(good)
        hashes = dict(good["archive_sha256"])
        hashes["evil"] = "0" * 64
        extra_hash["archive_sha256"] = hashes
        with self.assertRaisesRegex(MODULE.Refused, "unexpected Go pin field"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": extra_hash}}).encode("utf-8"))

        bool_hash = dict(good)
        hashes = dict(good["archive_sha256"])
        hashes["darwin_arm64"] = True
        bool_hash["archive_sha256"] = hashes
        with self.assertRaisesRegex(MODULE.Refused, "non-empty string"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": bool_hash}}).encode("utf-8"))

        extra_tree = dict(good)
        extra_tree["install_tree_sha256"] = {
            "darwin_arm64": self.tree_sha,
            "linux_amd64": "0" * 64,
        }
        with self.assertRaisesRegex(MODULE.Refused, "unexpected Go pin field"):
            MODULE.parse_pin_bytes(json.dumps({"tools": {"go": extra_tree}}).encode("utf-8"))

    def test_executable_digests_of_other_hosts_are_optional_and_exact(self) -> None:
        archive = self._copy_archive()
        good = self._go_object(archive)
        by_platform = dict(good)
        by_platform["executable_sha256_by_platform"] = {
            "linux_amd64": "1" * 64,
            "linux_arm64": "2" * 64,
        }
        pin = MODULE.parse_pin_bytes(
            json.dumps({"tools": {"go": by_platform}}).encode("utf-8")
        )
        self.assertEqual(pin["executable_sha"], good["executable_sha256"])

        for value, message in (
            ({"darwin_arm64": "3" * 64}, "unexpected Go pin field rejected: executable_sha256_by_platform.darwin_arm64"),
            ({"freebsd_amd64": "3" * 64}, "unexpected Go pin field rejected: executable_sha256_by_platform.freebsd_amd64"),
            ({"linux_amd64": "A" * 64}, "invalid Go digest pin: executable_sha256_by_platform.linux_amd64"),
            ({"linux_amd64": True}, "non-empty string"),
            (["linux_amd64"], "must be an object"),
        ):
            with self.subTest(value=value):
                hostile = dict(good)
                hostile["executable_sha256_by_platform"] = value
                with self.assertRaisesRegex(MODULE.Refused, re.escape(message)):
                    MODULE.parse_pin_bytes(json.dumps({"tools": {"go": hostile}}).encode("utf-8"))

    def test_live_pin_manifest_schema_is_accepted(self) -> None:
        pin = MODULE.parse_pin_bytes(PIN_MANIFEST.read_bytes())
        live = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))["tools"]["go"]
        self.assertEqual(pin["executable_sha"], live["executable_sha256"])
        self.assertEqual(
            set(live["executable_sha256_by_platform"]), {"linux_amd64", "linux_arm64"}
        )

    def test_replacement_manifest_and_archive_cannot_self_authorize(self) -> None:
        archive = self._copy_archive()
        manifest = self._manifest(archive)
        completed = self._cli("prepare", str(ROOT), str(manifest))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot self-authorize", completed.stderr)
        self.assertNotIn("RUNTIME|", completed.stdout)
        copied = self.case / "release_go_archive_custody.py"
        shutil.copyfile(TOOL, copied)
        copied.chmod(0o600)
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"malicious or substituted|not in the repository tools directory|owner blocked",
        ):
            MODULE.authorize_custody_inputs(copied, PIN_MANIFEST)
        with self.assertRaisesRegex(MODULE.Refused, "cannot self-authorize"):
            MODULE.authorize_custody_inputs(TOOL, manifest)
        evil_controller = self.case / "tools"
        evil_controller.mkdir()
        attacker = evil_controller / "release_go_archive_custody.py"
        attacker.write_text('raise SystemExit("replacement controller executed")\n', encoding="ascii")
        attacker.chmod(0o600)
        with self.assertRaises(MODULE.Refused) as raised:
            MODULE.authorize_custody_inputs(attacker, evil_controller / "toolchain-pins.json")
        self.assertNotIn("replacement controller executed", str(raised.exception))

    def test_authenticated_inputs_require_external_issuance_and_freeze_digest(self) -> None:
        self.assertTrue(TRUST_ANCHOR.is_file())
        os.environ.pop(MODULE.ISSUANCE_ENV, None)
        if production_trust_delta():
            with self.assertRaisesRegex(MODULE.Refused, "digest does not match the trust-anchor"):
                MODULE.authorize_custody_inputs(TOOL, PIN_MANIFEST)
            self.skipTest("production Go custody trust anchor requires controlled reissuance")
        with self.assertRaisesRegex(
            MODULE.Refused,
            "owner blocked: current reviewed Go custody issuance identity is unavailable",
        ):
            MODULE.authorize_custody_inputs(TOOL, PIN_MANIFEST)
        directory = issuance_parent()
        self.addCleanup(shutil.rmtree, directory, True)
        issuance = write_issuance(directory)
        with issuance_authority(issuance):
            with mock.patch.dict(os.environ, {MODULE.ISSUANCE_ENV: str(issuance)}):
                controller, wrapper, manifest, trust = MODULE.authorize_custody_inputs(
                    TOOL, PIN_MANIFEST
                )
        parsed = MODULE._parse_trust_anchor(trust)
        self.assertEqual(parsed["controller_sha256"], hashlib.sha256(controller).hexdigest())
        self.assertEqual(parsed["wrapper_sha256"], hashlib.sha256(wrapper).hexdigest())
        self.assertEqual(parsed["manifest_sha256"], hashlib.sha256(manifest).hexdigest())
        self.assertEqual(parsed["trust_anchor"], "tools/release_go_archive_custody.trust.json")
        self.assertEqual(parsed["issuance_env"], MODULE.ISSUANCE_ENV)

    def test_version_probe_mismatch_preserves_fail_closed_details(self) -> None:
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        with mock.patch.object(
            MODULE,
            "_run_go",
            return_value=subprocess.CompletedProcess(
                ["go", "version"], 1, "wrong-banner\n", "seatbelt-denied\n"
            ),
        ):
            with self.assertRaisesRegex(
                MODULE.Refused,
                r"Go runtime version probe mismatch: rc=1 stdout='wrong-banner\\n' stderr='seatbelt-denied\\n'",
            ):
                MODULE.check_go_identity(
                    Path(fields["BINARY"]),
                    Path(fields["RUNTIME"]),
                    Path(fields["ROOT"]),
                    VERSION,
                    "arm64",
                    fields["BINARY_SHA256"],
                )
        with mock.patch.object(
            MODULE,
            "authenticated_execution_image",
            side_effect=MODULE.Refused(MODULE.EXECUTION_BLOCKER),
        ):
            with self.assertRaisesRegex(MODULE.Refused, MODULE.EXECUTION_BLOCKER):
                MODULE.check_go_identity(
                    Path(fields["BINARY"]),
                    Path(fields["RUNTIME"]),
                    Path(fields["ROOT"]),
                    VERSION,
                    "arm64",
                    fields["BINARY_SHA256"],
                )

    def test_private_seal_rewrite_path_is_unreachable(self) -> None:
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        binary = Path(fields["BINARY"])
        runtime = Path(fields["RUNTIME"])

        with mock.patch.object(
            MODULE,
            "_kernel_seal_tree",
            side_effect=AssertionError("private sealer must not run on Darwin"),
        ):
            with self.assertRaisesRegex(MODULE.Refused, "private Darwin Go execution is refused"):
                MODULE.authenticated_execution_image(
                    binary, fields["BINARY_SHA256"], runtime
                )

    def test_cleanup_is_symlink_safe_and_residue_fatal(self) -> None:
        archive = self._copy_archive()
        fields = self._install(self._manifest(archive))
        runtime = Path(fields["RUNTIME"])
        victim = self.case / "cleanup-victim"
        victim.write_bytes(b"do-not-follow\n")
        original = victim.read_bytes()
        original_mode = stat.S_IMODE(victim.lstat().st_mode)
        decoy = runtime / "state" / "tmp" / "decoy"
        if decoy.exists() or decoy.is_symlink():
            decoy.unlink()
        decoy.symlink_to(victim)
        cleaned = self._cli("cleanup", fields["RUNTIME"], fields["RUNTIME_ID"])
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertFalse(runtime.exists())
        self.assertEqual(victim.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(victim.lstat().st_mode), original_mode)

        fields = self._install(self._manifest(archive))
        runtime = Path(fields["RUNTIME"])
        real_rmdir = os.rmdir

        def busy_rmdir(path, *args, **kwargs):
            if Path(path) == runtime or (
                not args and str(path) == str(runtime)
            ):
                raise OSError(16, "device or resource busy")
            return real_rmdir(path, *args, **kwargs)

        with mock.patch("os.rmdir", busy_rmdir):
            with self.assertRaisesRegex(MODULE.Refused, "residue"):
                MODULE._destroy_runtime(runtime)
        self.assertTrue(runtime.exists() or runtime.is_symlink())
        MODULE._destroy_runtime(runtime)
        self.assertFalse(runtime.exists() or runtime.is_symlink())

    def test_shell_and_python_syntax(self) -> None:
        for shell_path in (SHELL, PROVISIONER):
            shell = subprocess.run(
                ["/bin/bash", "-n", str(shell_path)], capture_output=True, text=True
            )
            self.assertEqual(shell.returncode, 0, shell.stderr)
        compiled = subprocess.run(
            [sys.executable, "-m", "py_compile", str(TOOL), str(Path(__file__).resolve())],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPYCACHEPREFIX": str(self.case / "pycache")},
        )
        self.assertEqual(compiled.returncode, 0, compiled.stderr)


class ReleaseGoCustodyContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.case = Path(tempfile.mkdtemp(prefix="wins-go-contract."))
        self.case.chmod(0o700)
        self.addCleanup(shutil.rmtree, self.case, True)

    def _write_tar(self, archive: Path, entries: list[tuple[str, str, bytes]]) -> None:
        tar_path = archive.with_suffix(".tar")
        with tarfile.open(tar_path, "w", format=tarfile.USTAR_FORMAT) as bundle:
            for name, kind, payload in entries:
                member = tarfile.TarInfo(name)
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mtime = 0
                if kind == "dir":
                    member.type = tarfile.DIRTYPE
                    member.mode = 0o755
                    bundle.addfile(member)
                else:
                    member.type = tarfile.REGTYPE
                    member.mode = 0o644
                    member.size = len(payload)
                    bundle.addfile(member, io.BytesIO(payload))
        with tar_path.open("rb") as raw, archive.open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                compressed.write(raw.read())
        tar_path.unlink()

    def _parsed_test_authority(self, issuance: Path) -> dict[str, object]:
        return MODULE._parse_authority(TEST_AUTHORITIES[issuance].read_bytes())

    def test_signed_issuance_accepts_exact_active_authority(self) -> None:
        directory = issuance_parent()
        self.addCleanup(shutil.rmtree, directory, True)
        issuance = write_issuance(directory)
        parsed = MODULE._parse_issuance(
            issuance.read_bytes(), self._parsed_test_authority(issuance)
        )
        self.assertEqual(parsed["issuance_id"], "a" * 32)
        self.assertNotIn("authenticated", parsed)

    def test_signed_issuance_rejects_forgery_wrong_key_replay_and_stale(self) -> None:
        directory = issuance_parent()
        self.addCleanup(shutil.rmtree, directory, True)
        issuance = write_issuance(directory)
        authority = self._parsed_test_authority(issuance)

        forged = json.loads(issuance.read_text(encoding="ascii"))
        forged["controller_sha256"] = "f" * 64
        with self.assertRaisesRegex(MODULE.Refused, "signature verification failed"):
            MODULE._parse_issuance(MODULE._canonical_json_bytes(forged), authority)

        other_directory = issuance_parent()
        self.addCleanup(shutil.rmtree, other_directory, True)
        other = write_issuance(other_directory)
        wrong_authority = self._parsed_test_authority(other)
        with self.assertRaisesRegex(MODULE.Refused, "authority key mismatch"):
            MODULE._parse_issuance(issuance.read_bytes(), wrong_authority)

        replay_authority = dict(authority)
        replay_authority["active_issuance_id"] = "b" * 32
        with self.assertRaisesRegex(MODULE.Refused, "replayed or inactive"):
            MODULE._parse_issuance(issuance.read_bytes(), replay_authority)

        stale_directory = issuance_parent()
        self.addCleanup(shutil.rmtree, stale_directory, True)
        stale = write_issuance(
            stale_directory,
            created_utc="2026-08-19T00:00:00Z",
            expires_utc="2026-08-19T01:00:00Z",
        )
        with self.assertRaisesRegex(MODULE.Refused, "stale|predates"):
            MODULE._parse_issuance(
                stale.read_bytes(), self._parsed_test_authority(stale)
            )

    def _owner_fixture(self) -> dict[str, object]:
        fixture_base = Path(
            tempfile.mkdtemp(prefix="wins-go-owner-fixture.", dir=str(MODULE._private_tmp()))
        )
        self.addCleanup(shutil.rmtree, fixture_base, True)
        fixture_xattrs = synthetic_owner_fixture_xattr_patch(fixture_base)
        fixture_xattrs.__enter__()
        self.addCleanup(fixture_xattrs.__exit__, None, None, None)
        library = fixture_base / "Library" / "WinsVPN"
        runtime_prefix = library / "ReleaseGo"
        bootstrap_prefix = library / "ReleaseGoBootstrap"
        runtime = runtime_prefix / VERSION
        root = runtime / "extracted" / TOP
        binary = root / "bin/go"
        (root / "bin").mkdir(parents=True)
        (root / "src").mkdir()
        binary.write_bytes(b"synthetic-owner-go\n")
        (root / "src/LICENSE").write_bytes(b"license\n")
        binary.chmod(0o555)
        (root / "src/LICENSE").chmod(0o444)
        (root / "bin").chmod(0o555)
        (root / "src").chmod(0o555)
        root.chmod(0o555)
        root_info = root.lstat()
        uid_gid = (root_info.st_uid, root_info.st_gid)
        with mock.patch.object(MODULE, "_owner_identity", return_value=uid_gid):
            tree_sha = MODULE.tree_hash(
                root, owner_runtime=True, require_immutable=False
            )
        binary_sha = file_sha256(binary)
        archive_name = f"go{VERSION}.darwin-arm64.tar.gz"
        archive_data = b"synthetic-owner-archive\n"
        archive_sha = hashlib.sha256(archive_data).hexdigest()
        source_bytes = {
            MODULE.CONTROLLER_NAME: b"controller\n",
            MODULE.WRAPPER_NAME: b"wrapper\n",
            MODULE.PROVISIONER_NAME: b"provisioner\n",
            MODULE.MANIFEST_NAME: b"manifest\n",
            MODULE.TRUST_ANCHOR_NAME: b"trust\n",
            MODULE.SOURCE_FREEZE_PRODUCER: b"freeze\n",
        }
        materials = {
            "controller_sha256": hashlib.sha256(
                source_bytes[MODULE.CONTROLLER_NAME]
            ).hexdigest(),
            "wrapper_sha256": hashlib.sha256(
                source_bytes[MODULE.WRAPPER_NAME]
            ).hexdigest(),
            "provisioner_sha256": hashlib.sha256(
                source_bytes[MODULE.PROVISIONER_NAME]
            ).hexdigest(),
            "manifest_sha256": hashlib.sha256(
                source_bytes[MODULE.MANIFEST_NAME]
            ).hexdigest(),
            "trust_anchor_sha256": hashlib.sha256(
                source_bytes[MODULE.TRUST_ANCHOR_NAME]
            ).hexdigest(),
            "source_freeze_producer_sha256": hashlib.sha256(
                source_bytes[MODULE.SOURCE_FREEZE_PRODUCER]
            ).hexdigest(),
        }
        pin = {
            "version": VERSION,
            "archive_sha": archive_sha,
            "tree_sha": tree_sha,
            "executable_sha": binary_sha,
        }
        bootstrap_identity = MODULE._bootstrap_identity(materials, pin)
        bootstrap = bootstrap_prefix / bootstrap_identity
        bootstrap.mkdir(parents=True)
        for name, data in source_bytes.items():
            path = bootstrap / name
            path.write_bytes(data)
            path.chmod(0o444)
        bootstrap_archive = bootstrap / archive_name
        bootstrap_archive.write_bytes(archive_data)
        bootstrap_archive.chmod(0o444)
        bootstrap_receipt = {
            "contract": MODULE.BOOTSTRAP_RECEIPT_CONTRACT,
            "schema_version": 1,
            "identity": bootstrap_identity,
            "path": str(bootstrap),
            "version": VERSION,
            "archive_name": archive_name,
            "archive_size": len(archive_data),
            "archive_sha256": archive_sha,
            "tree_sha256": tree_sha,
            "executable": MODULE.EXECUTABLE,
            "executable_sha256": binary_sha,
            **materials,
        }
        bootstrap_receipt_path = bootstrap / MODULE.BOOTSTRAP_RECEIPT_NAME
        bootstrap_receipt_path.write_bytes(
            MODULE._canonical_json_bytes(bootstrap_receipt)
        )
        bootstrap_receipt_path.chmod(0o444)
        bootstrap.chmod(0o555)
        archive_dir = runtime / "archive"
        archive_dir.mkdir(parents=True)
        archive = archive_dir / archive_name
        archive.write_bytes(archive_data)
        archive.chmod(0o444)
        archive_dir.chmod(0o555)
        (runtime / "extracted").chmod(0o555)
        owner_receipt = {
            "contract": MODULE.OWNER_RECEIPT_CONTRACT,
            "schema_version": 1,
            "version": VERSION,
            "runtime": str(runtime),
            "sealed_bootstrap": str(bootstrap),
            "sealed_bootstrap_identity": bootstrap_identity,
            "archive_name": archive_name,
            "archive_size": len(archive_data),
            "archive_sha256": archive_sha,
            "tree_sha256": tree_sha,
            "executable": MODULE.EXECUTABLE,
            "executable_sha256": binary_sha,
            **materials,
            "provisioned_issuance_id": "a" * 32,
        }
        owner_receipt_path = runtime / MODULE.OWNER_RECEIPT_NAME
        owner_receipt_path.write_bytes(MODULE._canonical_json_bytes(owner_receipt))
        owner_receipt_path.chmod(0o444)
        runtime.chmod(0o555)
        return {
            "runtime_prefix": runtime_prefix,
            "bootstrap_prefix": bootstrap_prefix,
            "runtime": runtime,
            "root": root,
            "binary": binary,
            "tree_sha": tree_sha,
            "binary_sha": binary_sha,
            "archive": archive,
            "bootstrap": bootstrap,
            "bootstrap_receipt": bootstrap_receipt_path,
            "owner_receipt": owner_receipt_path,
            "uid_gid": uid_gid,
        }

    def _owner_patches(self, fixture: dict[str, object]):
        return (
            mock.patch.object(
                MODULE, "OWNER_RUNTIME_PREFIX", fixture["runtime_prefix"]
            ),
            mock.patch.object(
                MODULE, "OWNER_BOOTSTRAP_PREFIX", fixture["bootstrap_prefix"]
            ),
            mock.patch.object(
                MODULE, "_owner_identity", return_value=fixture["uid_gid"]
            ),
            mock.patch.object(MODULE, "_verify_owner_ancestors", return_value=None),
            mock.patch.object(MODULE, "_require_system_immutable", return_value=None),
        )

    def test_prepared_owner_runtime_binds_receipts_archive_tree_and_binary(self) -> None:
        fixture = self._owner_fixture()
        patches = self._owner_patches(fixture)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            MODULE._verify_prepared_owner_runtime(
                fixture["root"],
                fixture["binary"],
                fixture["tree_sha"],
                fixture["binary_sha"],
            )
            with mock.patch.object(
                MODULE,
                "clone_execution_tree",
                side_effect=AssertionError("owner runtime must execute in place"),
            ):
                image = MODULE.authenticated_execution_image(
                    fixture["binary"],
                    fixture["binary_sha"],
                    self.case / "private-state",
                    fixture["tree_sha"],
                )
                try:
                    self.assertEqual(image.path, fixture["binary"])
                    self.assertEqual(image.tree, fixture["root"])
                    self.assertFalse(image.destroy_tree)
                finally:
                    image.cleanup()

    def test_prepared_owner_runtime_rejects_noncanonical_and_drifted_receipts(self) -> None:
        fixture = self._owner_fixture()
        receipt = fixture["owner_receipt"]
        receipt.chmod(0o644)
        document = json.loads(receipt.read_text(encoding="ascii"))
        receipt.write_text(json.dumps(document) + "\n", encoding="ascii")
        receipt.chmod(0o444)
        patches = self._owner_patches(fixture)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with self.assertRaisesRegex(MODULE.Refused, "not canonical JSON"):
                MODULE._verify_prepared_owner_runtime(
                    fixture["root"],
                    fixture["binary"],
                    fixture["tree_sha"],
                    fixture["binary_sha"],
                )

    def test_prepared_owner_runtime_rejects_archive_and_mode_drift(self) -> None:
        fixture = self._owner_fixture()
        archive = fixture["archive"]
        archive.chmod(0o644)
        archive.write_bytes(b"X" * archive.stat().st_size)
        archive.chmod(0o444)
        patches = self._owner_patches(fixture)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with self.assertRaisesRegex(MODULE.Refused, "archive digest changed"):
                MODULE._verify_prepared_owner_runtime(
                    fixture["root"],
                    fixture["binary"],
                    fixture["tree_sha"],
                    fixture["binary_sha"],
                )
        fixture = self._owner_fixture()
        fixture["binary"].chmod(0o755)
        patches = self._owner_patches(fixture)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with self.assertRaisesRegex(MODULE.Refused, "mode"):
                MODULE._verify_prepared_owner_runtime(
                    fixture["root"],
                    fixture["binary"],
                    fixture["tree_sha"],
                    fixture["binary_sha"],
                )

    def test_prepared_owner_runtime_rejects_arbitrary_xattr(self) -> None:
        fixture = self._owner_fixture()
        binary = fixture["binary"]
        binary.chmod(0o755)
        completed = subprocess.run(
            ["/usr/bin/xattr", "-w", "com.winsvpn.hostile", "hostile", str(binary)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        binary.chmod(0o555)
        self.assertEqual(MODULE._xattr_names(binary), [b"com.winsvpn.hostile"])
        patches = self._owner_patches(fixture)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with self.assertRaisesRegex(MODULE.Refused, "extended attributes"):
                MODULE._verify_prepared_owner_runtime(
                    fixture["root"],
                    fixture["binary"],
                    fixture["tree_sha"],
                    fixture["binary_sha"],
                )

    def test_owner_publish_normalizes_only_platform_provenance(self) -> None:
        root = self.case / "owner-xattr-normalization"
        root.mkdir(mode=0o755)
        probe = root / "probe"
        probe.write_bytes(b"probe\n")
        completed = subprocess.run(
            ["/usr/bin/xattr", "-w", "com.apple.provenance", "runner", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        MODULE._clear_allowed_owner_xattrs(root)
        self.assertTrue(
            set(MODULE._xattr_names(root)).issubset(MODULE.ALLOWED_XATTRS)
        )

        completed = subprocess.run(
            ["/usr/bin/xattr", "-w", "com.winsvpn.hostile", "hostile", str(probe)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        with self.assertRaisesRegex(MODULE.Refused, "extended attributes"):
            MODULE._clear_allowed_owner_xattrs(root)

    def test_sf_immutable_is_required_and_uf_only_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.Refused, "lacks SF_IMMUTABLE"):
            MODULE._require_system_immutable(SimpleNamespace(st_flags=0), "probe")
        with self.assertRaisesRegex(MODULE.Refused, "UF_IMMUTABLE is insufficient"):
            MODULE._require_system_immutable(
                SimpleNamespace(st_flags=MODULE.UF_IMMUTABLE), "probe"
            )
        MODULE._require_system_immutable(
            SimpleNamespace(st_flags=MODULE.SF_IMMUTABLE), "probe"
        )

    def test_owner_entry_rejects_foreign_owner_and_hardlink(self) -> None:
        probe = self.case / "owner-entry"
        probe.write_bytes(b"probe\n")
        probe.chmod(0o444)
        with mock.patch.object(MODULE, "_owner_identity", return_value=(12345, 12345)):
            with self.assertRaisesRegex(MODULE.Refused, "ownership or mode"):
                MODULE._require_owner_entry(
                    probe,
                    mode=0o444,
                    directory=False,
                    immutable=False,
                    label="probe",
                )
        alias = self.case / "owner-entry-hardlink"
        os.link(probe, alias)
        with mock.patch.object(
            MODULE, "_owner_identity", return_value=(os.getuid(), os.getgid())
        ):
            with self.assertRaisesRegex(MODULE.Refused, "hardlink"):
                MODULE._require_owner_entry(
                    probe,
                    mode=0o444,
                    directory=False,
                    immutable=False,
                    label="probe",
                )

    def test_exact_partial_publication_recovery_is_prefix_bounded(self) -> None:
        fixture = self._owner_fixture()
        runtime = fixture["runtime"]
        patches = self._owner_patches(fixture)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            mock.patch.object(os, "getuid", return_value=0),
            mock.patch.object(os, "geteuid", return_value=0),
            mock.patch.object(MODULE, "_lchflags", return_value=None),
        ):
            MODULE._destroy_exact_partial_owner_runtime(runtime)
        self.assertFalse(runtime.exists())
        outside = self.case / VERSION
        outside.mkdir()
        with (
            mock.patch.object(os, "getuid", return_value=0),
            mock.patch.object(os, "geteuid", return_value=0),
        ):
            with self.assertRaisesRegex(MODULE.Refused, "outside the exact prefix"):
                MODULE._destroy_exact_partial_owner_runtime(outside)
    def test_owner_provisioner_is_nonroot_fail_closed_and_never_invokes_sudo(self) -> None:
        source = PROVISIONER.read_text(encoding="utf-8")
        executable_lines = [
            line for line in source.splitlines() if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertFalse(any(re.match(r"\s*sudo(?:\s|$)", line) for line in executable_lines))
        self.assertNotIn("sudo -S", source)
        self.assertNotIn("/usr/local/go", source)
        issuance_dir = issuance_parent()
        self.addCleanup(shutil.rmtree, issuance_dir, True)
        issuance = write_issuance(issuance_dir)
        completed = subprocess.run(
            ["/bin/bash", str(PROVISIONER), str(PIN_MANIFEST)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "TERM": "xterm-256color",
                MODULE.ISSUANCE_ENV: str(issuance),
            },
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertRegex(
            completed.stderr,
            r"signed Go provisioning preflight failed|authority|archive|release Python",
        )
        self.assertNotIn("sudo -S", completed.stdout)
        self.assertNotIn("password", completed.stdout.lower())
        self.assertIn("signed Go provisioning preflight", source)
        self.assertIn("preflight >/dev/null", source)

    def test_controller_never_executes_unauthenticated_source(self) -> None:
        source = TOOL.read_text(encoding="utf-8")
        wrapper = SHELL.read_text(encoding="utf-8")
        self.assertNotIn("exec(compile", source)
        self.assertNotIn("importlib", source)
        self.assertIn("unauthenticated freeze source is never executed", source)
        self.assertIn("WINS_GO_CUSTODY_ISSUANCE", source)
        self.assertIn("_execution_fd_path", source)
        self.assertIn("FS_IMMUTABLE_FL", source)
        self.assertIn('array("l")', source)
        self.assertNotIn("parents=True", source)
        self.assertIn("wins_release_python_run -c", wrapper)
        self.assertIn('os.environ["WINS_GO_CUSTODY_ISSUANCE"] = issuance', wrapper)
        self.assertIn('sys.argv = ["release_go_archive_custody.py", *arguments]', wrapper)
        self.assertIn('issuance_raw = sys.argv[7]', wrapper)
        self.assertNotIn("wins_release_python_run \"$expected_controller\"", wrapper)
        self.assertNotIn("WINS_RELEASE_GO=\"$binary\"", wrapper)
        self.assertNotRegex(wrapper, r"export WINS_RELEASE_GO[ \n]")
        self.assertNotIn("wins-go-trust.", wrapper)
        self.assertIn("wins_release_go_run", wrapper)

    def test_go_environment_is_constructed_and_inherited_policy_is_refused(self) -> None:
        runtime = self.case / "runtime-environment"
        root = self.case / "root-environment"
        with mock.patch.dict(os.environ, {}, clear=True):
            environment = MODULE._validated_go_environment(runtime, root)
        self.assertEqual(environment["GOFLAGS"], "-mod=readonly")
        self.assertEqual(environment["GOWORK"], "off")
        self.assertEqual(environment["GOPROXY"], "off")
        self.assertEqual(environment["GOSUMDB"], "off")
        self.assertNotIn("GOEXPERIMENT", environment)
        for name in sorted(MODULE.REFUSED_INHERITED_GO_ENV):
            with self.subTest(name=name):
                with mock.patch.dict(os.environ, {name: "hostile"}, clear=True):
                    with self.assertRaisesRegex(MODULE.Refused, name):
                        MODULE._validated_go_environment(runtime, root)

        with mock.patch.dict(
            os.environ,
            {"WINS_GO_CUSTODY_LABEL": "caller-selected"},
            clear=True,
        ):
            with self.assertRaisesRegex(
                MODULE.Refused, "arbitrary release Go custody label is refused"
            ):
                MODULE._validated_go_environment(runtime, root)

    def test_overlay_toolexec_and_arbitrary_run_labels_are_refused(self) -> None:
        for arguments, label in (
            (["build", "-overlay=/tmp/hostile.json", "./..."], "-overlay"),
            (["build", "-overlay", "/tmp/hostile.json", "./..."], "-overlay"),
            (["build", "-toolexec=/tmp/hostile", "./..."], "-toolexec"),
            (["build", "-toolexec", "/tmp/hostile", "./..."], "-toolexec"),
        ):
            with self.subTest(label=label, arguments=arguments):
                with self.assertRaisesRegex(MODULE.Refused, label):
                    MODULE._reject_go_command_overrides(arguments)
        MODULE._reject_go_command_overrides(
            ["build", "-mod=readonly", "-trimpath", "-buildvcs=false", "./cdatapath"]
        )

    def test_missing_writable_and_adjacent_issuance_are_owner_blocked(self) -> None:
        os.environ.pop(MODULE.ISSUANCE_ENV, None)
        if production_trust_delta():
            with self.assertRaisesRegex(MODULE.Refused, "digest does not match the trust-anchor"):
                MODULE.authorize_repo(ROOT)
            self.skipTest("production Go custody trust anchor requires controlled reissuance")
        with self.assertRaisesRegex(MODULE.Refused, MODULE.OWNER_BLOCKED_UNAVAILABLE):
            MODULE.authorize_repo(ROOT)
        directory = issuance_parent()
        self.addCleanup(shutil.rmtree, directory, True)
        issuance = write_issuance(directory)
        issuance.chmod(0o644)
        with issuance_authority(issuance):
            with mock.patch.dict(os.environ, {MODULE.ISSUANCE_ENV: str(issuance)}):
                with self.assertRaisesRegex(MODULE.Refused, MODULE.OWNER_BLOCKED_WRITABLE):
                    MODULE.authorize_repo(ROOT)
        issuance.chmod(0o444)
        adjacent = ROOT / ".go-custody-issuance-test.json"
        self.addCleanup(lambda: adjacent.unlink(missing_ok=True))
        shutil.copyfile(issuance, adjacent)
        adjacent.chmod(0o444)
        with issuance_authority(issuance):
            with mock.patch.dict(os.environ, {MODULE.ISSUANCE_ENV: str(adjacent)}):
                with self.assertRaisesRegex(MODULE.Refused, MODULE.OWNER_BLOCKED_ADJACENT):
                    MODULE.authorize_repo(ROOT)
            with mock.patch.dict(os.environ, {MODULE.ISSUANCE_ENV: str(issuance)}):
                MODULE.authorize_repo(ROOT)

    def test_replacement_pins_without_matching_issuance_cannot_self_authorize(self) -> None:
        fake_parent = Path(
            tempfile.mkdtemp(prefix="wins-go-fake-repo.", dir=str(MODULE._private_tmp()))
        )
        self.addCleanup(shutil.rmtree, fake_parent, True)
        fake = fake_parent / "repo"
        tools = fake / "tools"
        tools.mkdir(parents=True)
        for name in (
            "release_go_archive_custody.py",
            "release_go_archive_custody.sh",
            "provision_macos_release_go_runtime.sh",
            "toolchain-pins.json",
            "release_go_archive_custody.trust.json",
            "release_source_freeze.py",
        ):
            shutil.copyfile(ROOT / "tools" / name, tools / name)
        attacker = tools / "release_go_archive_custody.py"
        attacker.write_bytes(attacker.read_bytes() + b"\n# replacement\n")
        trust = {
            "contract": "winsvpn-go-archive-custody-trust-v1",
            "schema_version": 1,
            "controller": "tools/release_go_archive_custody.py",
            "wrapper": "tools/release_go_archive_custody.sh",
            "provisioner": "tools/provision_macos_release_go_runtime.sh",
            "manifest": "tools/toolchain-pins.json",
            "trust_anchor": "tools/release_go_archive_custody.trust.json",
            "issuance_env": "WINS_GO_CUSTODY_ISSUANCE",
            "issuance_contract": MODULE.ISSUANCE_CONTRACT,
            "authority": str(MODULE.OWNER_AUTHORITY_PATH),
            "authority_contract": MODULE.AUTHORITY_CONTRACT,
            "signature_algorithm": MODULE.SIGNATURE_ALGORITHM,
            "controller_sha256": file_sha256(attacker),
            "wrapper_sha256": file_sha256(tools / "release_go_archive_custody.sh"),
            "provisioner_sha256": file_sha256(
                tools / "provision_macos_release_go_runtime.sh"
            ),
            "manifest_sha256": file_sha256(tools / "toolchain-pins.json"),
        }
        (tools / "release_go_archive_custody.trust.json").write_text(
            json.dumps(trust), encoding="ascii"
        )
        directory = issuance_parent()
        self.addCleanup(shutil.rmtree, directory, True)
        issuance = write_issuance(directory)
        with issuance_authority(issuance):
            with mock.patch.dict(os.environ, {MODULE.ISSUANCE_ENV: str(issuance)}):
                with self.assertRaisesRegex(MODULE.Refused, "digest does not match"):
                    MODULE.authorize_repo(fake)
        os.environ.pop(MODULE.ISSUANCE_ENV, None)
        with self.assertRaisesRegex(MODULE.Refused, MODULE.OWNER_BLOCKED_UNAVAILABLE):
            MODULE.authorize_repo(fake)

    def test_nfkc_and_casefold_tar_names_are_rejected(self) -> None:
        ligature = "\ufb03"
        with self.assertRaisesRegex(MODULE.Refused, "non-canonical"):
            MODULE._raw_tar_components(
                f"{TOP}/src/{ligature}.go", directory=False, label="Go TAR member path"
            )
        sharp = f"{TOP}/src/stra\u00dfe.go"
        folded = f"{TOP}/src/strasse.go"
        archive = self.case / "nfkc-casefold.tar.gz"
        self._write_tar(
            archive,
            [
                (TOP, "dir", b""),
                (f"{TOP}/src", "dir", b""),
                (sharp, "file", b"package a\n"),
                (folded, "file", b"package b\n"),
            ],
        )
        tar_path = self.case / "nfkc-casefold.tar"
        with gzip.open(archive, "rb") as stream, tar_path.open("wb") as output:
            output.write(stream.read())
        with self.assertRaisesRegex(MODULE.Refused, "collision"):
            MODULE.scan_tar(tar_path, TOP)
        compatibility = "\u2122"
        with self.assertRaisesRegex(MODULE.Refused, "non-canonical"):
            MODULE._raw_tar_components(
                f"{TOP}/src/{compatibility}.go",
                directory=False,
                label="Go TAR member path",
            )

    def test_safe_extract_does_not_create_undeclared_parents(self) -> None:
        archive = self.case / "undeclared-parent.tar.gz"
        self._write_tar(
            archive,
            [
                (TOP, "dir", b""),
                (f"{TOP}/src/nested/file.go", "file", b"package nested\n"),
            ],
        )
        with self.assertRaisesRegex(MODULE.Refused, "parent directory was not declared first"):
            MODULE.safe_extract(archive, self.case / "expanded-undeclared", TOP)

    def test_linux_fs_immutable_uses_clong_and_fail_closed(self) -> None:
        buf = MODULE._fs_flag_buffer(0)
        self.assertEqual(buf.itemsize, ctypes.sizeof(ctypes.c_long))
        self.assertNotEqual(buf.itemsize, ctypes.sizeof(ctypes.c_int) if ctypes.sizeof(ctypes.c_int) != ctypes.sizeof(ctypes.c_long) else -1)
        get_flags, set_flags = MODULE._fs_ioctl_numbers()
        self.assertEqual((get_flags >> 30) & 0x3, 2)
        self.assertEqual((set_flags >> 30) & 0x3, 1)
        self.assertEqual((get_flags >> 16) & 0x3FFF, ctypes.sizeof(ctypes.c_long))
        self.assertEqual(get_flags & 0xFF, 1)
        self.assertEqual(set_flags & 0xFF, 2)
        probe = self.case / "linux-immutable-probe"
        probe.write_bytes(b"probe\n")
        probe.chmod(0o400)
        with self.assertRaisesRegex(MODULE.Refused, MODULE.LINUX_UNSUPPORTED):
            MODULE._apply_linux_immutable(probe)

    def test_wrapper_bind_requires_issuance_and_never_exports_go_path(self) -> None:
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex.quote(str(SHELL))}
            wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
            wins_release_go_prepare {shlex.quote(str(TOOL))} {shlex.quote(str(PIN_MANIFEST))}
            printf 'EXPORTED_GO=%s\\n' "${{WINS_RELEASE_GO-}}"
            """
        )
        os.environ.pop(MODULE.ISSUANCE_ENV, None)
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("owner blocked: current reviewed Go custody issuance identity is unavailable", completed.stderr)
        self.assertNotIn("RUNTIME|", completed.stdout)
        exported = subprocess.run(
            ["/bin/bash", "-c", f"source {shlex.quote(str(SHELL))}; printf '%s' \"${{WINS_RELEASE_GO-}}\""],
            capture_output=True,
            text=True,
        )
        self.assertEqual(exported.stdout, "")

    def test_authenticated_true_is_not_cryptographic_authority(self) -> None:
        if production_trust_delta():
            with self.assertRaisesRegex(MODULE.Refused, "digest does not match the trust-anchor"):
                MODULE.authorize_repo(ROOT)
            self.skipTest("production Go custody trust anchor requires controlled reissuance")
        directory = issuance_parent()
        self.addCleanup(shutil.rmtree, directory, True)
        issuance = write_issuance(directory, authenticated=True)
        with issuance_authority(issuance):
            with mock.patch.dict(os.environ, {MODULE.ISSUANCE_ENV: str(issuance)}):
                with self.assertRaisesRegex(MODULE.Refused, "unexpected Go pin field"):
                    MODULE.authorize_repo(ROOT)

    def test_shell_and_python_syntax_unskipped(self) -> None:
        for shell_path in (SHELL, PROVISIONER):
            shell = subprocess.run(
                ["/bin/bash", "-n", str(shell_path)], capture_output=True, text=True
            )
            self.assertEqual(shell.returncode, 0, shell.stderr)
        compiled = subprocess.run(
            [sys.executable, "-m", "py_compile", str(TOOL), str(Path(__file__).resolve())],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPYCACHEPREFIX": str(self.case / "pycache")},
        )
        self.assertEqual(compiled.returncode, 0, compiled.stderr)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux FS_IMMUTABLE synthetic host")
class ReleaseGoLinuxSealTest(unittest.TestCase):
    def test_kernel_seal_fail_closed_before_execution_without_capability(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="wins-go-linux-seal.", dir="/var/tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        binary = root / "bin" / "go"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"synthetic-go\n")
        binary.chmod(0o500)
        (root / "bin").chmod(0o500)
        root.chmod(0o500)
        with self.assertRaisesRegex(MODULE.Refused, MODULE.LINUX_UNSUPPORTED):
            MODULE._kernel_seal_tree(root)


@unittest.skipUnless(
    sys.platform == "darwin"
    and os.geteuid() == 0
    and os.environ.get("WINS_GO_CUSTODY_RUN_ROOT_HARNESS") == "1",
    "explicit disposable root custody harness is disabled",
)
class ReleaseGoDisposableRootAcceptanceHarness(unittest.TestCase):
    """Real root/SF_IMMUTABLE/RENAME_EXCL acceptance under /private/tmp only."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp(prefix="wins-go-root-harness.", dir="/private/tmp"))
        self.prefix = self.base / "ReleaseGo"
        self.prefix.mkdir(mode=0o755)
        os.chown(self.base, 0, 0)
        os.chown(self.prefix, 0, 0)

    def tearDown(self) -> None:
        for base, directories, files in os.walk(self.base, topdown=False, followlinks=False):
            base_path = Path(base)
            for name in files + directories:
                path = base_path / name
                try:
                    os.chflags(path, 0, follow_symlinks=False)
                    path.chmod(0o700 if path.is_dir() else 0o600)
                except FileNotFoundError:
                    pass
            try:
                os.chflags(base_path, 0, follow_symlinks=False)
                base_path.chmod(0o700)
            except FileNotFoundError:
                pass
        shutil.rmtree(self.base, ignore_errors=True)

    def test_real_exclusive_publish_seal_idempotency_and_partial_recovery(self) -> None:
        authority_material = self.base / "authority-material"
        authority_material.mkdir(mode=0o700)
        _private_key, authority_path = _generate_test_authority(
            authority_material, "c" * 32, 7
        )
        for candidate in (authority_path.parent.parent, authority_path.parent, authority_path):
            os.chown(candidate, 0, 0)
            if candidate.is_dir():
                candidate.chmod(0o555)
            else:
                candidate.chmod(0o444)
            os.chflags(candidate, MODULE.SF_IMMUTABLE, follow_symlinks=False)
        with (
            mock.patch.object(
                MODULE, "OWNER_AUTHORITY_PREFIX", authority_path.parent
            ),
            mock.patch.object(MODULE, "OWNER_AUTHORITY_PATH", authority_path),
        ):
            bound_authority = MODULE._verify_authority_path(
                authority_path, require_immutable=True
            )
            self.assertEqual(
                MODULE._parse_authority(bound_authority)["active_sequence"], 7
            )

        staging = self.prefix / ".go-provisioning.acceptance"
        staging.mkdir(mode=0o555)
        probe = staging / "probe"
        probe.write_bytes(b"probe\n")
        probe.chmod(0o444)
        os.chown(probe, 0, 0)
        os.chown(staging, 0, 0)
        destination = self.prefix / "1.25.0"
        with mock.patch.object(MODULE, "OWNER_RUNTIME_PREFIX", self.prefix):
            MODULE._publish_directory_exclusive(staging, destination)
            MODULE._seal_owner_tree(destination)
            MODULE._seal_owner_tree(destination)
            MODULE._require_system_immutable(destination.lstat(), "root harness")
            MODULE._require_system_immutable(
                (destination / "probe").lstat(), "root harness probe"
            )
            competing = self.prefix / ".go-provisioning.competing"
            competing.mkdir(mode=0o700)
            with self.assertRaises(MODULE.Refused):
                MODULE._publish_directory_exclusive(competing, destination)

            partial = self.prefix / "1.25.1"
            partial.mkdir(mode=0o555)
            partial_file = partial / "probe"
            partial_file.write_bytes(b"partial\n")
            partial_file.chmod(0o444)
            os.chown(partial_file, 0, 0)
            os.chown(partial, 0, 0)
            os.chflags(partial_file, MODULE.SF_IMMUTABLE, follow_symlinks=False)
            MODULE._destroy_exact_partial_owner_runtime(partial)
            self.assertFalse(partial.exists())


if __name__ == "__main__":
    unittest.main()
