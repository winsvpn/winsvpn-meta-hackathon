#!/usr/bin/env python3
"""Adversarial fixture tests for Chrome for Testing archive custody."""

from __future__ import annotations

import datetime as dt
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import unicodedata
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "release_browser_archive_custody.py"
SHELL = ROOT / "tools" / "release_browser_archive_custody.sh"
PIN_MANIFEST = ROOT / "tools" / "toolchain-pins.json"
TRUST = ROOT / "tools" / "release_browser_archive_custody.trust.json"
PYTHON_SHELL = ROOT / "tools" / "release_python_archive_custody.sh"
VERSION = "145.0.7632.109"
REAL_VERSION = "152.0.7977.54"
TOP = "chrome-mac-arm64"
APP = "Google Chrome for Testing.app"
PRODUCT = "Google Chrome for Testing"
EXECUTABLE = f"{APP}/Contents/MacOS/Google Chrome for Testing"
IDENTITY = "adhoc"
REAL_ARCHIVE = Path("/Users/owner/Downloads") / f"{TOP}-{REAL_VERSION}.zip"
REAL_ARCHIVE_SHA256 = "0c8741d580076b3a8add518ddbb674183992d005cdee37a4875948c9f2748d2a"
REAL_TREE_SHA256 = "72f4ddcadc287abaabd05a645d0b5524c7c138097e318dc33984e2b64d0a5865"
REAL_BINARY_SHA256 = "e100ea3a3fc9d4dc4433e1f250a2394c894c88355f7d5210b5e57250f08adc15"
# extension/dist is an ignored local build output that may be absent or stale,
# so the current packages are rebuilt from this tree into the test directory
# (see _current_extension_packages). The digests are the deterministic
# extension/build.py packages of the current extension sources.
EXTENSION_BUILD = ROOT / "extension" / "build.py"
CHROME_PACKAGE = Path("wins-vpn-companion-chrome.zip")
EDGE_PACKAGE = Path("wins-vpn-companion-edge.zip")
FIREFOX_ZIP = Path("wins-vpn-companion-firefox.zip")
FIREFOX_XPI = Path("wins-vpn-companion-firefox.xpi")
CHROME_PACKAGE_SHA256 = "3d87c0935fffac3124c98508671fb3cd0dbe8f9ffdda9ad912c3b7069af88902"
EDGE_PACKAGE_SHA256 = "ac9347671ef4c81bf3e56693d5fb319c9f70b7f2258a17ce9b27db431e473f0f"
FIREFOX_PACKAGE_SHA256 = "590fbe20511d85f5e77ecff1b9562f927c25beed17e47051157bf61576836bd0"
STALE_REFUSED = r"stale Chrome custody trust refused"

SPEC = importlib.util.spec_from_file_location("release_browser_archive_custody", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release browser custody module")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TEST_AUTHORITIES: dict[Path, Path] = {}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_issuance(
    directory: Path,
    *,
    controller: Path = TOOL,
    wrapper: Path = SHELL,
    manifest: Path = PIN_MANIFEST,
    trust: Path = TRUST,
    freeze: Path | None = None,
    **overrides: object,
) -> Path:
    freeze = freeze or (ROOT / "tools" / "release_source_freeze.py")
    now = dt.datetime.now(dt.timezone.utc)
    created = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = (now + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    issuance_id = str(overrides.pop("issuance_id", "a" * 32))
    sequence = int(overrides.pop("sequence", 1))
    private_key = directory / f"fixture-authority-{issuance_id}.pem"
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
    public_key = exported.stdout
    authority = {
        "contract": MODULE.AUTHORITY_CONTRACT,
        "schema_version": 1,
        "key_id": hashlib.sha256(public_key).hexdigest(),
        "signature_algorithm": MODULE.SIGNATURE_ALGORITHM,
        "public_key_pem_base64": base64.b64encode(public_key).decode("ascii"),
        "active_issuance_id": issuance_id,
        "active_sequence": sequence,
        "not_before_utc": (now - dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    authority_path = directory / f"fixture-authority-{issuance_id}.json"
    authority_path.write_bytes(MODULE._canonical_json_bytes(authority))
    authority_path.chmod(0o444)
    payload: dict[str, object] = {
        "contract": MODULE.ISSUANCE_CONTRACT,
        "schema_version": 2,
        "issuance_id": issuance_id,
        "created_utc": str(overrides.pop("created_utc", created)),
        "sequence": sequence,
        "expires_utc": str(overrides.pop("expires_utc", expires)),
        "issuer": MODULE.ISSUANCE_ISSUER,
        "authority_key_id": authority["key_id"],
        "signature_algorithm": MODULE.SIGNATURE_ALGORITHM,
        "target": str(overrides.pop("target", MODULE.TARGET_ID)),
        "product": str(overrides.pop("product", PRODUCT)),
        "version": str(overrides.pop("version", REAL_VERSION)),
        "archive_sha256": str(overrides.pop("archive_sha256", REAL_ARCHIVE_SHA256)),
        "controller": "tools/release_browser_archive_custody.py",
        "wrapper": "tools/release_browser_archive_custody.sh",
        "manifest": "tools/toolchain-pins.json",
        "trust_anchor": "tools/release_browser_archive_custody.trust.json",
        "source_freeze_producer": "tools/release_source_freeze.py",
        "controller_sha256": sha256(controller),
        "wrapper_sha256": sha256(wrapper),
        "manifest_sha256": sha256(manifest),
        "trust_anchor_sha256": sha256(trust),
        "source_freeze_producer_sha256": sha256(freeze),
    }
    payload.update(overrides)
    signature = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(private_key)],
        input=MODULE._canonical_json_bytes(payload),
        capture_output=True,
        timeout=10,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "OPENSSL_CONF": "/dev/null"},
    )
    if signature.returncode != 0:
        raise AssertionError(signature.stderr.decode("utf-8", "replace"))
    payload["signature_base64"] = base64.b64encode(signature.stdout).decode("ascii")
    path = directory / f"browser-custody-issuance-{issuance_id}.json"
    if path.exists() or path.is_symlink():
        path.unlink()
    path.write_bytes(MODULE._canonical_json_bytes(payload))
    path.chmod(0o444)
    TEST_AUTHORITIES[path] = authority_path
    return path


def parse_fields(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("|")
        if not separator or key in result:
            raise AssertionError(f"malformed custody output: {line!r}")
        result[key] = value
    return result


def _zip_info(name: str, mode: int, *, directory: bool = False) -> zipfile.ZipInfo:
    member = zipfile.ZipInfo(name if not directory or name.endswith("/") else name + "/")
    member.create_system = 3
    kind = stat.S_IFDIR if directory else stat.S_IFREG
    member.external_attr = (kind | mode) << 16
    return member


def real_archive_ready() -> bool:
    try:
        MODULE.require_safe_input(REAL_ARCHIVE, f"{TOP}-{REAL_VERSION}.zip")
    except (MODULE.Refused, FileNotFoundError):
        # The real archive is a local download outside the repository.
        return False
    return MODULE.digest_file(REAL_ARCHIVE) == REAL_ARCHIVE_SHA256


@unittest.skipUnless(sys.platform == "darwin", "macOS arm64 Chrome custody target required")
class ReleaseBrowserArchiveCustodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if subprocess.run(["/usr/bin/uname", "-m"], capture_output=True, text=True).stdout.strip() != "arm64":
            raise unittest.SkipTest("arm64 host required")
        cls.base = Path(tempfile.mkdtemp(prefix="wins-browser-custody-test.", dir="/private/tmp"))
        cls.base.chmod(0o700)
        cls.inputs = cls.base / "inputs"
        cls.inputs.mkdir(mode=0o700)
        cls.binary = cls._compile_fixture("arm64")
        cls.reference = cls.base / "reference" / TOP
        cls._write_signed_tree(cls.reference, cls.binary)
        cls.tree_sha = MODULE.tree_hash(cls.reference)
        cls.binary_sha = sha256(cls.reference / EXECUTABLE)
        cls.archive = cls.inputs / f"{TOP}-{VERSION}.zip"
        cls._zip_tree(cls.reference.parent, cls.archive)
        cls.archive.chmod(0o444)

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
    def _current_extension_packages(cls) -> dict[str, Path]:
        """Build the current Chrome, Edge and Firefox packages from this tree once.

        A child interpreter runs extension/build.py's own stage and zip steps
        with DIST pointed into the class directory, so neither the ignored
        extension/dist nor this process's import state is used.
        """
        cached = getattr(cls, "_extension_packages", None)
        if cached is not None:
            return cached
        dist = cls.base / "extension-dist"
        builder = textwrap.dedent(
            """
            import importlib.util
            import pathlib
            import sys

            spec = importlib.util.spec_from_file_location(
                "extension_build_for_browser_custody_test", sys.argv[1]
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.DIST = pathlib.Path(sys.argv[2])
            for target in ("chrome", "edge", "firefox"):
                module.zip_package(module.stage(target), target)
            """
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-c", builder, str(EXTENSION_BUILD), str(dist)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=240,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"extension package build failed: {completed.stdout}{completed.stderr}"
            )
        packages = {
            package.name: dist / package.name
            for package in (CHROME_PACKAGE, EDGE_PACKAGE, FIREFOX_ZIP, FIREFOX_XPI)
        }
        cls._extension_packages = packages
        return packages

    @classmethod
    def _compile_fixture(cls, architecture: str) -> Path:
        source = cls.base / f"chrome-fixture-{architecture}.c"
        binary = cls.base / f"chrome-fixture-{architecture}"
        source.write_text(
            textwrap.dedent(
                f"""
                #include <stdio.h>
                #include <stdlib.h>
                #include <string.h>
                #include <sys/stat.h>

                int main(int argc, char **argv) {{
                  if (argc == 2 && strcmp(argv[1], "--version") == 0) {{
                    puts("{PRODUCT} {VERSION}");
                    return 0;
                  }}
                  if (argc == 2 && strcmp(argv[1], "--probe-env") == 0) {{
                    const char *home = getenv("HOME");
                    const char *tmp = getenv("TMPDIR");
                    const char *path = getenv("PATH");
                    if (getenv("ATTACKER") || getenv("HTTP_PROXY") ||
                        getenv("CHROME_LOG_FILE") || getenv("SSLKEYLOGFILE")) return 71;
                    if (!home || !tmp || !path) return 72;
                    if (strstr(home, "/private/tmp/wins-release-browser.") != home) return 73;
                    if (strstr(tmp, "/private/tmp/wins-release-browser.") != tmp) return 74;
                    puts("clean-browser-env");
                    return 0;
                  }}
                  if (argc == 2 && strcmp(argv[1], "--mutate-self") == 0) {{
                    if (chmod(argv[0], 0700) != 0) return 75;
                    FILE *stream = fopen(argv[0], "ab");
                    if (!stream) return 76;
                    if (fputc(1, stream) == EOF || fclose(stream) != 0) return 77;
                    if (chmod(argv[0], 0500) != 0) return 78;
                    return 0;
                  }}
                  return 79;
                }}
                """
            ).lstrip(),
            encoding="ascii",
        )
        completed = subprocess.run(
            ["/usr/bin/clang", "-Os", "-arch", architecture, "-o", str(binary), str(source)],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise unittest.SkipTest(f"clang {architecture} fixture unavailable: {completed.stderr}")
        return binary

    @classmethod
    def _info_plist(cls, version: str = VERSION) -> str:
        return textwrap.dedent(
            f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0">
            <dict>
              <key>CFBundleExecutable</key>
              <string>{PRODUCT}</string>
              <key>CFBundleIdentifier</key>
              <string>com.google.chrome.for.testing</string>
              <key>CFBundleName</key>
              <string>{PRODUCT}</string>
              <key>CFBundlePackageType</key>
              <string>APPL</string>
              <key>CFBundleShortVersionString</key>
              <string>{version}</string>
              <key>CFBundleVersion</key>
              <string>{version}</string>
            </dict>
            </plist>
            """
        )

    @classmethod
    def _write_signed_tree(cls, root: Path, binary: Path, version: str = VERSION) -> None:
        macos = root / APP / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        shutil.copyfile(binary, macos / PRODUCT)
        (root / APP / "Contents" / "Info.plist").write_text(cls._info_plist(version), encoding="ascii")
        (root / "LICENSE").write_bytes(b"synthetic Chrome for Testing fixture\n")
        os.chmod(macos / PRODUCT, 0o755)
        signed = subprocess.run(
            [
                "/usr/bin/codesign",
                "--sign",
                "-",
                "--force",
                "--timestamp=none",
                "--identifier",
                PRODUCT,
                str(root / APP),
            ],
            capture_output=True,
            text=True,
        )
        if signed.returncode != 0:
            raise unittest.SkipTest(f"adhoc codesign unavailable: {signed.stderr}")
        for path in [root, *root.rglob("*")]:
            if path.is_symlink():
                continue
            if path.is_dir():
                path.chmod(0o500)
            elif path.relative_to(root).as_posix() == EXECUTABLE:
                path.chmod(0o500)
            else:
                path.chmod(0o400)

    @classmethod
    def _zip_tree(cls, source_parent: Path, archive: Path, compress: int = zipfile.ZIP_STORED) -> None:
        archive.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive, "w", compression=compress) as bundle:
            for path in sorted(source_parent.rglob("*"), key=lambda item: os.fsencode(str(item))):
                relative = path.relative_to(source_parent).as_posix()
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    member = zipfile.ZipInfo(relative)
                    member.create_system = 3
                    member.external_attr = (stat.S_IFLNK | 0o755) << 16
                    bundle.writestr(member, os.readlink(path).encode("utf-8"))
                elif stat.S_ISDIR(info.st_mode):
                    member = _zip_info(relative, 0o755, directory=True)
                    bundle.writestr(member, b"")
                else:
                    member = _zip_info(relative, stat.S_IMODE(info.st_mode))
                    member.compress_type = compress
                    bundle.writestr(member, path.read_bytes())

    @classmethod
    def _write_zip(cls, path: Path, entries: list[tuple[str, str, bytes | str, int]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as bundle:
            for name, kind, payload, mode in entries:
                if kind == "dir":
                    bundle.writestr(_zip_info(name, mode, directory=True), b"")
                elif kind == "file":
                    bundle.writestr(_zip_info(name, mode), bytes(payload))
                elif kind == "symlink":
                    member = zipfile.ZipInfo(name)
                    member.create_system = 3
                    member.external_attr = (stat.S_IFLNK | 0o777) << 16
                    bundle.writestr(member, str(payload).encode("utf-8"))
                elif kind == "fifo":
                    member = zipfile.ZipInfo(name)
                    member.create_system = 3
                    member.external_attr = (stat.S_IFIFO | 0o644) << 16
                    bundle.writestr(member, b"")
                else:
                    raise AssertionError(f"unknown fixture kind: {kind}")

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

    def _assert_nonfinite_json_boundary(
        self,
        parser: object,
        payload: bytes,
        boundary: str,
        *,
        nested_path: tuple[str, ...] = (),
    ) -> None:
        constants = (
            ("NaN", float("nan")),
            ("Infinity", float("inf")),
            ("-Infinity", float("-inf")),
        )
        for token, value in constants:
            for placement in ("top-level", "nested"):
                document = json.loads(payload)
                target = document
                if placement == "nested":
                    for key in nested_path:
                        target = target[key]
                    target["_nonfinite_probe"] = {"value": value}
                else:
                    target["_nonfinite_probe"] = value
                hostile = json.dumps(document, allow_nan=True).encode("ascii")
                with self.subTest(
                    boundary=boundary,
                    token=token,
                    placement=placement,
                ):
                    with self.assertRaisesRegex(
                        MODULE.Refused,
                        rf"non-finite JSON constant rejected: {re.escape(token)}",
                    ):
                        parser(hostile)

    def _copy_archive(self, name: str | None = None) -> Path:
        destination = self.case / (name or self.archive.name)
        shutil.copyfile(self.archive, destination)
        destination.chmod(0o444)
        return destination

    def _manifest(
        self,
        archive: Path | None = None,
        *,
        archive_sha: str | None = None,
        tree_sha: str | None = None,
        binary_sha: str | None = None,
        archive_format: str = "zip",
        version: str = VERSION,
        product: str = PRODUCT,
        signing_identity: str = IDENTITY,
        architecture: str = "arm64",
        extra: dict[str, object] | None = None,
    ) -> Path:
        archive = archive or self.archive
        browser: dict[str, object] = {
            "product": product,
            "version": version,
            "platform": "mac-arm64",
            "architecture": architecture,
            "archive_format": archive_format,
            "archive_path": {"darwin_arm64": str(archive)},
            "archive_sha256": {"darwin_arm64": archive_sha or sha256(archive)},
            "install_tree_sha256": {"darwin_arm64": tree_sha or self.tree_sha},
            "top_level_root": TOP,
            "executable": EXECUTABLE,
            "executable_sha256": binary_sha or self.binary_sha,
            "signing_identity": signing_identity,
        }
        if extra:
            browser.update(extra)
        data = {"tools": {"browser": browser}}
        manifest = self.case / "pins.json"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        manifest.chmod(0o600)
        return manifest

    def _cli(
        self,
        *arguments: str,
        env: dict[str, str] | None = None,
        timeout: int = 90,
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

    def _prepare(self, manifest: Path, timeout: int = 90) -> dict[str, str]:
        return self._install(manifest)

    def _verification(self, fields: dict[str, str]) -> list[str]:
        return [
            fields["RUNTIME"],
            fields["RUNTIME_ID"],
            fields["ROOT"],
            fields["TREE_SHA256"],
            fields["BINARY"],
            fields["BINARY_SHA256"],
            fields["APP"],
            fields["SIGNING_IDENTITY"],
        ]

    def _cleanup_if_present(self, fields: dict[str, str]) -> None:
        runtime = Path(fields["RUNTIME"])
        if runtime.exists() and not runtime.is_symlink():
            self._cli("cleanup", fields["RUNTIME"], fields["RUNTIME_ID"], timeout=180)

    def _runtime_dirs(self) -> Path:
        runtime = self.case / "rt"
        (runtime / "state" / "home").mkdir(parents=True)
        (runtime / "state" / "tmp").mkdir(parents=True)
        (runtime / "exec").mkdir(parents=True)
        return runtime

    def test_prepare_verify_run_and_cleanup(self) -> None:
        archive = self._copy_archive()
        fields = self._prepare(self._manifest(archive))
        self.assertEqual(fields["PRODUCT"], PRODUCT)
        self.assertEqual(fields["VERSION"], VERSION)
        self.assertEqual(fields["TARGET"], MODULE.TARGET_ID)
        self.assertEqual(fields["SIGNING_IDENTITY"], IDENTITY)
        verified = self._cli("verify", *self._verification(fields))
        self.assertEqual(verified.returncode, 0, verified.stderr)
        env = os.environ.copy()
        env.update(
            {
                "ATTACKER": "must-not-reach-chrome",
                "HTTP_PROXY": "http://127.0.0.1:9",
                "CHROME_LOG_FILE": "/private/tmp/attacker.log",
                "SSLKEYLOGFILE": "/private/tmp/attacker.keys",
                "PATH": "/private/tmp/fake-chrome-bin",
            }
        )
        ran = self._cli("run", *self._verification(fields), "--", "--probe-env", env=env)
        self.assertNotEqual(ran.returncode, 0, ran.stderr)
        self.assertRegex(ran.stderr, r"owner/environment blocker")
        missing = self._cli("run", *self._verification(fields))
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("argument separator", missing.stderr)
        mutated = self._cli("run", *self._verification(fields), "--", "--mutate-self")
        self.assertNotEqual(mutated.returncode, 0)
        self.assertRegex(mutated.stderr, r"owner/environment blocker|digest mismatch")
        still = self._cli("verify", *self._verification(fields))
        self.assertEqual(still.returncode, 0, still.stderr)
        cleaned = self._cli("cleanup", fields["RUNTIME"], fields["RUNTIME_ID"])
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertFalse(Path(fields["RUNTIME"]).exists())

    def test_shell_caller_manifest_cannot_self_authorize(self) -> None:
        archive = self._copy_archive()
        manifest = self._manifest(archive)
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex.quote(str(SHELL))}
            wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
            wins_release_browser_prepare {shlex.quote(str(TOOL))} {shlex.quote(str(manifest))}
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
        self.assertRegex(completed.stderr, r"cannot self-authorize|substituted")

    def test_shell_copied_controller_cannot_self_authorize(self) -> None:
        controller = self.case / "browser-controller.py"
        shutil.copyfile(TOOL, controller)
        controller.chmod(0o600)
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex.quote(str(SHELL))}
            wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
            wins_release_browser_prepare {shlex.quote(str(controller))} {shlex.quote(str(PIN_MANIFEST))}
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
        self.assertRegex(completed.stderr, r"malicious or substituted|cannot self-authorize")

    def test_shell_requires_authenticated_python_function(self) -> None:
        script = f"source {shlex.quote(str(SHELL))}; _wins_rb_python verify"
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
            wins_release_browser_run --version
            """
        )
        completed = subprocess.run(
            ["/bin/bash", "-c", script], capture_output=True, text=True
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Chrome custody is not prepared", completed.stderr)

    def test_archive_symlink_and_hardlink_members_are_rejected(self) -> None:
        for kind, target, pattern in (
            ("symlink", "/private/tmp/attacker", "unsafe or non-canonical"),
            ("fifo", "LICENSE", "special files"),
        ):
            with self.subTest(kind=kind):
                archive = self.case / f"{kind}.zip"
                entries = [
                    (TOP, "dir", b"", 0o755),
                    (f"{TOP}/unsafe-{kind}", kind, target, 0o777),
                ]
                self._write_zip(archive, entries)
                with self.assertRaisesRegex(MODULE.Refused, pattern):
                    MODULE.safe_extract(archive, self.case / f"expanded-{kind}", TOP)

    def test_safe_relative_symlink_is_authenticated(self) -> None:
        archive = self.case / f"{TOP}-{VERSION}.zip"
        with zipfile.ZipFile(self.archive) as source, zipfile.ZipFile(archive, "w") as bundle:
            for item in source.infolist():
                bundle.writestr(item, b"" if item.is_dir() else source.read(item))
            member = zipfile.ZipInfo(f"{TOP}/alias")
            member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o755) << 16
            bundle.writestr(member, b"LICENSE")
        archive.chmod(0o444)
        root = MODULE.safe_extract(archive, self.case / "expanded-safe-link", TOP)
        link = root / "alias"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "LICENSE")
        self.assertEqual((root / "LICENSE").read_bytes(), b"synthetic Chrome for Testing fixture\n")
        tree_sha = MODULE.tree_hash(root)
        binary_sha = sha256(root / EXECUTABLE)
        fields = self._prepare(
            self._manifest(archive, tree_sha=tree_sha, binary_sha=binary_sha)
        )
        self.assertEqual(fields["TREE_SHA256"], tree_sha)

    def test_path_traversal_absolute_and_case_collision_are_rejected(self) -> None:
        cases = {
            "traversal": [
                (TOP, "dir", b"", 0o755),
                (f"{TOP}/../escape", "file", b"x", 0o644),
            ],
            "absolute": [
                (TOP, "dir", b"", 0o755),
                ("/tmp/evil", "file", b"x", 0o644),
            ],
            "collision": [
                (TOP, "dir", b"", 0o755),
                (f"{TOP}/Readme", "file", b"a", 0o644),
                (f"{TOP}/README", "file", b"b", 0o644),
            ],
        }
        for label, entries in cases.items():
            with self.subTest(label=label):
                archive = self.case / f"{label}.zip"
                self._write_zip(archive, entries)
                with self.assertRaises(MODULE.Refused):
                    MODULE.safe_extract(archive, self.case / f"expanded-{label}", TOP)

    def test_unicode_and_duplicate_members_are_rejected(self) -> None:
        nfd = unicodedata.normalize("NFD", "cafe\u0301")
        archive = self.case / "unicode.zip"
        self._write_zip(
            archive,
            [
                (TOP, "dir", b"", 0o755),
                (f"{TOP}/{nfd}", "file", b"x", 0o644),
            ],
        )
        with self.assertRaisesRegex(MODULE.Refused, "non-canonical"):
            MODULE.safe_extract(archive, self.case / "expanded-unicode", TOP)
        duplicate = self.case / "duplicate.zip"
        with zipfile.ZipFile(duplicate, "w") as bundle:
            bundle.writestr(_zip_info(f"{TOP}/", 0o755, directory=True), b"")
            bundle.writestr(_zip_info(f"{TOP}/file", 0o644), b"one")
            bundle.writestr(_zip_info(f"{TOP}/file", 0o644), b"two")
        with self.assertRaisesRegex(MODULE.Refused, "duplicate"):
            MODULE.safe_extract(duplicate, self.case / "expanded-duplicate", TOP)

    def test_zip_comment_trailer_and_encryption_are_rejected(self) -> None:
        commented = self.case / "commented.zip"
        shutil.copyfile(self.archive, commented)
        with zipfile.ZipFile(commented, "a") as bundle:
            bundle.comment = b"archive-comment"
        with self.assertRaisesRegex(MODULE.Refused, "comments or trailing"):
            MODULE.safe_extract(commented, self.case / "expanded-comment", TOP)
        trailing = self.case / "trailing.zip"
        shutil.copyfile(self.archive, trailing)
        with trailing.open("ab") as stream:
            stream.write(b"trailer-bytes")
        with self.assertRaisesRegex(MODULE.Refused, "comments or trailing"):
            MODULE.safe_extract(trailing, self.case / "expanded-trailer", TOP)
        encrypted = self.case / "encrypted.zip"
        with zipfile.ZipFile(encrypted, "w") as bundle:
            member = _zip_info(f"{TOP}/secret", 0o644)
            bundle.writestr(member, b"secret")
            bundle.writestr(_zip_info(f"{TOP}/", 0o755, directory=True), b"")
        raw = bytearray(encrypted.read_bytes())
        offset = 0
        while True:
            local = raw.find(b"PK\x03\x04", offset)
            central = raw.find(b"PK\x01\x02", offset)
            hits = [value for value in (local, central) if value >= 0]
            if not hits:
                break
            index = min(hits)
            flag_at = index + (6 if raw.startswith(b"PK\x03\x04", index) else 8)
            raw[flag_at] |= 1
            offset = index + 4
        encrypted.write_bytes(raw)
        with self.assertRaisesRegex(MODULE.Refused, "encrypted"):
            MODULE.safe_extract(encrypted, self.case / "expanded-encrypted", TOP)

    def test_excessive_depth_size_and_ratio_are_rejected(self) -> None:
        deep = self.case / "deep.zip"
        deep_name = "/".join([TOP, *(["deep"] * 32)])
        self._write_zip(
            deep,
            [
                (TOP, "dir", b"", 0o755),
                (deep_name, "file", b"x", 0o644),
            ],
        )
        with self.assertRaisesRegex(MODULE.Refused, "depth"):
            MODULE.safe_extract(deep, self.case / "expanded-deep", TOP)
        oversized = self.case / "size-limit.zip"
        self._write_zip(
            oversized,
            [
                (TOP, "dir", b"", 0o755),
                (f"{TOP}/big", "file", b"0123456789", 0o644),
            ],
        )
        with mock.patch.object(MODULE, "MAX_MEMBER", 8):
            with self.assertRaisesRegex(MODULE.Refused, "expanded size"):
                MODULE.safe_extract(oversized, self.case / "expanded-size", TOP)
        ratio = self.case / "ratio.zip"
        with zipfile.ZipFile(ratio, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr(_zip_info(f"{TOP}/", 0o755, directory=True), b"")
            payload = _zip_info(f"{TOP}/zeros", 0o644)
            payload.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(payload, b"a" * 4096)
        with mock.patch.object(MODULE, "MAX_RATIO", 1):
            with self.assertRaisesRegex(MODULE.Refused, "compression ratio"):
                MODULE.safe_extract(ratio, self.case / "expanded-ratio", TOP)

    def test_wrong_root_is_rejected(self) -> None:
        archive = self.case / "wrong-root.zip"
        self._write_zip(
            archive,
            [
                ("other-root", "dir", b"", 0o755),
                ("other-root/file", "file", b"x", 0o644),
            ],
        )
        with self.assertRaisesRegex(MODULE.Refused, "escaped its pinned top-level root"):
            MODULE.safe_extract(archive, self.case / "expanded-root", TOP)

    def test_writable_symlink_and_hardlinked_input_archives_are_rejected(self) -> None:
        writable = self._copy_archive()
        writable.chmod(0o644)
        with self.assertRaisesRegex(MODULE.Refused, "mode 0444"):
            MODULE.require_safe_input(writable, writable.name)
        linked = self.case / "hardlink.zip"
        os.link(self.archive, linked)
        with self.assertRaisesRegex(MODULE.Refused, "one owner-controlled"):
            MODULE.require_safe_input(linked, linked.name)
        aliased = self.case / f"{TOP}-{VERSION}-alias.zip"
        aliased.symlink_to(self.archive)
        with self.assertRaises(MODULE.Refused):
            MODULE.require_safe_input(aliased, aliased.name)
        unversioned = self._copy_archive(f"{TOP}.zip")
        with self.assertRaisesRegex(MODULE.Refused, "basename"):
            MODULE.require_safe_input(unversioned, f"{TOP}-{VERSION}.zip")

    def test_wrong_archive_tree_binary_and_identity_hashes_fail_closed(self) -> None:
        archive = self._copy_archive()
        cases = (
            {"archive_sha": "0" * 64},
            {"tree_sha": "1" * 64},
            {"binary_sha": "2" * 64},
            {"signing_identity": "Developer ID Application: Example (AAAAAAAAAA)"},
            {"product": "Google Chrome"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                manifest = self._manifest(archive, **overrides)
                with self.assertRaises(MODULE.Refused):
                    MODULE.install_extracted_runtime(
                        MODULE.parse_pin_bytes(manifest.read_bytes())
                    )

    def test_zip_format_and_duplicate_manifest_keys_are_rejected(self) -> None:
        archive = self._copy_archive()
        manifest = self._manifest(archive, archive_format="tar.xz")
        with self.assertRaisesRegex(MODULE.Refused, "ZIP archives"):
            MODULE.load_pin(manifest)
        duplicate = self.case / "duplicate.json"
        duplicate.write_text(
            '{"tools":{"browser":{"version":"1.2.3.4","version":"5.6.7.8"}}}',
            encoding="ascii",
        )
        duplicate.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, "duplicate JSON key"):
            MODULE.load_pin(duplicate)
        self._assert_nonfinite_json_boundary(
            MODULE.parse_pin_bytes,
            self._manifest(archive).read_bytes(),
            "browser pin",
            nested_path=("tools", "browser"),
        )
        extra = self._manifest(archive, extra={"note": "not part of the exact schema"})
        with self.assertRaisesRegex(MODULE.Refused, "unexpected Chrome pin field"):
            MODULE.load_pin(extra)
        production = MODULE.parse_production_manifest(PIN_MANIFEST.read_bytes())
        self.assertEqual(production["version"], REAL_VERSION)
        self.assertEqual(production["archive_sha"], REAL_ARCHIVE_SHA256)
        extra_root = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))
        extra_root["note"] = "not part of the exact schema"
        extra_doc = self.case / "extra-document.json"
        extra_doc.write_text(json.dumps(extra_root), encoding="utf-8")
        extra_doc.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, r"document\.note"):
            MODULE.parse_production_manifest(extra_doc.read_bytes())
        wrong_key = self.case / "chrome-for-testing.json"
        wrong_key.write_text(
            json.dumps({"tools": {"chrome_for_testing": {"version": VERSION}}}),
            encoding="utf-8",
        )
        wrong_key.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, "tools.browser"):
            MODULE.load_pin(wrong_key)

    def test_wrong_architecture_is_rejected(self) -> None:
        foreign = self._compile_fixture("x86_64")
        tree = self.case / "x86" / TOP
        self._write_signed_tree(tree, foreign)
        archive = self.case / f"{TOP}-{VERSION}.zip"
        self._zip_tree(tree.parent, archive)
        archive.chmod(0o444)
        manifest = self._manifest(
            archive,
            archive_sha=sha256(archive),
            tree_sha=MODULE.tree_hash(tree),
            binary_sha=sha256(tree / EXECUTABLE),
        )
        completed = self._cli("prepare", str(manifest))
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, r"cannot self-authorize|architecture|malformed")
        with self.assertRaisesRegex(MODULE.Refused, "architecture"):
            MODULE.install_extracted_runtime(MODULE.parse_pin_bytes(manifest.read_bytes()))

    def test_unsigned_bundle_is_rejected(self) -> None:
        tree = self.case / "unsigned" / TOP
        macos = tree / APP / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        shutil.copyfile(self.binary, macos / PRODUCT)
        (tree / APP / "Contents" / "Info.plist").write_text(self._info_plist(), encoding="ascii")
        (tree / "LICENSE").write_bytes(b"unsigned\n")
        (macos / PRODUCT).chmod(0o500)
        (tree / APP / "Contents" / "Info.plist").chmod(0o400)
        (tree / "LICENSE").chmod(0o400)
        for directory in [tree, tree / APP, tree / APP / "Contents", macos]:
            directory.chmod(0o500)
        archive = self.case / f"{TOP}-{VERSION}.zip"
        self._zip_tree(tree.parent, archive)
        archive.chmod(0o444)
        manifest = self._manifest(
            archive,
            archive_sha=sha256(archive),
            tree_sha=MODULE.tree_hash(tree),
            binary_sha=sha256(tree / EXECUTABLE),
        )
        completed = self._cli("prepare", str(manifest))
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, r"cannot self-authorize|code signature|malformed")
        with self.assertRaisesRegex(MODULE.Refused, "code signature"):
            MODULE.install_extracted_runtime(MODULE.parse_pin_bytes(manifest.read_bytes()))

    def test_runtime_content_and_pointer_replacement_are_detected(self) -> None:
        archive = self._copy_archive()
        fields = self._prepare(self._manifest(archive))
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
        app_swap = self._verification(fields)
        app_swap[6] = str(ROOT)
        replaced = self._cli("verify", *app_swap)
        self.assertNotEqual(replaced.returncode, 0)

    def test_runtime_state_symlink_replacement_is_detected(self) -> None:
        archive = self._copy_archive()
        fields = self._prepare(self._manifest(archive))
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
        aliased = Path("/private/tmp") / "wins-release-browser.symlink-cleanup"
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

    def test_real_macos_arm64_chrome_for_testing_archive(self) -> None:
        if not real_archive_ready():
            self.skipTest("real Chrome for Testing 152.0.7977.54 archive is unavailable")
        extracted = self.case / "real-extracted"
        root = MODULE.safe_extract(REAL_ARCHIVE, extracted, TOP)
        tree_sha = MODULE.tree_hash(root)
        binary_sha = MODULE.digest_file(root / EXECUTABLE)
        self.assertEqual(tree_sha, REAL_TREE_SHA256)
        self.assertEqual(binary_sha, REAL_BINARY_SHA256)
        app = root / APP
        self.assertTrue((root / EXECUTABLE).is_file())
        self.assertTrue((app / "Contents/Info.plist").is_file())
        self.assertEqual(
            os.readlink(
                app
                / "Contents/Frameworks/Google Chrome for Testing Framework.framework/Versions/Current"
            ),
            REAL_VERSION,
        )
        manifest = self._manifest(
            REAL_ARCHIVE,
            archive_sha=REAL_ARCHIVE_SHA256,
            tree_sha=tree_sha,
            binary_sha=binary_sha,
            version=REAL_VERSION,
        )
        fields = self._prepare(manifest, timeout=180)
        self.assertEqual(fields["VERSION"], REAL_VERSION)
        self.assertEqual(fields["PRODUCT"], PRODUCT)
        self.assertEqual(fields["TREE_SHA256"], tree_sha)
        self.assertEqual(fields["BINARY_SHA256"], binary_sha)
        self.assertEqual(fields["SIGNING_IDENTITY"], IDENTITY)
        verified = self._cli("verify", *self._verification(fields), timeout=180)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        probed = self._cli(
            "run", *self._verification(fields), "--", "--version", timeout=60
        )
        self.assertNotEqual(probed.returncode, 0, probed.stderr)
        self.assertRegex(probed.stderr, r"owner/environment blocker")
        production = MODULE.parse_production_manifest(PIN_MANIFEST.read_bytes())
        self.assertEqual(production["archive_sha"], REAL_ARCHIVE_SHA256)
        self.assertEqual(production["tree_sha"], REAL_TREE_SHA256)
        self.assertEqual(production["executable_sha"], REAL_BINARY_SHA256)
        self.assertEqual(production["version"], REAL_VERSION)
        Path(self.case / "real-layout.json").write_text(
            json.dumps(
                {
                    "archive": str(REAL_ARCHIVE),
                    "archive_sha256": REAL_ARCHIVE_SHA256,
                    "install_tree_sha256": tree_sha,
                    "executable": EXECUTABLE,
                    "executable_sha256": binary_sha,
                    "top_level_root": TOP,
                    "version": REAL_VERSION,
                    "product": PRODUCT,
                    "signing_identity": IDENTITY,
                },
                indent=2,
            )
            + "\n",
            encoding="ascii",
        )
        print(
            f"REAL_LAYOUT archive_sha256={REAL_ARCHIVE_SHA256} "
            f"install_tree_sha256={tree_sha} executable_sha256={binary_sha}",
            flush=True,
        )

    def test_copy_stable_keeps_authenticated_descriptor(self) -> None:
        dest = self.case / "incoming.zip"
        handle = MODULE.copy_stable(self.archive, dest, sha256(self.archive))
        try:
            self.assertGreaterEqual(handle.fd, 0)
            self.assertEqual(handle.digest, sha256(self.archive))
            self.assertEqual(MODULE._hash_fd(handle.fd), handle.digest)
            handle.ensure_bound()
            self.assertEqual(os.fstat(handle.fd).st_ino, dest.stat().st_ino)
            self.assertTrue(stat.S_ISREG(os.fstat(handle.fd).st_mode))
        finally:
            handle.close()

    def test_post_copy_path_swap_is_rejected(self) -> None:
        dest = self.case / "incoming.zip"
        other = self.case / "other.zip"
        self._zip_tree(self.reference.parent, other, compress=zipfile.ZIP_DEFLATED)
        other.chmod(0o444)
        self.assertNotEqual(sha256(self.archive), sha256(other))
        extracted = MODULE.safe_extract(other, self.case / "other-tree", TOP)
        self.assertEqual(MODULE.tree_hash(extracted), self.tree_sha)
        handle = MODULE.copy_stable(self.archive, dest, sha256(self.archive))
        try:
            os.unlink(dest)
            shutil.copyfile(other, dest)
            dest.chmod(0o400)
            with self.assertRaisesRegex(MODULE.Refused, "replaced"):
                MODULE.safe_extract(handle, self.case / "extracted-swap", TOP)
        finally:
            handle.close()

    def test_post_copy_restore_is_rejected(self) -> None:
        dest = self.case / "incoming.zip"
        original = self.archive.read_bytes()
        other = self.case / "other.zip"
        self._zip_tree(self.reference.parent, other, compress=zipfile.ZIP_DEFLATED)
        handle = MODULE.copy_stable(self.archive, dest, sha256(self.archive))
        try:
            os.unlink(dest)
            dest.write_bytes(other.read_bytes())
            dest.chmod(0o400)
            os.unlink(dest)
            dest.write_bytes(original)
            dest.chmod(0o400)
            with self.assertRaisesRegex(MODULE.Refused, "replaced"):
                MODULE.safe_extract(handle, self.case / "extracted-restore", TOP)
        finally:
            handle.close()

    def test_invalid_signature_is_rejected(self) -> None:
        tree = self.case / "badsig" / TOP
        self._write_signed_tree(tree, self.binary)
        exe = tree / EXECUTABLE
        for path in tree.rglob("*"):
            if path.is_file() and not path.is_symlink():
                path.chmod(path.stat().st_mode | stat.S_IWUSR)
        mutated = bytearray(exe.read_bytes())
        mutated[-1] ^= 1
        exe.write_bytes(mutated)
        plist = tree / APP / "Contents" / "Info.plist"
        plist.chmod(plist.stat().st_mode | stat.S_IWUSR)
        plist.write_bytes(plist.read_bytes() + b"\n")
        for path in [tree, *tree.rglob("*")]:
            if path.is_symlink():
                continue
            if path.is_dir():
                path.chmod(0o500)
            elif path.relative_to(tree).as_posix() == EXECUTABLE:
                path.chmod(0o500)
            else:
                path.chmod(0o400)
        with self.assertRaisesRegex(MODULE.Refused, "strict verification"):
            MODULE._codesign_identity(self._runtime_dirs(), tree / APP, exe)
        archive = self.case / f"{TOP}-{VERSION}.zip"
        self._zip_tree(tree.parent, archive)
        archive.chmod(0o444)
        manifest = self._manifest(
            archive,
            archive_sha=sha256(archive),
            tree_sha=MODULE.tree_hash(tree),
            binary_sha=sha256(tree / EXECUTABLE),
        )
        with self.assertRaisesRegex(MODULE.Refused, "strict verification"):
            MODULE.install_extracted_runtime(MODULE.parse_pin_bytes(manifest.read_bytes()))

    def test_zip_preamble_is_rejected(self) -> None:
        archive = self.case / "preamble.zip"
        archive.write_bytes(b"MZSTUB" + self.archive.read_bytes())
        with self.assertRaisesRegex(MODULE.Refused, "preamble|concatenated"):
            MODULE.safe_extract(archive, self.case / "extracted-preamble", TOP)

    def test_concatenated_zip_is_rejected(self) -> None:
        extra = self.case / "extra.zip"
        self._write_zip(
            extra,
            [
                (TOP, "dir", b"", 0o755),
                (f"{TOP}/LICENSE", "file", b"other\n", 0o644),
            ],
        )
        concatenated = self.case / "concatenated.zip"
        concatenated.write_bytes(self.archive.read_bytes() + extra.read_bytes())
        with self.assertRaisesRegex(MODULE.Refused, "preamble|concatenated|gap"):
            MODULE.safe_extract(concatenated, self.case / "extracted-concat", TOP)

    def test_codesign_verify_deep_strict_runs_on_frozen_bundle(self) -> None:
        fields = self._prepare(self._manifest(self._copy_archive()))
        calls: list[tuple[str, ...]] = []
        real = MODULE._run_system

        def wrapper(runtime: Path, tool: Path, *arguments: str):
            calls.append((str(tool),) + arguments)
            return real(runtime, tool, *arguments)

        with mock.patch.object(MODULE, "_run_system", wrapper):
            identity = MODULE._codesign_identity(
                Path(fields["RUNTIME"]),
                Path(fields["APP"]),
                Path(fields["BINARY"]),
            )
        verify_calls = [call for call in calls if "--verify" in call]
        self.assertTrue(verify_calls)
        self.assertTrue(any("--deep" in call and "--strict" in call for call in verify_calls))
        self.assertTrue(any(call[-1] == fields["APP"] for call in verify_calls))
        self.assertTrue(any("--display" in call for call in calls))
        self.assertEqual(identity, IDENTITY)
        self.assertEqual(fields["SIGNING_IDENTITY"], IDENTITY)

    def test_adhoc_trust_root_is_digests_not_publisher(self) -> None:
        self.assertIn("ad-hoc signed", MODULE.TRUST_ROOT_NOTE.lower().replace("adhoc", "ad-hoc"))
        self.assertIn("not Apple publisher identity", MODULE.TRUST_ROOT_NOTE)
        self.assertIn("archive", MODULE.TRUST_ROOT_NOTE.lower())
        self.assertIn("--verify --deep --strict", MODULE.TRUST_ROOT_NOTE)
        fields = self._prepare(self._manifest(self._copy_archive()))
        self.assertEqual(fields["SIGNING_IDENTITY"], IDENTITY)
        self.assertEqual(fields["TREE_SHA256"], self.tree_sha)
        self.assertEqual(fields["BINARY_SHA256"], self.binary_sha)

    def test_oversized_central_directory_is_rejected(self) -> None:
        with mock.patch.object(MODULE, "MAX_CENTRAL_DIR", 64):
            with self.assertRaisesRegex(MODULE.Refused, "central directory"):
                MODULE.safe_extract(self.archive, self.case / "extracted-cd", TOP)

    def test_oversized_zip_extra_is_rejected(self) -> None:
        archive = self.case / "extra.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(_zip_info(f"{TOP}/", 0o755, directory=True), b"")
            member = _zip_info(f"{TOP}/file", 0o644)
            member.extra = struct.pack("<HH", 0x9999, 5000) + b"\x00" * 5000
            bundle.writestr(member, b"x")
        with self.assertRaisesRegex(MODULE.Refused, "extra"):
            MODULE.safe_extract(archive, self.case / "extracted-extra", TOP)

    def test_member_comment_is_rejected(self) -> None:
        archive = self.case / "comment-member.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(_zip_info(f"{TOP}/", 0o755, directory=True), b"")
            member = _zip_info(f"{TOP}/file", 0o644)
            member.comment = b"member-comment"
            bundle.writestr(member, b"x")
        with self.assertRaisesRegex(MODULE.Refused, "comment"):
            MODULE.safe_extract(archive, self.case / "extracted-member-comment", TOP)

    def test_zip64_end_fields_are_rejected(self) -> None:
        archive = self.case / "zip64.zip"
        raw = bytearray(self.archive.read_bytes())
        raw[-6:-2] = b"\xff\xff\xff\xff"
        archive.write_bytes(raw)
        with self.assertRaisesRegex(MODULE.Refused, "ZIP64|end record|central"):
            MODULE.safe_extract(archive, self.case / "extracted-zip64", TOP)

    def test_zip64_extra_field_is_rejected(self) -> None:
        archive = self.case / "zip64-extra.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(_zip_info(f"{TOP}/", 0o755, directory=True), b"")
            member = _zip_info(f"{TOP}/file", 0o644)
            member.extra = struct.pack("<HHQ", 1, 8, 1)
            bundle.writestr(member, b"x")
        with self.assertRaisesRegex(MODULE.Refused, "ZIP64"):
            MODULE.safe_extract(archive, self.case / "extracted-zip64-extra", TOP)

    def test_chmod_executable_swap_and_restore_cannot_substitute_code(self) -> None:
        fields = self._prepare(self._manifest(self._copy_archive()))
        binary = Path(fields["BINARY"])
        original = binary.read_bytes()
        attacker_src = self.case / "attacker.c"
        attacker = self.case / "attacker"
        attacker_src.write_text("int main(void) { return 42; }\n", encoding="ascii")
        compiled = subprocess.run(
            ["/usr/bin/clang", "-Os", "-arch", "arm64", "-o", str(attacker), str(attacker_src)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        with self.assertRaisesRegex(MODULE.Refused, "owner/environment blocker"):
            MODULE.authenticated_execution_image(
                binary, fields["BINARY_SHA256"], Path(fields["RUNTIME"])
            )
        self.assertFalse((Path(fields["RUNTIME"]) / "exec/tree").exists())
        replaced_sha = hashlib.sha256(attacker.read_bytes()).hexdigest()
        self.assertNotEqual(replaced_sha, fields["BINARY_SHA256"])
        binary.chmod(0o700)
        shutil.copyfile(attacker, binary)
        binary.chmod(0o500)
        try:
            with mock.patch.object(MODULE, "_require_nested_seatbelt", return_value=None):
                with self.assertRaisesRegex(MODULE.Refused, "digest mismatch at execution"):
                    MODULE.authenticated_execution_image(
                        binary, fields["BINARY_SHA256"], Path(fields["RUNTIME"])
                    )
        finally:
            binary.chmod(0o700)
            binary.write_bytes(original)
            binary.chmod(0o500)

    def test_post_hash_clone_tree_substitution_is_closed_before_browser_runs(self) -> None:
        fields = self._prepare(self._manifest(self._copy_archive()))
        binary = Path(fields["BINARY"])
        runtime = Path(fields["RUNTIME"])
        attacker_src = self.case / "clone-attacker.c"
        attacker = self.case / "clone-attacker"
        attacker_src.write_text("int main(void) { return 42; }\n", encoding="ascii")
        compiled = subprocess.run(
            ["/usr/bin/clang", "-Os", "-arch", "arm64", "-o", str(attacker), str(attacker_src)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        with self.assertRaisesRegex(MODULE.Refused, "owner/environment blocker"):
            MODULE.authenticated_execution_image(binary, fields["BINARY_SHA256"], runtime)
        with mock.patch.object(
            MODULE, "_kernel_seal_tree", lambda _root: None
        ), mock.patch.object(MODULE, "_require_nested_seatbelt", return_value=None):
            image = MODULE.authenticated_execution_image(
                binary, fields["BINARY_SHA256"], runtime
            )
            try:
                clone = Path(image.path)
                clone.chmod(0o700)
                shutil.copyfile(attacker, clone)
                clone.chmod(0o500)
                completed = MODULE._spawn_sandboxed_chrome(
                    image, ["--probe-env"], timeout=30, capture=True
                )
                self.assertNotEqual(completed.returncode, 42)
                self.assertNotEqual((completed.stdout or "").strip(), "clean-browser-env")
            finally:
                image.cleanup()

    def test_copy_stable_same_inode_mutate_between_hash_and_reopen_is_rejected(self) -> None:
        dest = self.case / "incoming.zip"
        expected = sha256(self.archive)
        real_hash = MODULE._hash_fd
        calls = {"count": 0}

        def mutate_after_first_hash(fd: int) -> str:
            digest = real_hash(fd)
            calls["count"] += 1
            if calls["count"] == 1:
                os.lseek(fd, 0, os.SEEK_SET)
                os.write(fd, b"X")
                os.fsync(fd)
            return digest

        with mock.patch.object(MODULE, "_hash_fd", mutate_after_first_hash):
            with self.assertRaisesRegex(MODULE.Refused, "replaced|mismatch|changed"):
                MODULE.copy_stable(self.archive, dest, expected)

    def test_copy_stable_pre_copy_oversize_is_rejected(self) -> None:
        dest = self.case / "incoming.zip"
        with mock.patch.object(MODULE, "MAX_ARCHIVE", 8):
            with self.assertRaisesRegex(MODULE.Refused, "outside the accepted range"):
                MODULE.copy_stable(self.archive, dest, sha256(self.archive))
        self.assertFalse(dest.exists())

    def test_root_and_tools_schema_extras_are_rejected(self) -> None:
        archive = self._copy_archive()
        exact = json.loads(self._manifest(archive).read_text(encoding="utf-8"))
        extra_root = self.case / "extra-root.json"
        extra_root.write_text(
            json.dumps({"note": "not part of the exact schema", **exact}),
            encoding="utf-8",
        )
        extra_root.chmod(0o600)
        parsed = MODULE.load_pin(extra_root)
        self.assertEqual(parsed["version"], VERSION)
        self._assert_nonfinite_json_boundary(
            MODULE.parse_production_manifest,
            PIN_MANIFEST.read_bytes(),
            "complete production manifest",
            nested_path=("tools", "browser"),
        )
        production = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))
        extra_document = dict(production)
        extra_document["note"] = "not part of the exact schema"
        extra_doc = self.case / "extra-production-document.json"
        extra_doc.write_text(json.dumps(extra_document), encoding="utf-8")
        extra_doc.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, r"document\.note"):
            MODULE.parse_production_manifest(extra_doc.read_bytes())
        extra_tools_document = dict(production)
        extra_tools_document["tools"] = dict(production["tools"])
        extra_tools_document["tools"]["evil"] = {"version": "1"}
        extra_tools = self.case / "extra-tools.json"
        extra_tools.write_text(json.dumps(extra_tools_document), encoding="utf-8")
        extra_tools.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, r"tools\.evil"):
            MODULE.parse_production_manifest(extra_tools.read_bytes())
        missing_tool = dict(production)
        missing_tool["tools"] = {
            key: value for key, value in production["tools"].items() if key != "kotlin"
        }
        missing = self.case / "missing-tool.json"
        missing.write_text(json.dumps(missing_tool), encoding="utf-8")
        missing.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, r"tools\.kotlin"):
            MODULE.parse_production_manifest(missing.read_bytes())

    def test_double_slash_and_dot_zip_paths_are_rejected(self) -> None:
        cases = {
            "double-slash": f"{TOP}//LICENSE",
            "dot-component": f"{TOP}/./LICENSE",
            "leading-dot": f"./{TOP}/LICENSE",
            "parent-dot": f"{TOP}/foo/../LICENSE",
        }
        for label, name in cases.items():
            with self.subTest(label=label):
                archive = self.case / f"{label}.zip"
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr(_zip_info(f"{TOP}/", 0o755, directory=True), b"")
                    bundle.writestr(_zip_info(name, 0o644), b"x")
                with self.assertRaisesRegex(MODULE.Refused, "non-canonical"):
                    MODULE.safe_extract(archive, self.case / f"expanded-{label}", TOP)

    def test_kernel_bound_exec_is_required_and_fails_closed(self) -> None:
        source = TOOL.read_text(encoding="utf-8")
        self.assertIn("fclonefileat", source)
        self.assertIn("posix_spawn", source)
        self.assertIn("sandbox-exec", source)
        self.assertIn("deny file-write*", source)
        self.assertIn("SF_IMMUTABLE", source)
        self.assertIn("owner/environment blocker", source)
        self.assertIn("authenticated current source-freeze producer digest", source)
        fields = self._prepare(self._manifest(self._copy_archive()))
        with self.assertRaisesRegex(MODULE.Refused, "owner/environment blocker"):
            MODULE.authenticated_execution_image(
                Path(fields["BINARY"]),
                fields["BINARY_SHA256"],
                Path(fields["RUNTIME"]),
            )
        with mock.patch.object(MODULE.sys, "platform", "linux"):
            with self.assertRaisesRegex(MODULE.Refused, "owner/environment blocker"):
                MODULE.authenticated_execution_image(
                    Path(fields["BINARY"]),
                    fields["BINARY_SHA256"],
                    Path(fields["RUNTIME"]),
                )
        with mock.patch.object(MODULE._LIBC, "fclonefileat", lambda *_args, **_kwargs: -1):
            with self.assertRaisesRegex(MODULE.Refused, "owner/environment blocker"):
                MODULE.authenticated_execution_image(
                    Path(fields["BINARY"]),
                    fields["BINARY_SHA256"],
                    Path(fields["RUNTIME"]),
                )
        with mock.patch.object(MODULE, "_in_sandbox", lambda: True), mock.patch.object(
            MODULE, "_posix_spawn", side_effect=OSError("nested sandbox refused")
        ):
            with self.assertRaisesRegex(MODULE.Refused, "Seatbelt cannot nest"):
                MODULE.authenticated_execution_image(
                    Path(fields["BINARY"]),
                    fields["BINARY_SHA256"],
                    Path(fields["RUNTIME"]),
                )

    def test_local_central_zip_metadata_mismatch_is_rejected(self) -> None:
        local_cases = {
            "local-method": (b"PK\x03\x04", 8, 2),
            "local-flags": (b"PK\x03\x04", 6, 0x10),
            "local-crc": (b"PK\x03\x04", 14, 1),
            "local-compress": (b"PK\x03\x04", 18, 1),
            "local-uncompress": (b"PK\x03\x04", 22, 1),
        }
        central_cases = {
            "central-method": (b"PK\x01\x02", 10, 8),
            "central-flags": (b"PK\x01\x02", 8, 0x10),
            "central-crc": (b"PK\x01\x02", 16, 1),
            "central-compress": (b"PK\x01\x02", 20, 1),
            "central-uncompress": (b"PK\x01\x02", 24, 1),
        }
        for label, (magic, offset, xor_value) in {**local_cases, **central_cases}.items():
            with self.subTest(label=label):
                archive = self.case / f"{label}.zip"
                raw = bytearray(self.archive.read_bytes())
                index = raw.find(magic)
                self.assertGreaterEqual(index, 0)
                raw[index + offset] ^= xor_value
                archive.write_bytes(raw)
                with self.assertRaisesRegex(
                    MODULE.Refused,
                    "compression method|flags|CRC|compressed size|uncompressed size",
                ):
                    MODULE.safe_extract(archive, self.case / f"expanded-{label}", TOP)

    def test_p1_manifest_path_replacement_before_open_is_rejected(self) -> None:
        archive = self._copy_archive()
        good = self._manifest(archive)
        evil = self._manifest(archive, tree_sha="1" * 64, binary_sha="2" * 64)
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

    def test_authorize_rejects_caller_controller_and_manifest(self) -> None:
        archive = self._copy_archive()
        manifest = self._manifest(archive)
        controller = self.case / "controller.py"
        shutil.copyfile(TOOL, controller)
        controller.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, r"substituted|not in the repository tools directory"):
            MODULE.authorize_custody_inputs(controller, PIN_MANIFEST)
        with self.assertRaisesRegex(MODULE.Refused, "cannot self-authorize"):
            MODULE.authorize_custody_inputs(TOOL, manifest)

    def test_authorize_and_cli_prepare_require_source_freeze(self) -> None:
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"stale Chrome custody trust refused|owner blocked|source-freeze",
        ):
            MODULE.authorize_custody_inputs(TOOL, PIN_MANIFEST)
        completed = self._cli("prepare", str(ROOT), str(PIN_MANIFEST), timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(
            completed.stderr,
            r"stale Chrome custody trust refused|owner blocked|source-freeze|malformed",
        )
        synthetic = self._cli("prepare", str(self._manifest(self._copy_archive())))
        self.assertNotEqual(synthetic.returncode, 0)
        self.assertRegex(synthetic.stderr, r"cannot self-authorize|malformed")

    def test_trust_anchor_binds_production_controller_wrapper_and_manifest(self) -> None:
        trust_bytes = TRUST.read_bytes()
        parsed = MODULE._parse_trust_anchor(trust_bytes)
        self.assertEqual(parsed["contract"], MODULE.TRUST_CONTRACT)
        self._assert_nonfinite_json_boundary(
            MODULE._parse_trust_anchor,
            trust_bytes,
            "trust anchor",
        )
        live_controller = hashlib.sha256(TOOL.read_bytes()).hexdigest()
        live_wrapper = hashlib.sha256(SHELL.read_bytes()).hexdigest()
        live_manifest = hashlib.sha256(PIN_MANIFEST.read_bytes()).hexdigest()
        self.assertEqual(live_controller, parsed["controller_sha256"])
        self.assertEqual(live_wrapper, parsed["wrapper_sha256"])
        self.assertEqual(live_manifest, parsed["manifest_sha256"])
        with self.assertRaisesRegex(MODULE.Refused, "owner blocked"):
            MODULE.authorize_custody_inputs(TOOL, PIN_MANIFEST)
        pin = MODULE.parse_production_manifest(PIN_MANIFEST.read_bytes())
        self.assertEqual(pin["version"], REAL_VERSION)
        self.assertEqual(pin["archive_sha"], REAL_ARCHIVE_SHA256)
        self.assertEqual(pin["tree_sha"], REAL_TREE_SHA256)
        self.assertEqual(pin["executable_sha"], REAL_BINARY_SHA256)
        self.assertEqual(pin["target"], MODULE.TARGET_ID)
        mutated = json.loads(TRUST.read_text(encoding="utf-8"))
        mutated["controller_sha256"] = "0" * 64
        tools = self.case / "tools"
        tools.mkdir()
        shutil.copyfile(TOOL, tools / MODULE.CONTROLLER_NAME)
        shutil.copyfile(SHELL, tools / MODULE.WRAPPER_NAME)
        shutil.copyfile(PIN_MANIFEST, tools / MODULE.MANIFEST_NAME)
        fake = tools / MODULE.TRUST_ANCHOR_NAME
        fake.write_text(json.dumps(mutated), encoding="utf-8")
        fake.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, STALE_REFUSED):
            MODULE.authorize_custody_inputs(
                tools / MODULE.CONTROLLER_NAME,
                tools / MODULE.MANIFEST_NAME,
            )
        truncated = tools / MODULE.TRUST_ANCHOR_NAME
        truncated.write_bytes(b"{")
        truncated.chmod(0o600)
        with self.assertRaisesRegex(MODULE.Refused, "not JSON"):
            MODULE.authorize_custody_inputs(
                tools / MODULE.CONTROLLER_NAME,
                tools / MODULE.MANIFEST_NAME,
            )
        bool_schema = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))
        bool_schema["schema_version"] = True
        with self.assertRaisesRegex(MODULE.Refused, "must be an integer"):
            MODULE.parse_production_manifest(
                json.dumps(bool_schema).encode("utf-8")
            )
        del live_controller, live_wrapper

    def test_cleanup_refuses_hardlinked_inodes_and_reports_residue(self) -> None:
        fields = self._prepare(self._manifest(self._copy_archive()))
        internal = Path(fields["ROOT"]) / "LICENSE"
        original_mode = stat.S_IMODE(internal.lstat().st_mode)
        original_bytes = internal.read_bytes()
        victim = self.case / "external-victim"
        os.link(internal, victim)
        try:
            completed = self._cli("cleanup", fields["RUNTIME"], fields["RUNTIME_ID"])
            self.assertNotEqual(completed.returncode, 0)
            self.assertRegex(completed.stderr, r"hardlink|external|residue")
            self.assertTrue(Path(fields["RUNTIME"]).exists())
            self.assertEqual(stat.S_IMODE(victim.lstat().st_mode), original_mode)
            self.assertEqual(victim.read_bytes(), original_bytes)
        finally:
            if victim.exists():
                victim.unlink()

    def test_cleanup_fifo_residue_is_not_marked_complete(self) -> None:
        fields = self._prepare(self._manifest(self._copy_archive()))
        poison = Path(fields["RUNTIME"]) / "poison"
        os.mkfifo(poison)
        try:
            current_id = MODULE.runtime_identity(Path(fields["RUNTIME"]))
            completed = self._cli("cleanup", fields["RUNTIME"], current_id)
            self.assertNotEqual(completed.returncode, 0)
            self.assertRegex(completed.stderr, r"unsupported|residue")
            self.assertTrue(Path(fields["RUNTIME"]).exists())
            self.assertTrue(poison.exists())
        finally:
            if poison.exists():
                poison.unlink()

    def test_shell_cleanup_does_not_clear_while_residue_remains(self) -> None:
        fields = self._prepare(self._manifest(self._copy_archive()))
        poison = Path(fields["RUNTIME"]) / "poison"
        os.mkfifo(poison)
        try:
            script = textwrap.dedent(
                f"""
                set -u
                source {shlex.quote(str(SHELL))}
                wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
                export WINS_BROWSER_CUSTODY_ISSUANCE=/private/tmp/wins-browser-issuance-cleanup
                _WINS_RB_ACTIVE_TOOL_SOURCE=$(cat {shlex.quote(str(TOOL))})
                _WINS_RB_ACTIVE_RUNTIME={shlex.quote(fields["RUNTIME"])}
                _WINS_RB_ACTIVE_RUNTIME_ID={shlex.quote(fields["RUNTIME_ID"])}
                if wins_release_browser_cleanup; then
                  printf 'CLEARED\\n'
                  exit 0
                fi
                printf 'STILL_ACTIVE:%s\\n' "${{_WINS_RB_ACTIVE_RUNTIME}}"
                exit 1
                """
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", script],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn("CLEARED", completed.stdout)
            self.assertIn(f"STILL_ACTIVE:{fields['RUNTIME']}", completed.stdout)
            self.assertTrue(Path(fields["RUNTIME"]).exists())
        finally:
            if poison.exists():
                poison.unlink()

    def test_authenticated_python_integration_does_not_use_ambient_python(self) -> None:
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex.quote(str(PYTHON_SHELL))}
            source {shlex.quote(str(SHELL))}
            if ! declare -F wins_release_python_run >/dev/null; then
              printf 'missing authenticated python function\\n' >&2
              exit 2
            fi
            wins_release_browser_prepare {shlex.quote(str(TOOL))} {shlex.quote(str(PIN_MANIFEST))}
            """
        )
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotRegex(completed.stderr, r"replacement controller executed")
        self.assertRegex(
            completed.stderr,
            r"stale Chrome custody trust refused|owner blocked|source-freeze|Python custody|not prepared|owner/environment blocker",
        )

    def test_real_authenticated_python_and_production_manifest_fail_closed(self) -> None:
        production = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))
        package = Path(
            production["tools"]["python"]["archive_custody"]["darwin_arm64"]["package"]["path"]
        )
        try:
            info = package.lstat()
        except FileNotFoundError:
            self.skipTest("authenticated Python package is unavailable")
        if package.is_symlink() or not stat.S_ISREG(info.st_mode):
            self.skipTest("authenticated Python package is unavailable")
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex.quote(str(PYTHON_SHELL))}
            wins_release_python_prepare {shlex.quote(str(PIN_MANIFEST))}
            trap 'wins_release_python_cleanup' EXIT
            printf 'PYTHON_BIN:%s\\n' "${{WINS_RELEASE_PYTHON_BIN}}"
            source {shlex.quote(str(SHELL))}
            set +e
            wins_release_browser_prepare {shlex.quote(str(TOOL))} {shlex.quote(str(PIN_MANIFEST))}
            rc=$?
            set -e
            [[ "$rc" -ne 0 ]] || {{
              printf 'unexpected browser PASS\\n' >&2
              exit 2
            }}
            """
        )
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=240,
        )
        self.assertNotEqual(completed.returncode, 2, completed.stderr)
        self.assertTrue(
            any(
                line.startswith("PYTHON_BIN:/private/tmp/wins-release-python-")
                or line.startswith("PYTHON_BIN:/Library/WinsVPN/ReleasePython/")
                for line in completed.stdout.splitlines()
            ),
            completed.stdout,
        )
        self.assertNotRegex(completed.stderr, r"replacement controller executed")
        self.assertRegex(
            completed.stderr,
            r"stale Chrome custody trust refused|owner blocked|source-freeze|owner/environment blocker|Seatbelt cannot nest",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_shell_and_python_syntax(self) -> None:
        shell = subprocess.run(
            ["/bin/bash", "-n", str(SHELL)], capture_output=True, text=True
        )
        self.assertEqual(shell.returncode, 0, shell.stderr)
        compiled = subprocess.run(
            [sys.executable, "-m", "py_compile", str(TOOL), str(Path(__file__).resolve())],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPYCACHEPREFIX": str(self.case / "pycache")},
        )
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        trust = json.loads(TRUST.read_text(encoding="utf-8"))
        self.assertEqual(trust["contract"], MODULE.TRUST_CONTRACT)
        live_controller = hashlib.sha256(TOOL.read_bytes()).hexdigest()
        live_wrapper = hashlib.sha256(SHELL.read_bytes()).hexdigest()
        live_manifest = hashlib.sha256(PIN_MANIFEST.read_bytes()).hexdigest()
        self.assertEqual(
            (live_controller, live_wrapper, live_manifest),
            (
                trust["controller_sha256"],
                trust["wrapper_sha256"],
                trust["manifest_sha256"],
            ),
        )
        with self.assertRaisesRegex(MODULE.Refused, "owner blocked"):
            MODULE.authorize_custody_inputs(TOOL, PIN_MANIFEST)
        self.assertEqual(live_manifest, trust["manifest_sha256"])

    def test_selftest_is_internal_and_reports_owner_blockers(self) -> None:
        completed = self._cli("selftest", str(ROOT))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("INTERNAL_SELFTEST|PASS", completed.stdout)
        self.assertIn("PRODUCTION_AUTHORIZATION|OWNER_BLOCKED|", completed.stdout)
        self.assertIn("STORE_PUBLICATION|OWNER_BLOCKED|", completed.stdout)
        self.assertNotIn("PRODUCTION_AUTHORIZATION|PASS", completed.stdout)
        self.assertNotIn("STORE_PUBLICATION|PASS", completed.stdout)
        controller = TOOL.read_text(encoding="ascii")
        wrapper = SHELL.read_text(encoding="ascii")
        for source in (controller, wrapper):
            self.assertNotRegex(source, r"\bcurl\b|\bwget\b|urllib|requests\.")
            self.assertNotIn("http://", source)
            self.assertNotIn("https://", source)
        self.assertIn("base64.b64decode", wrapper)
        self.assertIn("validate=True", wrapper)

    def test_stale_production_trust_is_reported_not_rehashed(self) -> None:
        trust = json.loads(TRUST.read_text(encoding="utf-8"))
        live_manifest = hashlib.sha256(PIN_MANIFEST.read_bytes()).hexdigest()
        self.assertEqual(live_manifest, trust["manifest_sha256"])
        stale_repo = self.case / "stale-repo"
        tools = stale_repo / "tools"
        tools.mkdir(parents=True)
        shutil.copyfile(TOOL, tools / MODULE.CONTROLLER_NAME)
        shutil.copyfile(SHELL, tools / MODULE.WRAPPER_NAME)
        shutil.copyfile(PIN_MANIFEST, tools / MODULE.MANIFEST_NAME)
        stale = dict(trust)
        stale["manifest_sha256"] = "0" * 64
        stale_path = tools / MODULE.TRUST_ANCHOR_NAME
        stale_path.write_bytes(MODULE._canonical_json_bytes(stale))
        before = stale_path.read_bytes()
        with self.assertRaisesRegex(MODULE.Refused, STALE_REFUSED) as raised:
            MODULE.authorize_repo(stale_repo)
        text = str(raised.exception)
        self.assertRegex(text, r"live=[0-9a-f]{64}")
        self.assertRegex(text, r"trust=[0-9a-f]{64}")
        self.assertIn("stale Chrome custody trust refused", text)
        self.assertNotIn("rehash", text.lower())
        self.assertEqual(stale_path.read_bytes(), before)

    def test_external_issuance_rejects_missing_writable_adjacent_replay_and_cross_target(
        self,
    ) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(MODULE.ISSUANCE_ENV, None)
            with self.assertRaisesRegex(MODULE.Refused, "owner blocked"):
                MODULE._bind_external_issuance(ROOT)
        with mock.patch.dict(os.environ, {MODULE.ISSUANCE_ENV: str(TOOL)}):
            with self.assertRaisesRegex(MODULE.Refused, "external to the candidate repository"):
                MODULE._bind_external_issuance(ROOT)
        directory = Path(tempfile.mkdtemp(prefix="wins-browser-issuance.", dir="/private/tmp"))
        self.addCleanup(shutil.rmtree, directory, True)
        issuance = write_issuance(directory)
        authority = MODULE._parse_authority(TEST_AUTHORITIES[issuance].read_bytes())
        self._assert_nonfinite_json_boundary(
            lambda payload: MODULE._parse_issuance(payload, authority),
            issuance.read_bytes(),
            "external issuance",
        )
        parsed = MODULE._parse_issuance(issuance.read_bytes(), authority)
        self.assertEqual(parsed["target"], MODULE.TARGET_ID)
        self.assertNotIn("authenticated", parsed)
        with (
            mock.patch.dict(os.environ, {MODULE.ISSUANCE_ENV: str(issuance)}),
            mock.patch.object(
                MODULE,
                "_verify_authority_path",
                return_value=TEST_AUTHORITIES[issuance].read_bytes(),
            ),
        ):
            rebound = MODULE._bind_external_issuance(ROOT)
        self.assertEqual(rebound["issuance_id"], parsed["issuance_id"])
        writable = directory / "writable-issuance.json"
        writable.write_bytes(issuance.read_bytes())
        writable.chmod(0o644)
        with mock.patch.dict(os.environ, {MODULE.ISSUANCE_ENV: str(writable)}):
            with self.assertRaisesRegex(MODULE.Refused, "writable"):
                MODULE._bind_external_issuance(ROOT)
        edge = write_issuance(
            directory,
            issuance_id="b" * 32,
            target=MODULE.EDGE_TARGET_ID,
        )
        with self.assertRaisesRegex(MODULE.Refused, "Edge or Firefox/XPI"):
            MODULE._parse_issuance(
                edge.read_bytes(),
                MODULE._parse_authority(TEST_AUTHORITIES[edge].read_bytes()),
            )
        firefox = write_issuance(
            directory,
            issuance_id="c" * 32,
            target=MODULE.FIREFOX_TARGET_ID,
        )
        with self.assertRaisesRegex(MODULE.Refused, "Edge or Firefox/XPI"):
            MODULE._parse_issuance(
                firefox.read_bytes(),
                MODULE._parse_authority(TEST_AUTHORITIES[firefox].read_bytes()),
            )
        replay_authority = dict(authority)
        replay_authority["active_issuance_id"] = "f" * 32
        with self.assertRaisesRegex(MODULE.Refused, "replayed or inactive"):
            MODULE._parse_issuance(issuance.read_bytes(), replay_authority)
        stale = write_issuance(
            directory,
            issuance_id="d" * 32,
            created_utc="2026-08-19T00:00:00Z",
            expires_utc="2026-08-19T01:00:00Z",
        )
        with self.assertRaisesRegex(MODULE.Refused, "stale"):
            MODULE._parse_issuance(
                stale.read_bytes(),
                MODULE._parse_authority(TEST_AUTHORITIES[stale].read_bytes()),
            )
        forged = json.loads(issuance.read_text(encoding="ascii"))
        forged["controller_sha256"] = "f" * 64
        with self.assertRaisesRegex(MODULE.Refused, "signature verification failed"):
            MODULE._parse_issuance(MODULE._canonical_json_bytes(forged), authority)

    def test_current_chrome_edge_firefox_archives_cannot_substitute(self) -> None:
        packages = self._current_extension_packages()
        for path, digest in (
            (packages[CHROME_PACKAGE.name], CHROME_PACKAGE_SHA256),
            (packages[EDGE_PACKAGE.name], EDGE_PACKAGE_SHA256),
            (packages[FIREFOX_ZIP.name], FIREFOX_PACKAGE_SHA256),
            (packages[FIREFOX_XPI.name], FIREFOX_PACKAGE_SHA256),
        ):
            with self.subTest(archive=path.name):
                self.assertTrue(path.is_file(), path)
                self.assertEqual(sha256(path), digest)
                self.assertNotEqual(digest, REAL_ARCHIVE_SHA256)
                with self.assertRaisesRegex(
                    MODULE.Refused,
                    r"extension archives cannot substitute|Firefox/XPI|basename",
                ):
                    MODULE.require_safe_input(path, f"{TOP}-{VERSION}.zip")
                renamed_dir = self.case / f"{path.stem}-{path.suffix.lstrip('.')}"
                renamed_dir.mkdir()
                renamed = renamed_dir / f"{TOP}-{VERSION}.zip"
                shutil.copyfile(path, renamed)
                renamed.chmod(0o444)
                pin = MODULE.parse_pin_bytes(self._manifest(renamed).read_bytes())
                with self.assertRaises(MODULE.Refused):
                    MODULE.install_extracted_runtime(pin)
                with self.assertRaisesRegex(
                    MODULE.Refused,
                    r"escaped its pinned top-level root|ZIP pinned top-level root",
                ):
                    MODULE.safe_extract(renamed, self.case / f"expanded-{path.stem}", TOP)

    def test_xpi_symlink_path_duplicate_and_member_substitution_are_rejected(self) -> None:
        xpi = self.case / "hostile.xpi"
        self._write_zip(
            xpi,
            [
                (TOP, "dir", b"", 0o755),
                (f"{TOP}/../escape", "file", b"x", 0o644),
            ],
        )
        xpi.chmod(0o444)
        with self.assertRaisesRegex(MODULE.Refused, r"Firefox/XPI|basename"):
            MODULE.require_safe_input(xpi, f"{TOP}-{VERSION}.zip")
        with self.assertRaisesRegex(MODULE.Refused, "unsafe or non-canonical"):
            MODULE.safe_extract(xpi, self.case / "expanded-xpi-path", TOP)
        duplicate = self.case / "duplicate.xpi"
        with zipfile.ZipFile(self.archive) as source, zipfile.ZipFile(duplicate, "w") as bundle:
            for item in source.infolist():
                bundle.writestr(item, b"" if item.is_dir() else source.read(item))
            bundle.writestr(source.infolist()[0].filename, b"substituted-member")
        duplicate.chmod(0o444)
        with self.assertRaisesRegex(MODULE.Refused, r"duplicate|collision"):
            MODULE.safe_extract(duplicate, self.case / "expanded-xpi-dup", TOP)
        symlink_xpi = self.case / "symlink.xpi"
        self._write_zip(
            symlink_xpi,
            [
                (TOP, "dir", b"", 0o755),
                (f"{TOP}/link", "symlink", "/private/tmp/attacker", 0o777),
            ],
        )
        with self.assertRaisesRegex(MODULE.Refused, "unsafe or non-canonical"):
            MODULE.safe_extract(symlink_xpi, self.case / "expanded-xpi-link", TOP)
        real_xpi = self.case / FIREFOX_XPI.name
        shutil.copyfile(self._current_extension_packages()[FIREFOX_XPI.name], real_xpi)
        real_xpi.chmod(0o444)
        with self.assertRaisesRegex(MODULE.Refused, "Firefox/XPI"):
            MODULE.require_safe_input(real_xpi, real_xpi.name)

    def test_injected_runner_cannot_production_pass(self) -> None:
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex.quote(str(SHELL))}
            wins_release_python_run() {{ {shlex.quote(sys.executable)} "$@"; }}
            wins_release_browser_prepare {shlex.quote(str(TOOL))} {shlex.quote(str(PIN_MANIFEST))}
            printf 'unexpected browser PASS\\n' >&2
            """
        )
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("unexpected browser PASS", completed.stderr)
        self.assertRegex(
            completed.stderr,
            r"stale Chrome custody trust refused|owner blocked|authenticated release Python custody is required",
        )

    def test_authorize_snapshot_and_freeze_exec_are_refused(self) -> None:
        with self.assertRaisesRegex(MODULE.Refused, "injected or test runner"):
            MODULE.authorize_snapshot(TOOL)
        with self.assertRaisesRegex(MODULE.Refused, "source-freeze producer digest"):
            MODULE._verify_source_freeze_receipt(ROOT)
        source = TOOL.read_text(encoding="ascii")
        self.assertNotIn("exec(compile(data, str(producer), \"exec\")", source)
        self.assertIn("Never execute unauthenticated source", source)
        self.assertIn(MODULE.INJECTED_RUNNER_BLOCKER, source)


if __name__ == "__main__":
    unittest.main()
