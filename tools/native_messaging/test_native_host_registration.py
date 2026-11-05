#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CALLER_CHROMIUM_ID = "abcdefghijklmnopabcdefghijklmnop"
FIXTURE_EDGE_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
RECORDED_CHROME_ID = "lnehjdblendkagjbmdclepjalahdhbbn"
RECORDED_EDGE_ID = "glgihadopbjoandhoihghddecoibcldf"

SPEC = importlib.util.spec_from_file_location(
    "render_host_manifest", HERE / "render_host_manifest.py"
)
assert SPEC is not None and SPEC.loader is not None
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)

LAYOUT_SPEC = importlib.util.spec_from_file_location(
    "native_host_layout", HERE / "native_host_layout.py"
)
assert LAYOUT_SPEC is not None and LAYOUT_SPEC.loader is not None
layout = importlib.util.module_from_spec(LAYOUT_SPEC)
LAYOUT_SPEC.loader.exec_module(layout)


def _write_store_ids(path: Path, ids: dict[str, str] | None) -> Path:
    """Write a fixture store id record (or leave it absent) with reviewed modes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o755)
    if ids is not None:
        path.write_text(json.dumps(ids, sort_keys=True) + "\n", encoding="ascii")
        os.chmod(path, 0o644)
    return path


def _store_ids_python_env(
    root: Path,
    ids: dict[str, str] | None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Child-process env whose renderer reads a fixture store_ids.json record."""
    record = _write_store_ids(root / "fixture-manifests" / "store_ids.json", ids)
    site = root / "fixture-site"
    site.mkdir(parents=True, exist_ok=True)
    (site / "sitecustomize.py").write_text(
        "\n".join(
            [
                "import sys",
                "from pathlib import Path",
                f"sys.path.insert(0, {str(HERE)!r})",
                "import render_host_manifest as _renderer",
                f"_renderer.STORE_IDS_FILE = Path({str(record)!r})",
                # No store_identity.json listing beside the fixture record.
                f"_renderer.REPO_ROOT = Path({str(root / 'fixture-repo')!r})",
                "",
            ]
        ),
        encoding="ascii",
    )
    env = {
        **os.environ,
        "PYTHON_BIN": sys.executable,
        "WINSVPN_CHROME_STORE_ID": "",
        "WINSVPN_EDGE_STORE_ID": "",
    }
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(site) if not existing else str(site) + os.pathsep + existing
    if extra:
        env.update(extra)
    return env


def _blocked_helper_env(root: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    return _store_ids_python_env(root, None, extra)


@contextmanager
def isolated_store_env(ids: dict[str, str] | None = None, **values: str):
    """Point both loaded renderer copies at a fixture record (absent by default).

    The fixture root has no extension/store_listings/store_identity.json, so the
    repository's listing record does not corroborate fixture ids.
    """
    keys = ("WINSVPN_CHROME_STORE_ID", "WINSVPN_EDGE_STORE_ID")
    previous = {key: os.environ.get(key) for key in keys}
    modules = {id(module): module for module in (renderer, layout.renderer)}
    originals = [
        (module, module.STORE_IDS_FILE, module.REPO_ROOT) for module in modules.values()
    ]
    with tempfile.TemporaryDirectory(prefix="winsvpn-store-ids-") as raw:
        record = _write_store_ids(Path(raw) / "manifests" / "store_ids.json", ids)
        for module, _original, _root in originals:
            module.STORE_IDS_FILE = record
            module.REPO_ROOT = Path(raw)
        for key in keys:
            os.environ.pop(key, None)
        os.environ.update(values)
        try:
            yield record
        finally:
            for module, original, repo_root in originals:
                module.STORE_IDS_FILE = original
                module.REPO_ROOT = repo_root
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


@contextmanager
def cleared_store_env(**values: str):
    """Clear the store-id environment only; the real committed records stay in place."""
    keys = ("WINSVPN_CHROME_STORE_ID", "WINSVPN_EDGE_STORE_ID")
    previous = {key: os.environ.get(key) for key in keys}
    for key in keys:
        os.environ.pop(key, None)
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _render_cli(
    env: dict[str, str],
    browser: str,
    output: Path,
    extension_id: str | None = None,
    *,
    as_script: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the renderer CLI. The module form lets a fixture sitecustomize apply."""
    if as_script:
        launcher = [sys.executable, str(HERE / "render_host_manifest.py")]
    else:
        launcher = [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, sys.argv.pop(1)); "
            "import render_host_manifest as r; raise SystemExit(r.main(sys.argv[1:]))",
            str(HERE),
        ]
    command = [
        *launcher,
        "--browser",
        browser,
        "--host-path",
        "/opt/wins-vpn/wins_bridge_host",
        "--output",
        str(output),
    ]
    if extension_id is not None:
        command += ["--extension-id", extension_id]
    return subprocess.run(
        command, check=False, capture_output=True, text=True, env=env
    )


def _dummy_host_interpreter() -> Path:
    for candidate in (getattr(sys, "_base_executable", None), sys.executable):
        if not candidate:
            continue
        executable = Path(candidate)
        if executable.is_absolute() and executable.is_file() and os.access(
            executable, os.X_OK
        ):
            return executable
    raise RuntimeError("no executable Python interpreter is available")


def _framework_relocation_env(interpreter: Path) -> dict[str, str]:
    version_root = interpreter.parent.parent
    if (
        interpreter.parent.name == "bin"
        and version_root.parent.name == "Versions"
        and version_root.parent.parent.name == "Python.framework"
    ):
        framework = version_root.parent.parent
        return {
            "DYLD_FRAMEWORK_PATH": str(framework.parent),
            "DYLD_LIBRARY_PATH": str(version_root / "lib"),
        }
    return {}


def _compile_handshake_host(destination: Path) -> Path:
    source = destination.with_suffix(".c")
    source.write_text(
        "\n".join(
            [
                "#include <stdio.h>",
                "#include <stdint.h>",
                "#include <stdlib.h>",
                "#include <string.h>",
                "int main(int argc, char **argv) {",
                "  const char *body =",
                '      "{\\"type\\":\\"hello\\",\\"protocolVersion\\":1,'
                '\\"status\\":\\"app_not_running\\",\\"platform\\":\\"macos\\"}";',
                '  if (argc > 1 && strcmp(argv[1], "--selftest") == 0) return 0;',
                "  unsigned char hdr[4];",
                "  uint32_t n;",
                "  if (fread(hdr, 1, 4, stdin) != 4) return 1;",
                "  n = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |",
                "      ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);",
                "  if (n > 65536u) return 1;",
                "  {",
                "    char *buf = (char *)malloc(n ? n : 1);",
                "    if (buf == NULL) return 1;",
                "    if (n && fread(buf, 1, n, stdin) != n) { free(buf); return 1; }",
                "    free(buf);",
                "  }",
                "  uint32_t len = (uint32_t)strlen(body);",
                "  unsigned char out[4];",
                "  out[0] = (unsigned char)(len & 0xffu);",
                "  out[1] = (unsigned char)((len >> 8) & 0xffu);",
                "  out[2] = (unsigned char)((len >> 16) & 0xffu);",
                "  out[3] = (unsigned char)((len >> 24) & 0xffu);",
                "  if (fwrite(out, 1, 4, stdout) != 4) return 1;",
                "  if (fwrite(body, 1, len, stdout) != len) return 1;",
                "  return 0;",
                "}",
                "",
            ]
        ),
        encoding="ascii",
    )
    completed = subprocess.run(
        [
            "/usr/bin/clang",
            "-arch",
            "arm64",
            "-arch",
            "x86_64",
            "-Os",
            "-o",
            str(destination),
            str(source),
        ],
        cwd="/",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    destination.chmod(0o755)
    return destination


def write_dummy_host(path: Path) -> Path:
    interpreter = _dummy_host_interpreter()
    child_env = {
        "HOME": str(path.parent),
        "TMPDIR": str(path.parent),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        **_framework_relocation_env(interpreter),
    }
    program = (
        "import json, struct, sys\n"
        "header = sys.stdin.buffer.read(4)\n"
        "if len(header) == 4:\n"
        "    n, = struct.unpack('<I', header)\n"
        "    sys.stdin.buffer.read(n)\n"
        "body = json.dumps({'type': 'hello', 'protocolVersion': 1,"
        " 'platform': 'test', 'status': 'app_not_running'}).encode()\n"
        "sys.stdout.buffer.write(struct.pack('<I', len(body)) + body)\n"
        "sys.stdout.buffer.flush()\n"
    )
    command = [
        "/usr/bin/env",
        "-i",
        *(f"{key}={value}" for key, value in child_env.items()),
        str(interpreter),
        "-S",
        "-c",
        program,
    ]
    path.write_text(
        "#!/bin/sh\nexec " + " ".join(shlex.quote(arg) for arg in command) + "\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


STORE_IDENTITY_RECORD = REPO / "extension" / "store_listings" / "store_identity.json"
STORE_IDENTITY_REL = Path("extension") / "store_listings" / "store_identity.json"
STORE_IDS_REL = Path("tools") / "native_messaging" / "manifests" / "store_ids.json"


def _recorded_listing_ids() -> dict[str, str]:
    record = json.loads(STORE_IDENTITY_RECORD.read_text(encoding="utf-8"))
    return {
        browser: record["stores"][f"{browser}-extension-package"]["store_id"]
        for browser in ("chrome", "edge")
    }


@contextmanager
def store_identity_root(root: Path):
    """Point every loaded renderer at `root` in place of the repository.

    `root` holds only the identity records a case needs. An empty root is a
    layout with no recorded Chrome or Edge identity at all.
    """
    modules = list({id(module): module for module in (renderer, layout.renderer)}.values())
    saved = [(module, module.REPO_ROOT, module.STORE_IDS_FILE) for module in modules]
    try:
        for module in modules:
            module.REPO_ROOT = root
            module.STORE_IDS_FILE = root / STORE_IDS_REL
        yield
    finally:
        for module, repo_root, ids_file in saved:
            module.REPO_ROOT = repo_root
            module.STORE_IDS_FILE = ids_file


IDENTITYLESS_PACKAGE_FILES = (
    Path("tools") / "native_messaging" / "render_host_manifest.py",
    Path("tools") / "native_messaging" / "native_host_layout.py",
    Path("tools") / "native_messaging" / "install_native_host.sh",
    Path("extension") / "tools" / "jsonc.py",
    Path("extension") / "manifest" / "firefox.jsonc",
)


def _identityless_package(root: Path) -> Path:
    """A package layout that ships neither identity record."""
    for rel in IDENTITYLESS_PACKAGE_FILES:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, target)
    assert not (root / STORE_IDENTITY_REL).exists()
    assert not (root / STORE_IDS_REL).exists()
    return root / "tools" / "native_messaging"


class ManifestRendererTests(unittest.TestCase):
    def test_chromium_manifest_uses_exact_store_origin(self) -> None:
        manifest = renderer.manifest_for(
            "chrome",
            CALLER_CHROMIUM_ID,
            "wins_bridge_host.exe",
            allow_relative_host_path=True,
        )
        self.assertEqual(
            manifest["allowed_origins"],
            [f"chrome-extension://{CALLER_CHROMIUM_ID}/"],
        )
        self.assertNotIn("allowed_extensions", manifest)

    def test_firefox_manifest_uses_pinned_addon_id(self) -> None:
        manifest = renderer.manifest_for(
            "firefox", "companion@winsvpn.org", "/opt/wins-vpn/wins_bridge_host"
        )
        self.assertEqual(manifest["allowed_extensions"], ["companion@winsvpn.org"])
        self.assertNotIn("allowed_origins", manifest)

    def test_placeholder_and_invented_ids_are_refused(self) -> None:
        for browser, extension_id in (
            ("chrome", "PLACEHOLDER_CHROME_EXTENSION_ID"),
            ("edge", "z" * 32),
            ("firefox", "somebody@example.invalid"),
        ):
            with self.subTest(browser=browser):
                with self.assertRaises(ValueError):
                    renderer.manifest_for(browser, extension_id, "/safe/host")

    def test_non_windows_host_path_must_be_absolute(self) -> None:
        with self.assertRaises(ValueError):
            renderer.manifest_for(
                "firefox", "companion@winsvpn.org", "wins_bridge_host"
            )

    def test_atomic_output_is_valid_json_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "nested" / "org.winsvpn.bridge.json"
            manifest = renderer.manifest_for(
                "firefox", "companion@winsvpn.org", "/opt/wins-vpn/wins_bridge_host"
            )
            renderer.write_atomic(target, manifest)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), manifest)
            if os.name != "nt":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(target.parent.glob("*.tmp")), [])

    def test_atomic_output_refuses_symlink_manifest_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            victim = root / "victim"
            victim.mkdir()
            planted = victim / "org.winsvpn.bridge.json"
            planted.write_text("KEEP\n", encoding="ascii")
            linked = root / "manifest-dir"
            linked.symlink_to(victim)
            target = linked / "org.winsvpn.bridge.json"
            manifest = renderer.manifest_for(
                "firefox", "companion@winsvpn.org", "/opt/wins-vpn/wins_bridge_host"
            )
            with self.assertRaises(OSError) as raised:
                renderer.write_atomic(target, manifest)
            self.assertIn("symlink", str(raised.exception))
            self.assertEqual(planted.read_text(encoding="ascii"), "KEEP\n")
            self.assertTrue(linked.is_symlink())

    def test_atomic_output_refuses_intermediate_symlink_and_special_parents(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            victim = root / "victim"
            victim.mkdir()
            decoy = root / "decoy"
            decoy.mkdir()
            (decoy / "dir").symlink_to(victim)
            nested = decoy / "dir" / "nested" / "org.winsvpn.bridge.json"
            manifest = renderer.manifest_for(
                "firefox", "companion@winsvpn.org", "/opt/wins-vpn/wins_bridge_host"
            )
            with self.assertRaises(OSError) as raised:
                renderer.write_atomic(nested, manifest)
            self.assertIn("symlink", str(raised.exception))
            self.assertFalse((victim / "nested").exists())
            self.assertEqual(list(victim.iterdir()), [])

            file_parent = root / "file-parent"
            file_parent.write_text("NOT-A-DIR\n", encoding="ascii")
            file_target = file_parent / "org.winsvpn.bridge.json"
            with self.assertRaises(OSError) as raised_file:
                renderer.write_atomic(file_target, manifest)
            self.assertTrue(
                "non-directory" in str(raised_file.exception)
                or "special" in str(raised_file.exception),
                str(raised_file.exception),
            )
            self.assertEqual(file_parent.read_text(encoding="ascii"), "NOT-A-DIR\n")

            fifo_parent = root / "fifo-parent"
            os.mkfifo(fifo_parent)
            fifo_target = fifo_parent / "org.winsvpn.bridge.json"
            with self.assertRaises(OSError) as raised_fifo:
                renderer.write_atomic(fifo_target, manifest)
            self.assertTrue(
                "special" in str(raised_fifo.exception)
                or "non-directory" in str(raised_fifo.exception)
                or "symlink" in str(raised_fifo.exception),
                str(raised_fifo.exception),
            )

    def test_chrome_without_recorded_id_is_refused_naming_the_missing_value(self) -> None:
        with isolated_store_env():
            self.assertIsNone(renderer.recorded_extension_id("chrome"))
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "should-not-be-written.json"
            completed = _render_cli(_store_ids_python_env(root, None), "chrome", target)
            self.assertEqual(completed.returncode, renderer.MISSING_STORE_ID_EXIT)
            self.assertFalse(target.exists())
            self.assertIn("chrome store-listing id is missing", completed.stderr)
            self.assertIn("manifests/store_ids.json", completed.stderr)
        # EXT2: a package layout that ships neither identity record is refused too.
        with tempfile.TemporaryDirectory() as raw:
            with store_identity_root(Path(raw) / "no-records"):
                self.assertIsNone(renderer.recorded_extension_id("chrome"))
            package = _identityless_package(Path(raw) / "package")
            target = Path(raw) / "should-not-be-written.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(package / "render_host_manifest.py"),
                    "--browser",
                    "chrome",
                    "--host-path",
                    "/opt/wins-vpn/wins_bridge_host",
                    "--output",
                    str(target),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "WINSVPN_CHROME_STORE_ID": "", "WINSVPN_EDGE_STORE_ID": ""},
            )
            self.assertEqual(
                completed.returncode, renderer.MISSING_STORE_ID_EXIT, completed.stderr
            )
            self.assertFalse(target.exists())
            self.assertIn("chrome store-listing id is missing", completed.stderr)

    def test_firefox_id_can_be_omitted_because_it_is_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "org.winsvpn.bridge.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "render_host_manifest.py"),
                    "--browser",
                    "firefox",
                    "--host-path",
                    "/opt/wins-vpn/wins_bridge_host",
                    "--output",
                    str(target),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(payload["allowed_extensions"], ["companion@winsvpn.org"])


    def test_canonical_firefox_id_parses_gecko_id_not_a_comment(self) -> None:
        self.assertEqual(renderer.canonical_firefox_id(), "companion@winsvpn.org")
        with tempfile.TemporaryDirectory() as raw:
            fake = Path(raw) / "firefox.jsonc"
            fake.write_text(
                json.dumps({
                    "browser_specific_settings": {
                        "gecko": {"id": "other@example.invalid"}
                    }
                }),
                encoding="utf-8",
            )
            original = renderer.FIREFOX_FRAGMENT
            renderer.FIREFOX_FRAGMENT = fake
            try:
                with self.assertRaises(ValueError):
                    renderer.canonical_firefox_id()
            finally:
                renderer.FIREFOX_FRAGMENT = original

    def test_committed_store_ids_record_is_the_chromium_identity_source(self) -> None:
        record = HERE / "manifests" / "store_ids.json"
        info = record.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(stat.S_IMODE(info.st_mode) & 0o022, 0)
        self.assertEqual(stat.S_IMODE(record.parent.lstat().st_mode) & 0o022, 0)
        self.assertEqual(renderer.STORE_IDS_FILE, record)
        expected = {"chrome": RECORDED_CHROME_ID, "edge": RECORDED_EDGE_ID}
        self.assertEqual(json.loads(record.read_text(encoding="ascii")), expected)
        for browser, extension_id in expected.items():
            template = (
                HERE / "manifests" / f"org.winsvpn.bridge.{browser}.json"
            ).read_text(encoding="utf-8")
            self.assertIn(f"chrome-extension://{extension_id}/", template)
        env_free = {"WINSVPN_CHROME_STORE_ID": "", "WINSVPN_EDGE_STORE_ID": ""}
        previous = {key: os.environ.get(key) for key in env_free}
        os.environ.update(env_free)
        try:
            self.assertEqual(renderer.recorded_store_ids(), expected)
            self.assertEqual(renderer.owner_issued_chromium_ids(), expected)
            self.assertEqual(renderer.recorded_extension_id("chrome"), RECORDED_CHROME_ID)
            self.assertEqual(renderer.recorded_extension_id("edge"), RECORDED_EDGE_ID)
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        with tempfile.TemporaryDirectory() as raw:
            env = {**os.environ, **env_free}
            for browser, extension_id in expected.items():
                target = Path(raw) / f"{browser}.json"
                completed = _render_cli(env, browser, target, as_script=True)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads(target.read_text(encoding="utf-8"))
                self.assertEqual(
                    payload["allowed_origins"], [f"chrome-extension://{extension_id}/"]
                )

    def test_owner_receipt_machinery_is_removed(self) -> None:
        for name in (
            "bind_owner_identity",
            "parse_owner_identity_document",
            "_refuse_unbound_substitutes",
            "owner_identity_receipt_path",
            "OWNER_IDENTITY_PATH",
            "OWNER_IDENTITY_ENV",
            "OWNER_IDENTITY_MAX_AGE",
            "OWNER_IDENTITY_CONTRACT",
            "OWNER_BLOCKED_IDENTITY",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(renderer, name))
        source = (HERE / "render_host_manifest.py").read_text(encoding="utf-8")
        self.assertNotIn("/var/lib/winsvpn", source)
        self.assertNotIn("OWNER_IDENTITY_", source)
        self.assertNotIn("timedelta", source)
        self.assertNotIn("genuinely external", source)
        self.assertNotIn("candidate-minted", source)

    def test_absent_edge_id_refuses_only_edge(self) -> None:
        with isolated_store_env({"chrome": CALLER_CHROMIUM_ID}):
            self.assertEqual(renderer.recorded_extension_id("chrome"), CALLER_CHROMIUM_ID)
            self.assertIsNone(renderer.recorded_extension_id("edge"))
            self.assertEqual(
                renderer.recorded_extension_id("firefox"), "companion@winsvpn.org"
            )
            with self.assertRaises(renderer.OwnerIdentityBlocked) as raised:
                renderer.owner_issued_chromium_ids()
            self.assertIn("edge store-listing id is missing", str(raised.exception))
            self.assertNotIn("chrome store-listing id is missing", str(raised.exception))
            with self.assertRaises(layout.MissingStoreIdError):
                layout.resolve_extension_id("edge", None)
            self.assertEqual(layout.resolve_extension_id("chrome", None), CALLER_CHROMIUM_ID)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            env = _store_ids_python_env(root, {"chrome": CALLER_CHROMIUM_ID})
            chrome = _render_cli(env, "chrome", root / "chrome.json")
            self.assertEqual(chrome.returncode, 0, chrome.stderr)
            self.assertEqual(
                json.loads((root / "chrome.json").read_text(encoding="utf-8"))[
                    "allowed_origins"
                ],
                [f"chrome-extension://{CALLER_CHROMIUM_ID}/"],
            )
            firefox = _render_cli(env, "firefox", root / "firefox.json")
            self.assertEqual(firefox.returncode, 0, firefox.stderr)
            edge = _render_cli(env, "edge", root / "edge.json")
            self.assertEqual(edge.returncode, renderer.MISSING_STORE_ID_EXIT, edge.stderr)
            self.assertIn("edge store-listing id is missing", edge.stderr)
            self.assertIn("manifests/store_ids.json has no 'edge' value", edge.stderr)
            self.assertFalse((root / "edge.json").exists())
            supplied = _render_cli(env, "edge", root / "edge.json", FIXTURE_EDGE_ID)
            self.assertEqual(
                supplied.returncode, renderer.MISSING_STORE_ID_EXIT, supplied.stderr
            )
            self.assertIn("cannot substitute", supplied.stderr)
            self.assertFalse((root / "edge.json").exists())
            env_edge = dict(env, WINSVPN_EDGE_STORE_ID=FIXTURE_EDGE_ID)
            from_env = _render_cli(env_edge, "edge", root / "edge.json")
            self.assertNotEqual(from_env.returncode, 0, from_env.stdout)
            self.assertFalse((root / "edge.json").exists())

    def test_missing_record_is_blocked_and_caller_id_cannot_substitute(
        self,
    ) -> None:
        with isolated_store_env():
            with self.assertRaises(renderer.OwnerIdentityBlocked):
                renderer.owner_issued_chromium_ids()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "should-not-be-written.json"
            completed = _render_cli(
                _store_ids_python_env(root, None), "chrome", target, CALLER_CHROMIUM_ID
            )
            self.assertEqual(completed.returncode, renderer.MISSING_STORE_ID_EXIT)
            self.assertFalse(target.exists())
            self.assertIn("cannot substitute", completed.stderr)
        # EXT2: the same refusal from a package layout with neither identity record.
        with tempfile.TemporaryDirectory() as raw:
            with store_identity_root(Path(raw) / "no-records"):
                with self.assertRaises(renderer.OwnerIdentityBlocked):
                    renderer.owner_issued_chromium_ids()
            package = _identityless_package(Path(raw) / "package")
            target = Path(raw) / "should-not-be-written.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(package / "render_host_manifest.py"),
                    "--browser",
                    "chrome",
                    "--extension-id",
                    CALLER_CHROMIUM_ID,
                    "--host-path",
                    "/opt/wins-vpn/wins_bridge_host",
                    "--output",
                    str(target),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "WINSVPN_CHROME_STORE_ID": "", "WINSVPN_EDGE_STORE_ID": ""},
            )
            self.assertEqual(
                completed.returncode, renderer.MISSING_STORE_ID_EXIT, completed.stderr
            )
            self.assertFalse(target.exists())
            self.assertIn("chrome store-listing id is missing", completed.stderr)
            self.assertIn("cannot substitute", completed.stderr)

    def test_recorded_identity_resolves_without_any_receipt(self) -> None:
        """EXT2 Turn 3 owner ruling: no expiring receipt decides a recorded id."""
        expected = _recorded_listing_ids()
        # The receipt reader is gone (SEALED); the committed records alone decide.
        self.assertFalse(hasattr(renderer, "bind_owner_identity"))
        with cleared_store_env():
            self.assertEqual(renderer.owner_issued_chromium_ids(), expected)
            self.assertEqual(renderer.recorded_extension_id("edge"), expected["edge"])
            for browser in ("chrome", "edge"):
                self.assertEqual(
                    renderer.resolve_cli_extension_id(browser, None), expected[browser]
                )
                self.assertEqual(
                    renderer.resolve_cli_extension_id(browser, expected[browser]),
                    expected[browser],
                )
            with self.assertRaises(renderer.OwnerIdentityInvalid) as raised:
                renderer.resolve_cli_extension_id("chrome", CALLER_CHROMIUM_ID)
            self.assertIn("recorded store identity", str(raised.exception))
            with self.assertRaises(renderer.OwnerIdentityInvalid):
                renderer.resolve_cli_extension_id("edge", expected["chrome"])
        with cleared_store_env(), tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "org.winsvpn.bridge.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "render_host_manifest.py"),
                    "--browser",
                    "edge",
                    "--host-path",
                    "/opt/wins-vpn/wins_bridge_host",
                    "--output",
                    str(target),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["allowed_origins"], [f"chrome-extension://{expected['edge']}/"]
            )

    def test_compact_store_ids_record_serves_an_installed_layout(self) -> None:
        expected = _recorded_listing_ids()
        with isolated_store_env(), tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            ids_file = root / STORE_IDS_REL
            ids_file.parent.mkdir(parents=True)
            ids_file.write_text(json.dumps(expected), encoding="utf-8")
            with store_identity_root(root):
                self.assertEqual(renderer.owner_issued_chromium_ids(), expected)
                self.assertEqual(layout.resolve_extension_id("edge", None), expected["edge"])
            ids_file.unlink()
            with store_identity_root(root):
                with self.assertRaises(renderer.OwnerIdentityBlocked):
                    renderer.owner_issued_chromium_ids()
                with self.assertRaises(layout.MissingStoreIdError):
                    layout.resolve_extension_id("chrome", None)

    def test_listing_alone_never_supplies_ids_when_store_ids_record_is_absent(self) -> None:
        # INTEG6 combined rule: manifests/store_ids.json is the only source and
        # the listing record only corroborates it. A checkout whose compact
        # record is missing blocks Chrome and Edge although the listing names
        # both (EXT2's listing-only resolution is not kept; SEALED blocks).
        with cleared_store_env(), tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            listing = root / STORE_IDENTITY_REL
            listing.parent.mkdir(parents=True)
            shutil.copyfile(REPO / STORE_IDENTITY_REL, listing)
            os.chmod(listing, 0o644)
            (root / STORE_IDS_REL).parent.mkdir(parents=True)
            os.chmod((root / STORE_IDS_REL).parent, 0o755)
            with store_identity_root(root):
                self.assertIsNone(renderer.recorded_extension_id("chrome"))
                self.assertIsNone(renderer.recorded_extension_id("edge"))
                with self.assertRaises(renderer.OwnerIdentityBlocked) as raised:
                    renderer.owner_issued_chromium_ids()
                self.assertIn("chrome store-listing id is missing", str(raised.exception))
                self.assertIn("edge store-listing id is missing", str(raised.exception))
                with self.assertRaises(layout.MissingStoreIdError):
                    layout.resolve_extension_id("edge", None)
            # A partial record is not completed from the listing either.
            partial = {"chrome": _recorded_listing_ids()["chrome"]}
            _write_store_ids(root / STORE_IDS_REL, partial)
            with store_identity_root(root):
                self.assertEqual(renderer.recorded_store_ids(), partial)
                self.assertIsNone(renderer.recorded_extension_id("edge"))
                with self.assertRaises(renderer.OwnerIdentityBlocked) as raised:
                    renderer.owner_issued_chromium_ids()
                self.assertIn("edge store-listing id is missing", str(raised.exception))

    def test_recorded_identity_records_must_be_exact_and_agree(self) -> None:
        expected = _recorded_listing_ids()
        good = json.loads(STORE_IDENTITY_RECORD.read_text(encoding="utf-8"))

        def entry(record: dict, browser: str) -> dict:
            return record["stores"][f"{browser}-extension-package"]

        def edit(change):
            def apply(record: dict) -> dict:
                change(record)
                return record
            return apply

        cases = {
            "contract": edit(lambda r: r.__setitem__("contract", "other")),
            "bool schema": edit(lambda r: r.__setitem__("schema_version", True)),
            "schema 2": edit(lambda r: r.__setitem__("schema_version", 2)),
            "host name": edit(lambda r: r.__setitem__("native_host_name", "org.other")),
            "stores list": edit(lambda r: r.__setitem__("stores", [])),
            "chrome missing": edit(lambda r: r["stores"].pop("chrome-extension-package")),
            "padded id": edit(
                lambda r: entry(r, "chrome").__setitem__(
                    "store_id", " " + expected["chrome"]
                )
            ),
            "placeholder id": edit(
                lambda r: entry(r, "edge").__setitem__(
                    "store_id", "PLACEHOLDER_EDGE_EXTENSION_ID"
                )
            ),
            "listing name": edit(
                lambda r: entry(r, "edge").__setitem__("listing_name", "Win's VPN Proxy")
            ),
            "swapped template": edit(
                lambda r: entry(r, "chrome").__setitem__(
                    "native_host_template",
                    "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
                )
            ),
            "foreign allowlist": edit(
                lambda r: entry(r, "chrome").__setitem__(
                    "native_host_allowlist",
                    [f"chrome-extension://{expected['edge']}/"],
                )
            ),
            "extra allowlist": edit(
                lambda r: entry(r, "edge").__setitem__(
                    "native_host_allowlist",
                    [
                        f"chrome-extension://{expected['edge']}/",
                        f"chrome-extension://{CALLER_CHROMIUM_ID}/",
                    ],
                )
            ),
            "reused id": edit(
                lambda r: entry(r, "edge").update(
                    {
                        "store_id": expected["chrome"],
                        "native_host_allowlist": [
                            f"chrome-extension://{expected['chrome']}/"
                        ],
                    }
                )
            ),
        }

        def refused(root: Path, **env: str) -> Exception:
            with isolated_store_env(**env), store_identity_root(root):
                with self.assertRaises(ValueError) as raised:
                    renderer.owner_issued_chromium_ids()
            self.assertNotIsInstance(raised.exception, renderer.OwnerIdentityBlocked)
            return raised.exception

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            record_path = root / STORE_IDENTITY_REL
            record_path.parent.mkdir(parents=True)
            record_path.write_text(json.dumps(good), encoding="utf-8")
            # The committed compact record is the source; the listing must agree.
            ids_file = root / STORE_IDS_REL
            ids_file.parent.mkdir(parents=True)
            ids_file.write_text(json.dumps(expected), encoding="utf-8")
            with isolated_store_env(), store_identity_root(root):
                self.assertEqual(renderer.owner_issued_chromium_ids(), expected)
            for name, mutate in cases.items():
                with self.subTest(case=name):
                    record = mutate(json.loads(json.dumps(good)))
                    record_path.write_text(json.dumps(record), encoding="utf-8")
                    refused(root)
            with self.subTest(case="duplicate key"):
                record_path.write_text(
                    json.dumps(good).replace(
                        '"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1
                    ),
                    encoding="utf-8",
                )
                self.assertIn("duplicate JSON key", str(refused(root)))
            with self.subTest(case="empty"):
                record_path.write_bytes(b"")
                refused(root)
            with self.subTest(case="oversize"):
                record_path.write_bytes(b" " * (renderer.STORE_IDS_MAX_BYTES + 1))
                refused(root)
            with self.subTest(case="valid record padded past the size bound"):
                payload = json.dumps(good).encode("utf-8")
                record_path.write_bytes(
                    payload + b" " * (renderer.STORE_IDS_MAX_BYTES + 1 - len(payload))
                )
                self.assertIn("regular bounded file", str(refused(root)))
            record_path.write_text(json.dumps(good), encoding="utf-8")
            with self.subTest(case="hard link"):
                twin = root / "twin.json"
                os.link(record_path, twin)
                try:
                    refused(root)
                finally:
                    twin.unlink()
            with self.subTest(case="symlink"):
                real = root / "real.json"
                record_path.rename(real)
                record_path.symlink_to(real)
                try:
                    refused(root)
                finally:
                    record_path.unlink()
                    real.rename(record_path)
            with self.subTest(case="compact record disagrees"):
                ids_file.write_text(
                    json.dumps({"chrome": expected["edge"], "edge": expected["chrome"]}),
                    encoding="utf-8",
                )
                try:
                    self.assertIn("disagree", str(refused(root)))
                finally:
                    ids_file.write_text(json.dumps(expected), encoding="utf-8")
            with self.subTest(case="environment disagrees"):
                refused(root, WINSVPN_EDGE_STORE_ID=CALLER_CHROMIUM_ID)
            with isolated_store_env(
                WINSVPN_CHROME_STORE_ID=expected["chrome"],
                WINSVPN_EDGE_STORE_ID=expected["edge"],
            ), store_identity_root(root):
                self.assertEqual(renderer.owner_issued_chromium_ids(), expected)

    def test_compact_identity_requires_exact_ids_and_bounded_read(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import Mock, patch

        expected = _recorded_listing_ids()
        cases = [
            ("valid", json.dumps(expected).encode("utf-8"), False),
            (
                "padded chrome",
                json.dumps(dict(expected, chrome=" " + expected["chrome"])).encode("utf-8"),
                True,
            ),
            (
                "padded edge",
                json.dumps(dict(expected, edge=expected["edge"] + "\n")).encode("utf-8"),
                True,
            ),
            ("oversize", b" " * (renderer.STORE_IDS_MAX_BYTES + 1), True),
        ]
        for name, payload, refused in cases:
            with self.subTest(case=name):
                info = SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o644,
                    st_dev=1,
                    st_ino=1,
                    st_nlink=1,
                    st_size=len(payload),
                    st_mtime_ns=1,
                    st_ctime_ns=1,
                )
                path = Mock()
                path.is_file.return_value = True
                path.lstat.return_value = info
                path.read_bytes.return_value = payload
                with (
                    patch.object(renderer, "STORE_IDS_FILE", path),
                    patch.object(renderer, "_store_ids_directory_present", return_value=True),
                    patch.object(renderer.os, "open", return_value=123),
                    patch.object(renderer.os, "fstat", return_value=info),
                    patch.object(renderer.os, "read", return_value=payload) as read,
                    patch.object(renderer.os, "close"),
                ):
                    if refused:
                        with self.assertRaises(renderer.OwnerIdentityInvalid):
                            renderer._load_store_ids_file()
                    else:
                        self.assertEqual(renderer._load_store_ids_file(), expected)
                        read.assert_called_once_with(123, len(payload) + 1)
                    if name == "oversize":
                        read.assert_not_called()
                    path.read_bytes.assert_not_called()

    def test_compact_identity_read_is_bound_to_one_unchanged_file(self) -> None:
        """EXT2 Turn 4: the compact record is read once, bounded, from the file checked."""
        from types import SimpleNamespace
        from unittest.mock import Mock, patch

        expected = _recorded_listing_ids()
        valid = json.dumps(expected).encode("utf-8")

        def info(**changes: int) -> SimpleNamespace:
            fields = dict(
                st_mode=stat.S_IFREG | 0o644, st_dev=1, st_ino=1, st_nlink=1,
                st_size=len(valid), st_mtime_ns=1, st_ctime_ns=1,
            )
            fields.update(changes)
            return SimpleNamespace(**fields)

        # (name, fstat before, lstat of the path, bytes read, fstat after, refused)
        cases = [
            ("valid", info(), info(), valid, info(), False),
            ("path swapped", info(), info(st_ino=2), valid, info(), True),
            ("path is a symlink", info(), info(st_mode=stat.S_IFLNK | 0o777), valid, info(), True),
            ("hard link", info(st_nlink=2), info(st_nlink=2), valid, info(st_nlink=2), True),
            ("fifo", info(st_mode=stat.S_IFIFO | 0o644), info(st_mode=stat.S_IFIFO | 0o644),
             valid, info(st_mode=stat.S_IFIFO | 0o644), True),
            ("empty", info(st_size=0), info(st_size=0), b"", info(st_size=0), True),
            ("grew while read", info(), info(), valid + b" ", info(), True),
            ("short read", info(), info(), valid[:-1], info(), True),
            ("changed while read", info(), info(), valid, info(st_mtime_ns=2), True),
            ("replaced while read", info(), info(), valid, info(st_ino=3), True),
        ]
        for name, before, path_info, payload, after, refused in cases:
            with self.subTest(case=name):
                path = Mock()
                path.is_file.return_value = True
                path.lstat.return_value = path_info
                path.read_bytes.return_value = payload
                with (
                    patch.object(renderer, "STORE_IDS_FILE", path),
                    patch.object(renderer, "_store_ids_directory_present", return_value=True),
                    patch.object(renderer.os, "open", return_value=123),
                    patch.object(renderer.os, "fstat", side_effect=[before, after]),
                    patch.object(renderer.os, "read", return_value=payload) as read,
                    patch.object(renderer.os, "close") as close,
                ):
                    if refused:
                        with self.assertRaises(renderer.OwnerIdentityInvalid):
                            renderer._load_store_ids_file()
                    else:
                        self.assertEqual(renderer._load_store_ids_file(), expected)
                    if name in {"valid", "grew while read", "short read",
                                "changed while read", "replaced while read"}:
                        read.assert_called_once_with(123, len(valid) + 1)
                    else:
                        read.assert_not_called()
                    close.assert_called_once_with(123)
                    path.read_bytes.assert_not_called()

    def test_compact_identity_files_must_be_exact_bounded_and_regular(self) -> None:
        """EXT2 Turn 4: real files at the compact record path, no mocks."""
        expected = _recorded_listing_ids()

        def refused(root: Path) -> Exception:
            with isolated_store_env(), store_identity_root(root):
                with self.assertRaises(renderer.OwnerIdentityInvalid) as raised:
                    renderer.owner_issued_chromium_ids()
            return raised.exception

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            ids_file = root / STORE_IDS_REL
            ids_file.parent.mkdir(parents=True)
            ids_file.write_text(json.dumps(expected), encoding="utf-8")
            with isolated_store_env(), store_identity_root(root):
                self.assertEqual(renderer.owner_issued_chromium_ids(), expected)
            for name, document in (
                ("padded chrome", dict(expected, chrome=" " + expected["chrome"])),
                ("padded edge", dict(expected, edge=expected["edge"] + "\n")),
                ("tab padded chrome", dict(expected, chrome=expected["chrome"] + "\t")),
                ("shared id", dict(expected, edge=expected["chrome"])),
            ):
                with self.subTest(case=name):
                    ids_file.write_text(json.dumps(document), encoding="utf-8")
                    refused(root)
            with self.subTest(case="valid record padded past the size bound"):
                payload = json.dumps(expected).encode("utf-8")
                ids_file.write_bytes(
                    payload + b" " * (renderer.STORE_IDS_MAX_BYTES + 1 - len(payload))
                )
                self.assertIn("bounded single-link regular file", str(refused(root)))
            elsewhere = root / "elsewhere.json"
            elsewhere.write_text(json.dumps(expected), encoding="utf-8")
            for name, target in (
                ("symlink to a valid record", elsewhere),
                ("dangling symlink", root / "missing.json"),
            ):
                with self.subTest(case=name):
                    ids_file.unlink()
                    ids_file.symlink_to(target)
                    try:
                        refused(root)
                    finally:
                        ids_file.unlink()
                        ids_file.write_text(json.dumps(expected), encoding="utf-8")
            with self.subTest(case="fifo is refused without blocking"):
                ids_file.unlink()
                os.mkfifo(ids_file)
                try:
                    completed = subprocess.run(
                        [
                            sys.executable, "-I", "-c",
                            "import runpy,sys\n"
                            "from pathlib import Path\n"
                            "g = runpy.run_path(sys.argv[1])\n"
                            "g['_load_store_ids_file'].__globals__['STORE_IDS_FILE'] = Path(sys.argv[2])\n"
                            "try:\n"
                            "    got = g['_load_store_ids_file']()\n"
                            "except ValueError as error:\n"
                            "    print('REFUSED', type(error).__name__)\n"
                            "else:\n"
                            "    print('ACCEPTED' if got else 'ABSENT')\n",
                            str(HERE / "render_host_manifest.py"), str(ids_file),
                        ],
                        check=False, capture_output=True, text=True, timeout=30,
                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    )
                except subprocess.TimeoutExpired:
                    self.fail("reading a FIFO compact record blocked")
                finally:
                    ids_file.unlink()
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip(), "REFUSED OwnerIdentityInvalid")

    def test_identity_record_read_errors_are_identity_refusals(self) -> None:
        """EXT2 Turn 4: an I/O error while reading either record is a refusal."""
        import errno
        from types import SimpleNamespace
        from unittest.mock import Mock, patch

        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_read_errors", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644, st_dev=1, st_ino=1, st_nlink=1,
            st_size=512, st_mtime_ns=1, st_ctime_ns=1,
        )
        for name, module, attribute, call, invalid in (
            ("compact store_ids.json", renderer, "STORE_IDS_FILE",
             renderer._load_store_ids_file, renderer.OwnerIdentityInvalid),
            ("store_identity.json checker", checker, "STORE_IDENTITY_FILE",
             checker.recorded_store_identity, checker.renderer.OwnerIdentityInvalid),
        ):
            with self.subTest(case=name):
                path = Mock()
                path.is_file.return_value = True
                path.lstat.return_value = info
                path.read_bytes.side_effect = OSError(errno.EIO, "I/O error")
                with (
                    patch.object(module, attribute, path),
                    patch.object(renderer, "_store_ids_directory_present", return_value=True),
                    patch.object(module.os, "open", return_value=123),
                    patch.object(module.os, "fstat", return_value=info),
                    patch.object(module.os, "read", side_effect=OSError(errno.EIO, "I/O error")),
                    patch.object(module.os, "close") as close,
                ):
                    with self.assertRaises(invalid) as raised:
                        call()
                    self.assertIn("unreadable", str(raised.exception))
                    close.assert_called_once_with(123)

    def test_env_and_caller_ids_only_corroborate_the_record(self) -> None:
        ids = {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID}
        other = "a" * 32
        with isolated_store_env(ids):
            self.assertEqual(
                renderer.resolve_cli_extension_id("chrome", CALLER_CHROMIUM_ID),
                CALLER_CHROMIUM_ID,
            )
            self.assertEqual(renderer.resolve_cli_extension_id("edge", None), FIXTURE_EDGE_ID)
            with self.assertRaises(renderer.OwnerIdentityInvalid):
                renderer.resolve_cli_extension_id("chrome", other)
            with self.assertRaises(ValueError):
                renderer.resolve_cli_extension_id("chrome", "PLACEHOLDER_CHROME_EXTENSION_ID")
        with isolated_store_env(ids, WINSVPN_CHROME_STORE_ID=CALLER_CHROMIUM_ID):
            self.assertEqual(renderer.recorded_store_ids(), ids)
        with isolated_store_env(ids, WINSVPN_CHROME_STORE_ID=other):
            with self.assertRaises(renderer.OwnerIdentityInvalid):
                renderer.recorded_store_ids()
        with isolated_store_env(
            {"chrome": CALLER_CHROMIUM_ID}, WINSVPN_EDGE_STORE_ID=FIXTURE_EDGE_ID
        ):
            with self.assertRaises(renderer.OwnerIdentityInvalid) as raised:
                renderer.recorded_store_ids()
            self.assertIn("cannot supply", str(raised.exception))
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            env = _store_ids_python_env(root, ids)
            mismatch = _render_cli(env, "chrome", root / "chrome.json", other)
            self.assertEqual(mismatch.returncode, 1, mismatch.stderr)
            self.assertIn("does not match", mismatch.stderr)
            self.assertFalse((root / "chrome.json").exists())

    def test_store_ids_record_refuses_unsafe_or_malformed_files(self) -> None:
        good = {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID}
        content_cases = [
            ("placeholder", b'{"chrome": "PLACEHOLDER_CHROME_EXTENSION_ID"}', "placeholder"),
            ("bad alphabet", b'{"edge": "' + b"z" * 32 + b'"}', "32 lowercase"),
            ("short", b'{"chrome": "abc"}', "32 lowercase"),
            (
                "same ids",
                json.dumps({"chrome": CALLER_CHROMIUM_ID, "edge": CALLER_CHROMIUM_ID}).encode(),
                "same id",
            ),
            ("extra key", json.dumps({**good, "safari": CALLER_CHROMIUM_ID}).encode(), "unexpected"),
            (
                "firefox key",
                json.dumps({**good, "firefox": "companion@winsvpn.org"}).encode(),
                "unexpected",
            ),
            (
                "duplicate key",
                ('{"chrome": "%s", "chrome": "%s"}' % (CALLER_CHROMIUM_ID, FIXTURE_EDGE_ID)).encode(),
                "duplicate JSON key",
            ),
            ("list", b"[]", "one JSON object"),
            ("not json", b"chrome=" + CALLER_CHROMIUM_ID.encode(), "valid UTF-8 JSON"),
            ("empty", b"", "non-empty"),
            ("oversized", b" " * (64 * 1024 + 1) + b"{}", "non-empty"),
            ("padded", ('{"chrome": " %s"}' % CALLER_CHROMIUM_ID).encode(), "whitespace"),
            ("number", b'{"chrome": 7}', "non-empty JSON string"),
        ]
        for name, payload, needle in content_cases:
            with self.subTest(case=name):
                with isolated_store_env() as record:
                    record.write_bytes(payload)
                    os.chmod(record, 0o644)
                    with self.assertRaises(ValueError) as raised:
                        renderer.recorded_store_ids()
                    self.assertIn(needle, str(raised.exception))
        if os.name == "nt":
            return
        with isolated_store_env() as record:
            target = record.parent / "real.json"
            target.write_text(json.dumps(good), encoding="ascii")
            os.chmod(target, 0o644)
            record.symlink_to(target)
            with self.assertRaises(renderer.OwnerIdentityInvalid) as raised:
                renderer.recorded_store_ids()
            self.assertIn("symlink", str(raised.exception))
        with isolated_store_env(good) as record:
            os.link(record, record.parent / "alias.json")
            with self.assertRaises(renderer.OwnerIdentityInvalid) as raised:
                renderer.recorded_store_ids()
            self.assertIn("single-link", str(raised.exception))
        for mode in (0o664, 0o646):
            with self.subTest(file_mode=oct(mode)):
                with isolated_store_env(good) as record:
                    os.chmod(record, mode)
                    with self.assertRaises(renderer.OwnerIdentityInvalid) as raised:
                        renderer.recorded_store_ids()
                    self.assertIn("group- or world-writable", str(raised.exception))
        with isolated_store_env(good) as record:
            os.chmod(record.parent, 0o775)
            try:
                with self.assertRaises(renderer.OwnerIdentityInvalid) as raised:
                    renderer.recorded_store_ids()
                self.assertIn(
                    "directory must not be group- or world-writable", str(raised.exception)
                )
            finally:
                os.chmod(record.parent, 0o755)
        with isolated_store_env() as record:
            real_dir = record.parent.parent / "real-manifests"
            _write_store_ids(real_dir / "store_ids.json", good)
            os.rmdir(record.parent)
            record.parent.symlink_to(real_dir)
            with self.assertRaises(renderer.OwnerIdentityInvalid) as raised:
                renderer.recorded_store_ids()
            self.assertIn("not a symlink", str(raised.exception))
        with isolated_store_env() as record:
            os.mkfifo(record)
            with self.assertRaises(renderer.OwnerIdentityInvalid) as raised:
                renderer.recorded_store_ids()
            self.assertIn("regular file", str(raised.exception))

    def test_check_host_manifests_refuses_placeholders_without_recorded_ids(
        self,
    ) -> None:
        with isolated_store_env(), tempfile.TemporaryDirectory() as raw:
            manifests = Path(raw) / "templates"
            manifests.mkdir()
            for browser in ("chrome", "edge"):
                (manifests / f"org.winsvpn.bridge.{browser}.json").write_text(
                    json.dumps({"allowed_origins": ["chrome-extension://PLACEHOLDER/"]}),
                    encoding="utf-8",
                )
            (manifests / "org.winsvpn.bridge.firefox.json").write_text(
                json.dumps({"allowed_extensions": [renderer.canonical_firefox_id()]}),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, "-c",
                 "import runpy,sys; from pathlib import Path; "
                 "checker=runpy.run_path(sys.argv[1]); "
                 "checker['main'].__globals__['MANIFESTS']=Path(sys.argv[2]); "
                 "checker['main'].__globals__['STORE_IDENTITY_FILE']=Path(sys.argv[3]); "
                 "sys.exit(checker['main']())",
                 str(HERE / "check_host_manifests.py"), str(manifests),
                 str(manifests / "absent-store-identity.json")],
                check=False,
                capture_output=True,
                text=True,
                cwd=str(REPO),
                env=_store_ids_python_env(Path(raw), None),
            )
            output = completed.stdout + completed.stderr
            self.assertNotEqual(completed.returncode, 0, output)
            self.assertIn("WARN", completed.stdout)
            self.assertIn("FAIL", completed.stdout)
            self.assertIn("store_ids.json", output)
            self.assertIn("PLACEHOLDER", (manifests / "org.winsvpn.bridge.chrome.json").read_text())
        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_under_test", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        with tempfile.TemporaryDirectory() as raw:
            template = Path(raw) / "org.winsvpn.bridge.chrome.json"
            template.write_text(
                json.dumps(
                    {
                        "name": "org.winsvpn.bridge",
                        "allowed_origins": [
                            f"chrome-extension://{CALLER_CHROMIUM_ID}/"
                        ],
                    }
                ),
                encoding="utf-8",
            )
            checker.FAILED = False
            checker.check_chromium(template, "chrome", None)
            self.assertTrue(checker.FAILED)

    def test_check_host_manifests_refuses_missing_unsafe_and_placeholder_records(
        self,
    ) -> None:
        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_receipt_refusals", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        refusals = (
            renderer.OwnerIdentityBlocked(renderer.missing_store_id_message("edge")),
            renderer.OwnerIdentityInvalid("native-host store id record must not be a symlink"),
            renderer.OwnerIdentityInvalid(
                "chrome extension id is missing or is a placeholder"
            ),
        )
        for error in refusals:
            with self.subTest(error=str(error)):
                checker.FAILED = False
                with isolated_store_env():
                    original = checker.renderer.owner_issued_chromium_ids

                    def blocked(_error=error) -> dict[str, str]:
                        raise _error

                    checker.renderer.owner_issued_chromium_ids = blocked
                    try:
                        ids = checker.known_ids()
                    finally:
                        checker.renderer.owner_issued_chromium_ids = original
                self.assertEqual(ids, {})
                self.assertTrue(checker.FAILED)

    def _store_identity_record(
        self, chrome_id: str = CALLER_CHROMIUM_ID, edge_id: str = FIXTURE_EDGE_ID
    ) -> dict[str, object]:
        stores: dict[str, object] = {}
        for browser, extension_id, name in (
            ("chrome", chrome_id, "Win's VPN Proxy for Chrome"),
            ("edge", edge_id, "Win's VPN Proxy for Microsoft Edge"),
            ("firefox", "companion@winsvpn.org", "Win's VPN Proxy"),
        ):
            stores[f"{browser}-extension-package"] = {
                "listing_name": name,
                "store_id": extension_id,
                "native_host_template":
                    f"tools/native_messaging/manifests/org.winsvpn.bridge.{browser}.json",
                "native_host_allowlist": [
                    extension_id if browser == "firefox"
                    else f"chrome-extension://{extension_id}/"
                ],
            }
        return {
            "schema_version": 1,
            "contract": renderer.STORE_IDENTITY_CONTRACT,
            "native_host_name": "org.winsvpn.bridge",
            "stores": stores,
        }

    def test_check_host_manifests_reads_the_record_and_never_a_receipt(self) -> None:
        """Owner ruling: no receipt, age or approval decides a stable store id."""
        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_record_only", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        # The receipt reader is gone (SEALED): the checker binds the committed
        # store_ids.json record and the store identity record, which must agree.
        self.assertFalse(hasattr(checker.renderer, "bind_owner_identity"))
        with isolated_store_env({"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID}), tempfile.TemporaryDirectory() as raw:
            record = Path(raw) / "store_identity.json"
            record.write_text(json.dumps(self._store_identity_record()), encoding="utf-8")
            checker.STORE_IDENTITY_FILE = record
            checker.FAILED = False
            self.assertEqual(
                checker.known_ids(),
                {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID},
            )
            self.assertFalse(checker.FAILED)
            with self.subTest(case="the two records disagree"):
                record.write_text(
                    json.dumps(self._store_identity_record(chrome_id="a" * 32)),
                    encoding="utf-8",
                )
                checker.FAILED = False
                self.assertEqual(checker.known_ids(), {})
                self.assertTrue(checker.FAILED)

    def test_check_host_manifests_refuses_missing_and_inconsistent_records(
        self,
    ) -> None:
        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_record_refusals", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)

        def mutate(path: tuple[str, ...], value: object):
            def apply(record: dict[str, object]) -> None:
                target = record
                for key in path[:-1]:
                    target = target[key]  # type: ignore[index]
                target[path[-1]] = value  # type: ignore[index]
            return apply

        chrome = ("stores", "chrome-extension-package")
        cases = {
            "placeholder chrome id": mutate(chrome + ("store_id",), "PLACEHOLDER_CHROME_ID"),
            "malformed chrome id": mutate(chrome + ("store_id",), "A" * 32),
            "padded chrome id": mutate(chrome + ("store_id",), f" {CALLER_CHROMIUM_ID}"),
            # Edge's entry is otherwise self-consistent, so only distinctness refuses it.
            "reused id": lambda record: record["stores"].__setitem__(
                "edge-extension-package",
                self._store_identity_record(edge_id=CALLER_CHROMIUM_ID)["stores"][
                    "edge-extension-package"
                ],
            ),
            "wrong template": mutate(chrome + ("native_host_template",),
                                     "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json"),
            "wrong allowlist": mutate(chrome + ("native_host_allowlist",),
                                      [f"chrome-extension://{FIXTURE_EDGE_ID}/"]),
            "wrong listing name": mutate(chrome + ("listing_name",), "Other"),
            "firefox id": mutate(("stores", "firefox-extension-package", "store_id"),
                                 "other@example.invalid"),
            "missing edge": lambda record: record["stores"].pop("edge-extension-package"),
            "boolean schema": mutate(("schema_version",), True),
            "wrong contract": mutate(("contract",), "other"),
            "wrong host name": mutate(("native_host_name",), "org.example.bridge"),
        }
        with isolated_store_env({"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID}), tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            documents: dict[str, bytes | None] = {"missing record": None}
            for name, change in cases.items():
                record = self._store_identity_record()
                change(record)
                documents[name] = json.dumps(record).encode("utf-8")
            valid = json.dumps(self._store_identity_record())
            documents["duplicate key"] = (
                valid[:-1] + ', "contract": "other"}'
            ).encode("utf-8")
            for name, payload in documents.items():
                with self.subTest(case=name):
                    record_path = root / f"{len(name)}-{name.replace(' ', '-')}.json"
                    if payload is not None:
                        record_path.write_bytes(payload)
                    checker.STORE_IDENTITY_FILE = record_path
                    checker.FAILED = False
                    self.assertEqual(checker.known_ids(), {})
                    self.assertTrue(checker.FAILED)
            link = root / "linked-record.json"
            target = root / "real-record.json"
            target.write_text(valid, encoding="utf-8")
            link.symlink_to(target)
            with self.subTest(case="symlink"):
                checker.STORE_IDENTITY_FILE = link
                checker.FAILED = False
                self.assertEqual(checker.known_ids(), {})
                self.assertTrue(checker.FAILED)
            checker.STORE_IDENTITY_FILE = target
            for env_name, value in (
                ("WINSVPN_CHROME_STORE_ID", FIXTURE_EDGE_ID),
                ("WINSVPN_EDGE_STORE_ID", CALLER_CHROMIUM_ID),
            ):
                with self.subTest(case=f"disagreeing {env_name}"):
                    os.environ[env_name] = value
                    try:
                        checker.FAILED = False
                        self.assertEqual(checker.known_ids(), {})
                        self.assertTrue(checker.FAILED)
                    finally:
                        os.environ.pop(env_name, None)
            checker.FAILED = False
            self.assertEqual(
                checker.known_ids(),
                {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID},
            )
            self.assertFalse(checker.FAILED)

    def test_check_host_manifests_record_read_is_bounded_and_bound_to_one_file(
        self,
    ) -> None:
        """EXT2 Turn 4: store_identity.json gets the compact record's read rule."""
        from types import SimpleNamespace
        from unittest.mock import Mock, patch

        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_bounded_read", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        valid = json.dumps(self._store_identity_record()).encode("utf-8")
        expected = {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID,
                    "firefox": "companion@winsvpn.org"}

        def info(**changes: int) -> SimpleNamespace:
            fields = dict(
                st_mode=stat.S_IFREG | 0o644, st_dev=1, st_ino=1, st_nlink=1,
                st_size=len(valid), st_mtime_ns=1, st_ctime_ns=1,
            )
            fields.update(changes)
            return SimpleNamespace(**fields)

        oversize = renderer.STORE_IDS_MAX_BYTES + 1
        # (name, fstat before, lstat of the path, bytes read, fstat after, refused)
        cases = [
            ("valid", info(), info(), valid, info(), False),
            ("path swapped", info(), info(st_ino=2), valid, info(), True),
            ("path is a symlink", info(), info(st_mode=stat.S_IFLNK | 0o777), valid, info(), True),
            ("grew while read", info(), info(), valid + b" ", info(), True),
            ("short read", info(), info(), valid[:-1], info(), True),
            ("changed while read", info(), info(), valid, info(st_mtime_ns=2), True),
            ("replaced while read", info(), info(), valid, info(st_ino=3), True),
            ("oversize", info(st_size=oversize), info(st_size=oversize),
             valid, info(st_size=oversize), True),
        ]
        with isolated_store_env():
            for name, before, path_info, payload, after, refused in cases:
                with self.subTest(case=name):
                    path = Mock()
                    path.lstat.return_value = path_info
                    path.read_bytes.return_value = payload
                    with (
                        patch.object(checker, "STORE_IDENTITY_FILE", path),
                        patch.object(checker.os, "open", return_value=123),
                        patch.object(checker.os, "fstat", side_effect=[before, after]),
                        patch.object(checker.os, "read", return_value=payload) as read,
                        patch.object(checker.os, "close") as close,
                    ):
                        if refused:
                            with self.assertRaises(ValueError):
                                checker.recorded_store_identity()
                        else:
                            self.assertEqual(checker.recorded_store_identity(), expected)
                        if name in {"oversize", "path swapped", "path is a symlink"}:
                            read.assert_not_called()
                        else:
                            read.assert_called_once_with(123, len(valid) + 1)
                        close.assert_called_once_with(123)
                        path.read_bytes.assert_not_called()

    def test_check_host_manifests_record_files_are_bounded_and_never_block(
        self,
    ) -> None:
        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_record_files", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        with isolated_store_env(), tempfile.TemporaryDirectory() as raw:
            record = Path(raw) / "store_identity.json"
            payload = json.dumps(self._store_identity_record()).encode("utf-8")
            record.write_bytes(payload)
            checker.STORE_IDENTITY_FILE = record
            self.assertEqual(checker.recorded_store_identity()["edge"], FIXTURE_EDGE_ID)
            with self.subTest(case="valid record padded past the size bound"):
                record.write_bytes(
                    payload + b" " * (renderer.STORE_IDS_MAX_BYTES + 1 - len(payload))
                )
                with self.assertRaises(ValueError) as raised:
                    checker.recorded_store_identity()
                self.assertIn("bounded single-link regular file", str(raised.exception))
            with self.subTest(case="fifo is refused without blocking"):
                record.unlink()
                os.mkfifo(record)
                try:
                    completed = subprocess.run(
                        [
                            sys.executable, "-I", "-c",
                            "import runpy,sys\n"
                            "from pathlib import Path\n"
                            "g = runpy.run_path(sys.argv[1])\n"
                            "g['recorded_store_identity'].__globals__['STORE_IDENTITY_FILE'] = Path(sys.argv[2])\n"
                            "try:\n"
                            "    g['recorded_store_identity']()\n"
                            "except ValueError as error:\n"
                            "    print('REFUSED', error)\n"
                            "else:\n"
                            "    print('ACCEPTED')\n",
                            str(HERE / "check_host_manifests.py"), str(record),
                        ],
                        check=False, capture_output=True, text=True, timeout=30,
                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                             "WINSVPN_CHROME_STORE_ID": "", "WINSVPN_EDGE_STORE_ID": ""},
                    )
                except subprocess.TimeoutExpired:
                    self.fail("reading a FIFO store identity record blocked")
                finally:
                    record.unlink()
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("REFUSED", completed.stdout)
                self.assertIn("bounded single-link regular file", completed.stdout)

    def test_check_host_manifests_accepts_templates_bound_to_fixture_owner_ids(
        self,
    ) -> None:
        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_fixture_pass", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        with tempfile.TemporaryDirectory() as raw:
            manifests = Path(raw)
            for browser, extension_id in (
                ("chrome", CALLER_CHROMIUM_ID),
                ("edge", FIXTURE_EDGE_ID),
            ):
                (manifests / f"org.winsvpn.bridge.{browser}.json").write_text(
                    json.dumps(
                        {
                            "name": "org.winsvpn.bridge",
                            "allowed_origins": [
                                f"chrome-extension://{extension_id}/"
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
            (manifests / "org.winsvpn.bridge.firefox.json").write_text(
                json.dumps(
                    {
                        "name": "org.winsvpn.bridge",
                        "allowed_extensions": ["companion@winsvpn.org"],
                    }
                ),
                encoding="utf-8",
            )
            original_manifests = checker.MANIFESTS
            original_ids = checker.renderer.owner_issued_chromium_ids
            original_listing = checker.recorded_store_identity
            checker.MANIFESTS = manifests
            checker.FAILED = False

            def issued() -> dict[str, str]:
                return {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID}

            checker.renderer.owner_issued_chromium_ids = issued
            checker.recorded_store_identity = issued
            try:
                self.assertEqual(checker.main(), 0)
            finally:
                checker.MANIFESTS = original_manifests
                checker.renderer.owner_issued_chromium_ids = original_ids
                checker.recorded_store_identity = original_listing
                checker.FAILED = False

    def _write_host_templates(
        self,
        manifests: Path,
        chrome_id: str,
        edge_id: str,
        firefox_id: str = "companion@winsvpn.org",
    ) -> None:
        for browser, extension_id in (("chrome", chrome_id), ("edge", edge_id)):
            (manifests / f"org.winsvpn.bridge.{browser}.json").write_text(
                json.dumps(
                    {
                        "name": "org.winsvpn.bridge",
                        "allowed_origins": [
                            f"chrome-extension://{extension_id}/"
                        ],
                    }
                ),
                encoding="utf-8",
            )
        (manifests / "org.winsvpn.bridge.firefox.json").write_text(
            json.dumps(
                {
                    "name": "org.winsvpn.bridge",
                    "allowed_extensions": [firefox_id],
                }
            ),
            encoding="utf-8",
        )

    def test_check_host_manifests_refuses_cross_browser_origin_substitution(
        self,
    ) -> None:
        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_cross_browser", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        with tempfile.TemporaryDirectory() as raw:
            manifests = Path(raw)
            self._write_host_templates(
                manifests, FIXTURE_EDGE_ID, CALLER_CHROMIUM_ID
            )
            original_manifests = checker.MANIFESTS
            original_ids = checker.renderer.owner_issued_chromium_ids
            original_listing = checker.recorded_store_identity
            checker.MANIFESTS = manifests
            checker.FAILED = False

            def issued() -> dict[str, str]:
                return {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID}

            checker.renderer.owner_issued_chromium_ids = issued
            checker.recorded_store_identity = issued
            try:
                self.assertEqual(checker.main(), 1)
            finally:
                checker.MANIFESTS = original_manifests
                checker.renderer.owner_issued_chromium_ids = original_ids
                checker.recorded_store_identity = original_listing
                checker.FAILED = False

    def test_check_host_manifests_refuses_reused_chrome_and_edge_identity(
        self,
    ) -> None:
        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_reused_ids", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        with tempfile.TemporaryDirectory() as raw:
            manifests = Path(raw)
            self._write_host_templates(
                manifests, CALLER_CHROMIUM_ID, CALLER_CHROMIUM_ID
            )
            original_manifests = checker.MANIFESTS
            original_ids = checker.renderer.owner_issued_chromium_ids
            original_listing = checker.recorded_store_identity
            checker.MANIFESTS = manifests
            checker.FAILED = False

            def issued() -> dict[str, str]:
                return {"chrome": CALLER_CHROMIUM_ID, "edge": CALLER_CHROMIUM_ID}

            checker.renderer.owner_issued_chromium_ids = issued
            checker.recorded_store_identity = issued
            try:
                self.assertEqual(checker.main(), 1)
            finally:
                checker.MANIFESTS = original_manifests
                checker.renderer.owner_issued_chromium_ids = original_ids
                checker.recorded_store_identity = original_listing
                checker.FAILED = False

    def test_check_host_manifests_keeps_firefox_pinned_when_chromium_ids_are_bound(
        self,
    ) -> None:
        checker_mod_spec = importlib.util.spec_from_file_location(
            "check_host_manifests_firefox_pin", HERE / "check_host_manifests.py"
        )
        assert checker_mod_spec is not None and checker_mod_spec.loader is not None
        checker = importlib.util.module_from_spec(checker_mod_spec)
        checker_mod_spec.loader.exec_module(checker)
        with tempfile.TemporaryDirectory() as raw:
            manifests = Path(raw)
            self._write_host_templates(
                manifests,
                CALLER_CHROMIUM_ID,
                FIXTURE_EDGE_ID,
                firefox_id="other@example.invalid",
            )
            original_manifests = checker.MANIFESTS
            original_ids = checker.renderer.owner_issued_chromium_ids
            original_listing = checker.recorded_store_identity
            checker.MANIFESTS = manifests
            checker.FAILED = False

            def issued() -> dict[str, str]:
                return {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID}

            checker.renderer.owner_issued_chromium_ids = issued
            checker.recorded_store_identity = issued
            try:
                self.assertEqual(checker.main(), 1)
            finally:
                checker.MANIFESTS = original_manifests
                checker.renderer.owner_issued_chromium_ids = original_ids
                checker.recorded_store_identity = original_listing
                checker.FAILED = False


class LayoutInstallUninstallTests(unittest.TestCase):
    def test_unix_destinations_match_the_browser_search_paths(self) -> None:
        home = Path("/tmp/winsvpn-home")
        expected = {
            ("chrome", "Darwin", False): home
            / "Library/Application Support/Google/Chrome/NativeMessagingHosts",
            ("chrome", "Darwin", True): Path("/Library/Google/Chrome/NativeMessagingHosts"),
            ("chrome", "Linux", False): home / ".config/google-chrome/NativeMessagingHosts",
            ("chrome", "Linux", True): Path("/etc/opt/chrome/native-messaging-hosts"),
            ("edge", "Darwin", False): home
            / "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
            ("edge", "Darwin", True): Path("/Library/Microsoft/Edge/NativeMessagingHosts"),
            ("edge", "Linux", False): home / ".config/microsoft-edge/NativeMessagingHosts",
            ("firefox", "Darwin", False): home
            / "Library/Application Support/Mozilla/NativeMessagingHosts",
            ("firefox", "Linux", False): home / ".mozilla/native-messaging-hosts",
            ("firefox", "Linux", True): Path("/usr/lib/mozilla/native-messaging-hosts"),
        }
        for (browser, os_name, system), dest in expected.items():
            with self.subTest(browser=browser, os_name=os_name, system=system):
                self.assertEqual(
                    layout.unix_manifest_dir(
                        browser, os_name, system=system, home=home
                    ),
                    dest,
                )

    def test_install_uninstall_are_idempotent_and_do_not_invent_ids(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            firefox_path = root / "firefox" / layout.UNIX_MANIFEST_NAME
            with isolated_store_env():
                layout.install_manifest(
                    browser="firefox",
                    host_path=str(root / "bin" / "wins_bridge_host"),
                    manifest_path=firefox_path,
                )
                payload = json.loads(firefox_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    payload["allowed_extensions"], ["companion@winsvpn.org"]
                )
                self.assertTrue(layout.uninstall_manifest(firefox_path))
                self.assertFalse(firefox_path.exists())
                self.assertFalse(layout.uninstall_manifest(firefox_path))
                with self.assertRaises(layout.MissingStoreIdError):
                    layout.install_manifest(
                        browser="chrome",
                        host_path=str(root / "bin" / "wins_bridge_host"),
                        manifest_path=root / "chrome.json",
                    )
                self.assertFalse((root / "chrome.json").exists())
                layout.install_manifest(
                    browser="chrome",
                    host_path=str(root / "bin" / "wins_bridge_host"),
                    manifest_path=root / "chrome.json",
                    extension_id=CALLER_CHROMIUM_ID,
                )
                chrome = json.loads((root / "chrome.json").read_text(encoding="utf-8"))
                self.assertEqual(
                    chrome["allowed_origins"],
                    [f"chrome-extension://{CALLER_CHROMIUM_ID}/"],
                )

    def test_origin_companion_preserves_browser_slots_and_replaces_rotated_id(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            host = root / "bin" / "wins_bridge_host"
            ids = {"chrome": "a" * 32, "edge": "b" * 32, "firefox": layout.FIREFOX_ID}
            for browser, identity in ids.items():
                manifest_path = root / browser / layout.UNIX_MANIFEST_NAME
                layout.install_manifest(browser=browser, host_path=str(host),
                                        manifest_path=manifest_path, extension_id=identity)
                self.assertTrue((manifest_path.parent / "allowed_origins.txt").is_file())
            companion = host.parent / "allowed_origins.txt"
            installed = layout.read_installed_origins(companion)
            self.assertEqual(installed, {
                "chrome": ["chrome-extension://" + "a" * 32 + "/"],
                "edge": ["chrome-extension://" + "b" * 32 + "/"],
                "firefox": [layout.FIREFOX_ID],
            })
            layout.install_manifest(browser="chrome", host_path=str(host),
                                    manifest_path=root / "chrome" / layout.UNIX_MANIFEST_NAME,
                                    extension_id="c" * 32)
            updated = layout.read_installed_origins(companion)
            self.assertEqual(updated["chrome"], ["chrome-extension://" + "c" * 32 + "/"])
            self.assertEqual(updated["edge"], installed["edge"])
            self.assertEqual(updated["firefox"], installed["firefox"])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(companion.stat().st_mode), 0o644)
            self.assertNotIn(b"\r", companion.read_bytes())

    def test_origin_companion_rejects_malformed_and_linked_configuration(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            host = root / "wins_bridge_host"
            companion = root / "allowed_origins.txt"
            manifest_path = root / layout.UNIX_MANIFEST_NAME
            for body in ["{", "[]", '{"unknown": []}', '{"chrome": ["foreign"]}', " " * 4097]:
                companion.write_text(body)
                with self.assertRaises((ValueError, OSError)):
                    layout.install_manifest(browser="firefox", host_path=str(host),
                                            manifest_path=manifest_path)
                self.assertFalse(manifest_path.exists())
            if os.name != "nt":
                companion.unlink()
                sentinel = root / "sentinel"
                sentinel.write_text("{}")
                companion.symlink_to(sentinel)
                with self.assertRaises((ValueError, OSError)):
                    layout.install_manifest(browser="firefox", host_path=str(host),
                                            manifest_path=manifest_path)
                self.assertEqual(sentinel.read_text(), "{}")

    def test_windows_plan_matches_inno_registry_contract(self) -> None:
        iss = (REPO / "installer" / "windows" / "winsvpn.iss").read_text(
            encoding="utf-8"
        )
        with isolated_store_env():
            firefox = layout.registration_plan(
                browser="firefox",
                host_path="wins_bridge_host.exe",
                manifest_path=Path(r"C:\Program Files\WinsVPN\NativeMessagingHost\org.winsvpn.bridge.firefox.json"),
                allow_relative_host_path=True,
                windows_hive="HKLM",
            )
        self.assertEqual(len(firefox["registry"]), 2)
        for entry in firefox["registry"]:
            self.assertIn(entry["hive"], {"HKLM32", "HKLM64"})
            self.assertEqual(
                entry["subkey"], layout.WINDOWS_REGISTRY_SUBKEYS["firefox"]
            )
            self.assertEqual(entry["uninstall"], "delete_key")
            expected = (
                f'Root: {entry["hive"]}; Subkey: "{entry["subkey"]}"; '
                'ValueType: string; ValueName: ""; '
                'ValueData: "{app}\\NativeMessagingHost\\org.winsvpn.bridge.firefox.json"; '
                "Flags: uninsdeletekey"
            )
            self.assertIn(expected, iss)
        with isolated_store_env():
            with self.assertRaises(layout.MissingStoreIdError):
                layout.registration_plan(
                    browser="chrome",
                    host_path="wins_bridge_host.exe",
                    manifest_path=Path("chrome.json"),
                    allow_relative_host_path=True,
                    windows_hive="HKLM",
                )
        chrome_block = iss.split("#ifdef EnableChromeNativeHost", 1)[1].split(
            "#endif", 1
        )[0]
        self.assertIn(layout.WINDOWS_REGISTRY_SUBKEYS["chrome"], chrome_block)
        self.assertIn("uninsdeletekey", chrome_block)
        edge_block = iss.split("#ifdef EnableEdgeNativeHost", 1)[1].split(
            "#endif", 1
        )[0]
        self.assertIn(layout.WINDOWS_REGISTRY_SUBKEYS["edge"], edge_block)
        self.assertIn("uninsdeletekey", edge_block)


class ShellInstallContractTests(unittest.TestCase):
    def test_dummy_host_executes_with_current_base_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dummy = write_dummy_host(Path(raw) / "wins_bridge_host")
            self.assertIn(
                shlex.quote(str(_dummy_host_interpreter())),
                dummy.read_text(encoding="utf-8"),
            )
            request = b"{}"
            completed = subprocess.run(
                [str(dummy)],
                input=len(request).to_bytes(4, "little") + request,
                check=False,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertGreaterEqual(len(completed.stdout), 4)
            response_size = int.from_bytes(completed.stdout[:4], "little")
            response = json.loads(completed.stdout[4:].decode("utf-8"))
            self.assertEqual(response_size, len(completed.stdout) - 4)
            self.assertEqual(response["type"], "hello")
            self.assertEqual(response["protocolVersion"], 1)
            self.assertEqual(response["status"], "app_not_running")

    def test_dummy_host_executes_with_sys_executable_fallback(self) -> None:
        had_marker = hasattr(sys, "_base_executable")
        marker = getattr(sys, "_base_executable", None)
        try:
            sys._base_executable = ""
            with tempfile.TemporaryDirectory() as raw:
                dummy = write_dummy_host(Path(raw) / "wins_bridge_host")
                self.assertIn(
                    shlex.quote(sys.executable), dummy.read_text(encoding="utf-8")
                )
                completed = subprocess.run(
                    [str(dummy)], check=False, capture_output=True
                )
                self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        finally:
            if had_marker:
                sys._base_executable = marker
            else:
                del sys._base_executable

    def test_install_and_uninstall_use_renderer_against_a_prefix(self) -> None:
        installer = HERE / "install_native_host.sh"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            dummy = write_dummy_host(root / "wins_bridge_host")
            host_dest = root / "lib"
            manifest_dest = root / "mozilla"
            installed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(host_dest),
                    "--manifest-dir",
                    str(manifest_dest),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            manifest = manifest_dest / "org.winsvpn.bridge.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(payload["name"], "org.winsvpn.bridge")
            self.assertEqual(
                payload["allowed_extensions"], ["companion@winsvpn.org"]
            )
            self.assertTrue((host_dest / "wins_bridge_host").is_file())
            removed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--uninstall",
                    "--remove-host",
                    "--dest-dir",
                    str(host_dest),
                    "--manifest-dir",
                    str(manifest_dest),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(manifest.exists())
            self.assertFalse((host_dest / "wins_bridge_host").exists())

    def test_chrome_placeholder_is_refused_before_any_copy(self) -> None:
        installer = HERE / "install_native_host.sh"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            dummy = write_dummy_host(root / "wins_bridge_host")
            completed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(root / "lib"),
                    "--manifest-dir",
                    str(root / "chrome"),
                    "chrome",
                    "PLACEHOLDER_CHROME_EXTENSION_ID",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("PLACEHOLDER", completed.stderr)
            self.assertEqual(list((root / "chrome").glob("*")), [])
            self.assertEqual(list((root / "lib").glob("*")), [])

    def test_chrome_caller_supplied_id_installs_and_uninstalls(self) -> None:
        installer = HERE / "install_native_host.sh"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            dummy = write_dummy_host(root / "wins_bridge_host")
            installed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(root / "lib"),
                    "--manifest-dir",
                    str(root / "chrome"),
                    "chrome",
                    CALLER_CHROMIUM_ID,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            payload = json.loads(
                (root / "chrome" / "org.winsvpn.bridge.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                payload["allowed_origins"],
                [f"chrome-extension://{CALLER_CHROMIUM_ID}/"],
            )
            removed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--uninstall",
                    "--manifest-dir",
                    str(root / "chrome"),
                    "chrome",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse((root / "chrome" / "org.winsvpn.bridge.json").exists())

    def test_chrome_missing_id_is_refused_and_copies_nothing(self) -> None:
        installer = HERE / "install_native_host.sh"
        with isolated_store_env():
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                dummy = write_dummy_host(root / "wins_bridge_host")
                env = _store_ids_python_env(root, {"edge": FIXTURE_EDGE_ID})
                completed = subprocess.run(
                    [
                        "bash",
                        str(installer),
                        "--host-path",
                        str(dummy),
                        "--dest-dir",
                        str(root / "lib"),
                        "--manifest-dir",
                        str(root / "chrome"),
                        "chrome",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertEqual(completed.returncode, 78, completed.stderr)
                self.assertIn("chrome store-listing id is missing", completed.stderr)
                self.assertIn("manifests/store_ids.json", completed.stderr)
                self.assertEqual(list((root / "chrome").glob("*")), [])
                self.assertEqual(list((root / "lib").glob("*")), [])
        # EXT2: an installed package that ships neither identity record.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            package_installer = (
                _identityless_package(root / "package") / "install_native_host.sh"
            )
            dummy = write_dummy_host(root / "wins_bridge_host")
            completed = subprocess.run(
                [
                    "bash",
                    str(package_installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(root / "lib"),
                    "--manifest-dir",
                    str(root / "chrome"),
                    "chrome",
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PYTHON_BIN": sys.executable,
                    "WINSVPN_CHROME_STORE_ID": "",
                    "WINSVPN_EDGE_STORE_ID": "",
                },
            )
            self.assertEqual(completed.returncode, 78, completed.stderr)
            self.assertIn("chrome store-listing id is missing", completed.stderr)
            self.assertEqual(list((root / "chrome").glob("*")), [])
            self.assertEqual(list((root / "lib").glob("*")), [])

    def test_preplanted_new_symlink_is_refused_and_does_not_write_the_victim(self) -> None:
        installer = HERE / "install_native_host.sh"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            dummy = write_dummy_host(root / "wins_bridge_host")
            dest = root / "lib"
            dest.mkdir()
            victim = root / "victim-host"
            victim.write_text("KEEP-VICTIM\n", encoding="ascii")
            planted = dest / "wins_bridge_host.new"
            planted.symlink_to(victim)
            completed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(dest),
                    "--manifest-dir",
                    str(root / "firefox"),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("preplanted staging symlink", completed.stderr)
            self.assertEqual(victim.read_text(encoding="ascii"), "KEEP-VICTIM\n")
            self.assertTrue(planted.is_symlink())
            self.assertFalse((dest / "wins_bridge_host").exists())
            self.assertFalse((root / "firefox" / "org.winsvpn.bridge.json").exists())

    def test_symlink_manifest_dir_is_refused_and_does_not_write_the_victim(self) -> None:
        installer = HERE / "install_native_host.sh"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            dummy = write_dummy_host(root / "wins_bridge_host")
            dest = root / "lib"
            dest.mkdir()
            victim = root / "victim-manifests"
            victim.mkdir()
            planted = victim / "keep.json"
            planted.write_text("KEEP-MANIFEST\n", encoding="ascii")
            linked = root / "firefox"
            linked.symlink_to(victim)
            completed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(dest),
                    "--manifest-dir",
                    str(linked),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertTrue(
                "symlink" in completed.stderr or "manifest directory" in completed.stderr,
                completed.stderr,
            )
            self.assertEqual(planted.read_text(encoding="ascii"), "KEEP-MANIFEST\n")
            self.assertFalse((victim / "org.winsvpn.bridge.json").exists())
            self.assertTrue(linked.is_symlink())
            self.assertFalse((dest / "wins_bridge_host").exists())

    def test_intermediate_dest_and_manifest_symlinks_are_refused(self) -> None:
        installer = HERE / "install_native_host.sh"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            dummy = write_dummy_host(root / "wins_bridge_host")
            victim_lib = root / "victim-lib"
            victim_lib.mkdir()
            decoy = root / "decoy"
            decoy.mkdir()
            (decoy / "lib").symlink_to(victim_lib)
            nested_dest = decoy / "lib" / "nested"
            completed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(nested_dest),
                    "--manifest-dir",
                    str(root / "firefox"),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("symlink", completed.stderr)
            self.assertEqual(list(victim_lib.iterdir()), [])
            self.assertFalse((root / "firefox" / "org.winsvpn.bridge.json").exists())

            victim_mf = root / "victim-mf"
            victim_mf.mkdir()
            (decoy / "mozilla").symlink_to(victim_mf)
            real_lib = root / "real-lib"
            real_lib.mkdir()
            completed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(real_lib),
                    "--manifest-dir",
                    str(decoy / "mozilla" / "hosts"),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("symlink", completed.stderr)
            self.assertFalse((victim_mf / "hosts").exists())
            self.assertFalse((real_lib / "wins_bridge_host").exists())

    def test_dest_symlink_and_fifo_are_refused_without_hang_or_write_through(self) -> None:
        installer = HERE / "install_native_host.sh"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            dummy = write_dummy_host(root / "wins_bridge_host")
            dest = root / "lib"
            dest.mkdir()
            victim = root / "victim-host"
            victim.write_text("KEEP-VICTIM-UNTOUCHED\n", encoding="ascii")
            planted = dest / "wins_bridge_host"
            planted.symlink_to(victim)
            completed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(dest),
                    "--manifest-dir",
                    str(root / "firefox"),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("symlink", completed.stderr)
            self.assertEqual(victim.read_text(encoding="ascii"), "KEEP-VICTIM-UNTOUCHED\n")
            self.assertTrue(planted.is_symlink())
            self.assertFalse((root / "firefox" / "org.winsvpn.bridge.json").exists())

            fifo_dest = root / "fifo-lib"
            fifo_dest.mkdir()
            os.mkfifo(fifo_dest / "wins_bridge_host")
            fifo_run = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(fifo_dest),
                    "--manifest-dir",
                    str(root / "fifo-firefox"),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            self.assertNotEqual(fifo_run.returncode, 0, fifo_run.stdout)
            self.assertTrue(
                "special" in fifo_run.stderr or "non-regular" in fifo_run.stderr,
                fifo_run.stderr,
            )
            self.assertTrue(stat.S_ISFIFO((fifo_dest / "wins_bridge_host").lstat().st_mode))
            self.assertFalse((root / "fifo-firefox" / "org.winsvpn.bridge.json").exists())

            sock_dest = root / "sock-lib"
            sock_dest.mkdir()
            sock_path = sock_dest / "wins_bridge_host"
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(str(sock_path))
            finally:
                sock.close()
            sock_run = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(sock_dest),
                    "--manifest-dir",
                    str(root / "sock-firefox"),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            self.assertNotEqual(sock_run.returncode, 0, sock_run.stdout)
            self.assertTrue(
                "special" in sock_run.stderr or "non-regular" in sock_run.stderr,
                sock_run.stderr,
            )
            self.assertTrue(stat.S_ISSOCK(sock_path.lstat().st_mode))
            self.assertFalse((root / "sock-firefox" / "org.winsvpn.bridge.json").exists())

            prev_fifo_dir = root / "prev-fifo"
            prev_fifo_dir.mkdir()
            host_file = prev_fifo_dir / "wins_bridge_host"
            host_file.write_text("OLD-HOST-BODY\n", encoding="ascii")
            host_file.chmod(0o755)
            os.mkfifo(prev_fifo_dir / f"{host_file.name}.winsvpn-prev.{os.getpid()}")
            prev_run = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(prev_fifo_dir),
                    "--manifest-dir",
                    str(root / "prev-firefox"),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            self.assertEqual(prev_run.returncode, 0, prev_run.stderr)
            self.assertTrue((prev_fifo_dir / "wins_bridge_host").is_file())
            self.assertNotEqual(
                (prev_fifo_dir / "wins_bridge_host").read_text(encoding="ascii"),
                "OLD-HOST-BODY\n",
            )

    def test_uninstall_refuses_intermediate_symlink_parents(self) -> None:
        installer = HERE / "install_native_host.sh"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            dummy = write_dummy_host(root / "wins_bridge_host")
            real_lib = root / "real-lib"
            real_mf = root / "real-mf"
            real_lib.mkdir()
            real_mf.mkdir()
            installed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(dummy),
                    "--dest-dir",
                    str(real_lib),
                    "--manifest-dir",
                    str(real_mf),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            decoy = root / "decoy"
            decoy.mkdir()
            (decoy / "mozilla").symlink_to(real_mf)
            (decoy / "lib").symlink_to(real_lib)
            removed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--uninstall",
                    "--remove-host",
                    "--dest-dir",
                    str(decoy / "lib"),
                    "--manifest-dir",
                    str(decoy / "mozilla"),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(removed.returncode, 0, removed.stdout)
            self.assertIn("symlink", removed.stderr)
            self.assertTrue((real_mf / "org.winsvpn.bridge.json").is_file())
            self.assertTrue((real_lib / "wins_bridge_host").is_file())

            victim = root / "victim-manifest.json"
            victim.write_text("KEEP-UNINSTALL-VICTIM\n", encoding="ascii")
            planted = real_mf / "org.winsvpn.bridge.json"
            planted.unlink()
            planted.symlink_to(victim)
            removed_leaf = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--uninstall",
                    "--manifest-dir",
                    str(real_mf),
                    "firefox",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(removed_leaf.returncode, 0, removed_leaf.stdout)
            self.assertIn("symlink", removed_leaf.stderr)
            self.assertEqual(victim.read_text(encoding="ascii"), "KEEP-UNINSTALL-VICTIM\n")
            self.assertTrue(planted.is_symlink())
            self.assertTrue((real_lib / "wins_bridge_host").is_file())


class PackagingWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = (
            REPO / "installer" / "windows" / "build_installer.ps1"
        ).read_text(encoding="utf-8")
        cls.inno = (REPO / "installer" / "windows" / "winsvpn.iss").read_text(
            encoding="utf-8"
        )
        cls.register = (HERE / "register_native_host.ps1").read_text(encoding="utf-8")
        cls.host = (HERE / "host" / "bin" / "wins_bridge_host.dart").read_text(
            encoding="utf-8"
        )
        cls.harness = (
            HERE / "host" / "bin" / "wins_bridge_host_harness.dart"
        ).read_text(encoding="utf-8")
        cls.build_ps1 = (HERE / "build_native_host.ps1").read_text(encoding="utf-8")
        cls.build_sh = (HERE / "build_native_host.sh").read_text(encoding="utf-8")

    def test_unix_entrypoints_are_executable(self) -> None:
        for script_name in ("build_native_host.sh", "install_native_host.sh"):
            script = HERE / script_name
            self.assertTrue(
                os.access(script, os.X_OK),
                f"{script_name} has a shebang and is invoked directly, but is not executable",
            )

    def test_store_ids_come_from_the_committed_record(self) -> None:
        checker = (HERE / "check_host_manifests.py").read_text(encoding="utf-8")
        self.assertIn("WINSVPN_CHROME_STORE_ID", checker)
        self.assertIn("WINSVPN_EDGE_STORE_ID", checker)
        self.assertIn("manifests/store_ids.json", checker)
        # Owner ruling (EXT2): the checker binds the recorded store identity and
        # never an owner receipt with an age.
        self.assertIn("store_identity.json", checker)
        self.assertNotIn("WINSVPN_BROWSER_EXTENSION_IDENTITY_RECEIPT", checker)
        self.assertNotIn("bind_owner_identity", checker)
        self.assertNotIn(CALLER_CHROMIUM_ID, checker)
        self.assertEqual(
            json.loads((HERE / "manifests" / "store_ids.json").read_text(encoding="ascii")),
            {"chrome": RECORDED_CHROME_ID, "edge": RECORDED_EDGE_ID},
        )
        chrome_template = (
            HERE / "manifests" / "org.winsvpn.bridge.chrome.json"
        ).read_text(encoding="utf-8")
        self.assertIn("chrome-extension://lnehjdblendkagjbmdclepjalahdhbbn/", chrome_template)
        self.assertIn("PLACEHOLDER_ABSOLUTE_PATH_TO_HOST", chrome_template)

    def test_windows_producer_renders_instead_of_copying_templates(self) -> None:
        self.assertIn("render_host_manifest.py", self.builder)
        self.assertIn("native_host_layout.py", self.builder)
        self.assertIn("recorded-id --browser firefox", self.builder)
        self.assertIn("$NativeHostManifestRenderer --browser $browser", self.builder)
        self.assertIn("LASTEXITCODE -eq 78", self.builder)
        self.assertIn("companion@winsvpn.org", self.builder)
        self.assertNotIn("No placeholder manifest or registry key will be produced", self.builder)
        self.assertIn("Refusing to stage native-host manifest", self.builder)
        native_fn = self.builder.split("function Build-BrowserNativeHost", 1)[1]
        native_fn = native_fn.split("\nfunction ", 1)[0]
        self.assertNotIn("Copy-Item", native_fn)
        self.assertNotIn("tools\\native_messaging\\manifests", native_fn)
        self.assertIn("EnableChromeNativeHost=1", self.builder)
        self.assertIn("org.winsvpn.bridge.chrome.json", self.builder)
        self.assertIn("bin/wins_bridge_host.dart", self.build_ps1)
        self.assertIn("bin/wins_bridge_host.dart", self.build_sh)
        self.assertIn("pub get --offline --enforce-lockfile", self.build_ps1)
        self.assertIn("pub get --offline --enforce-lockfile", self.build_sh)
        self.assertNotIn("chmod 0755 --", self.build_sh)
        self.assertRegex(self.build_sh, r"chmod 0755 \"\$\{TEMPORARY\}\"")
        self.assertNotIn("wins_bridge_host_harness", self.build_ps1)
        self.assertNotIn("wins_bridge_host_harness", self.build_sh)
        self.assertNotIn("wins_bridge_host_harness", native_fn)

    def test_windows_native_host_selftest_runs_a_path_powershell_treats_as_a_program(self) -> None:
        # PowerShell runs `& $path` only for a program extension; any other suffix
        # (the old "<output>.new.<pid>") fails with "Cannot run a document in the
        # middle of a pipeline" and stopped every Windows release build.
        self.assertIn('$temporary = "$Output.new.$PID.exe"', self.build_ps1)
        self.assertNotIn('$temporary = "$Output.new.$PID"\n', self.build_ps1)
        self.assertIn("& $temporary --selftest", self.build_ps1)
        self.assertIn("-o $temporary", self.build_ps1)
        self.assertIn("Move-Item -LiteralPath $temporary -Destination $Output -Force", self.build_ps1)

    def test_local_windows_registration_is_hkcu_and_fail_closed(self) -> None:
        self.assertIn("-windows-hive', 'HKCU'", self.register.replace('"', "'"))
        self.assertIn("WINSVPN_$($Browser.ToUpperInvariant())_STORE_ID", self.register)
        self.assertIn("No store id will be invented", self.register)
        self.assertIn("Remove-Item -LiteralPath \"HKCU:\\$subkey\"", self.register)
        self.assertIn("uninstall-manifest", self.register)
        self.assertNotIn(CALLER_CHROMIUM_ID, self.register)

    def test_shipping_host_uses_app_ipc_and_refuses_state_file(self) -> None:
        self.assertIn("AppIpcStateSource(winn: winn)", self.host)
        self.assertIn("class AppIpcStateSource", self.host)
        self.assertIn("invokeFailClosed", self.host)
        self.assertIn("requestConnect()", self.host)
        self.assertIn("requestDisconnect()", self.host)
        self.assertIn("production host has no state-file override", self.host)
        self.assertNotIn("stateSource: UnobservedStateSource(winn)", self.host)
        self.assertNotIn("FileStateSource", self.host)
        self.assertIn("class FileStateSource", self.harness)
        self.assertIn("--state-file", self.harness)
        self.assertIn("AppIpcStateSource(winn: winn)", self.harness)
        firefox = (REPO / "extension" / "manifest" / "firefox.jsonc").read_text(
            encoding="utf-8"
        )
        self.assertIn("companion@winsvpn.org", firefox)


class MacOSNativeHostHelperContractTests(unittest.TestCase):
    def test_macos_helper_delivers_edge_beside_chrome_without_inventing_ids(self) -> None:
        helper = (HERE / "install_macos_native_host.sh").read_text(encoding="utf-8")
        self.assertIn("--edge-manifest-dir", helper)
        self.assertIn("owner_issued_chromium_ids", helper)
        self.assertEqual(helper.count("owner_issued_chromium_ids"), 1)
        self.assertNotIn("recorded-id --browser chrome", helper)
        self.assertNotIn("recorded-id --browser edge", helper)
        self.assertIn("owner-blocked", helper)
        self.assertIn("missing_store_id_message", helper)
        self.assertIn('"chrome-missing "*)', helper)
        self.assertIn('"edge-missing "*)', helper)
        self.assertIn("must be distinct", helper)
        self.assertIn("owner identity snapshot failed", helper)
        self.assertNotIn("PLACEHOLDER", helper)
        self.assertIsNone(re.search(r"[a-p]{32}", helper))
        self.assertIn("verify_chromium_manifest edge", helper)
        self.assertIn("uninstall-manifest", helper)
        self.assertIn("edge.json", helper)
        self.assertIn("owner_edge_id", helper)
        self.assertIn("ast.parse", helper)
        self.assertIn("canonical_home", helper)
        self.assertIn(".mutated", helper)
        self.assertIn(".backup-state", helper)
        self.assertIn("rollback copy failed", helper)
        rollback_start = helper.index("rollback_install()")
        set_plus = helper.index("set +e", rollback_start)
        restore = helper.index("restore_rollback", rollback_start)
        self.assertLess(set_plus, restore)
        self.assertTrue(os.access(HERE / "install_macos_native_host.sh", os.X_OK))

    def test_macos_helper_snapshot_blocks_only_the_missing_browser(self) -> None:
        helper = (HERE / "install_macos_native_host.sh").read_text(encoding="utf-8")
        opener = 'read_owner_chromium_snapshot() {\n  "${PYTHON_BIN}" - "${LAYOUT}" <<\'PY\'\n'
        self.assertIn(opener, helper)
        snippet = helper.split(opener, 1)[1].split("\nPY\n}", 1)[0] + "\n"

        def snapshot(root: Path, ids: dict[str, str] | None, **extra: str):
            return subprocess.run(
                [sys.executable, "-", str(HERE / "native_host_layout.py")],
                input=snippet,
                check=False,
                capture_output=True,
                text=True,
                env=_store_ids_python_env(root, ids, extra or None),
            )

        with tempfile.TemporaryDirectory() as raw:
            partial = snapshot(Path(raw), {"chrome": CALLER_CHROMIUM_ID})
            self.assertEqual(partial.returncode, 0, partial.stderr)
            lines = partial.stdout.splitlines()
            self.assertEqual(lines[0], f"chrome {CALLER_CHROMIUM_ID}")
            self.assertTrue(lines[1].startswith("edge-missing edge store-listing id is missing"))
            self.assertEqual(len(lines), 2)
        with tempfile.TemporaryDirectory() as raw:
            complete = snapshot(
                Path(raw), {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID}
            )
            self.assertEqual(complete.returncode, 0, complete.stderr)
            self.assertEqual(
                complete.stdout.splitlines(),
                [f"chrome {CALLER_CHROMIUM_ID}", f"edge {FIXTURE_EDGE_ID}"],
            )
        with tempfile.TemporaryDirectory() as raw:
            absent = snapshot(Path(raw), None)
            self.assertEqual(absent.returncode, 0, absent.stderr)
            self.assertEqual(
                [line.split(" ", 1)[0] for line in absent.stdout.splitlines()],
                ["chrome-missing", "edge-missing"],
            )
        with tempfile.TemporaryDirectory() as raw:
            contradicted = snapshot(
                Path(raw),
                {"chrome": CALLER_CHROMIUM_ID},
                WINSVPN_CHROME_STORE_ID="a" * 32,
            )
            self.assertEqual(contradicted.returncode, 1, contradicted.stdout)
            self.assertEqual(contradicted.stdout, "")

    def test_macos_helper_owner_blocks_edge_without_touching_live_registration(
        self,
    ) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        installer = HERE / "install_macos_native_host.sh"
        with isolated_store_env():
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                host = _compile_handshake_host(root / "wins_bridge_host")
                edge_dir = root / "edge"
                edge_dir.mkdir()
                live_edge = edge_dir / "org.winsvpn.bridge.json"
                live_edge.write_text("live-edge\n", encoding="ascii")
                chrome_dir = root / "chrome"
                chrome_dir.mkdir()
                live_chrome = chrome_dir / "org.winsvpn.bridge.json"
                live_chrome.write_text("live-chrome\n", encoding="ascii")
                chrome_stat = live_chrome.stat()
                edge_stat = live_edge.stat()
                completed = subprocess.run(
                    [
                        "bash",
                        str(installer),
                        "--host-path",
                        str(host),
                        "--dest-dir",
                        str(root / "lib"),
                        "--firefox-manifest-dir",
                        str(root / "firefox"),
                        "--chrome-manifest-dir",
                        str(chrome_dir),
                        "--edge-manifest-dir",
                        str(edge_dir),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    cwd=str(REPO),
                    env=_blocked_helper_env(root),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
                self.assertIn("edge: owner-blocked", completed.stdout)
                self.assertIn("chrome: owner-blocked", completed.stdout)
                self.assertEqual(live_edge.read_text(encoding="ascii"), "live-edge\n")
                self.assertEqual(live_chrome.read_text(encoding="ascii"), "live-chrome\n")
                self.assertEqual(live_chrome.stat().st_ino, chrome_stat.st_ino)
                self.assertEqual(live_edge.stat().st_ino, edge_stat.st_ino)
                self.assertTrue((root / "lib" / "wins_bridge_host").is_file())
                self.assertTrue((root / "firefox" / "org.winsvpn.bridge.json").is_file())
                self.assertFalse(live_chrome.is_symlink())
                self.assertFalse(live_edge.is_symlink())

    def test_macos_helper_hostile_backup_failure_preserves_untouched_live_manifests(
        self,
    ) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        installer = HERE / "install_macos_native_host.sh"
        with isolated_store_env():
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                host = _compile_handshake_host(root / "wins_bridge_host")
                edge_dir = root / "edge"
                edge_dir.mkdir()
                live_edge = edge_dir / "org.winsvpn.bridge.json"
                live_edge.write_text("live-edge\n", encoding="ascii")
                chrome_dir = root / "chrome"
                chrome_dir.mkdir()
                live_chrome = chrome_dir / "org.winsvpn.bridge.json"
                live_chrome.write_text("live-chrome\n", encoding="ascii")
                live_chrome.chmod(0o000)
                env = _blocked_helper_env(root)
                try:
                    completed = subprocess.run(
                        [
                            "bash",
                            str(installer),
                            "--host-path",
                            str(host),
                            "--dest-dir",
                            str(root / "lib"),
                            "--firefox-manifest-dir",
                            str(root / "firefox"),
                            "--chrome-manifest-dir",
                            str(chrome_dir),
                            "--edge-manifest-dir",
                            str(edge_dir),
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        cwd=str(REPO),
                        env=env,
                    )
                finally:
                    live_chrome.chmod(0o644)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("rollback copy failed", completed.stderr)
                self.assertTrue(live_chrome.exists())
                self.assertEqual(live_chrome.read_text(encoding="ascii"), "live-chrome\n")
                self.assertEqual(live_edge.read_text(encoding="ascii"), "live-edge\n")

    def test_macos_helper_layout_exit_1_aborts_without_uninstalling_live_edge(
        self,
    ) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        installer = HERE / "install_macos_native_host.sh"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            host = _compile_handshake_host(root / "wins_bridge_host")
            edge_dir = root / "edge"
            edge_dir.mkdir()
            live_edge = edge_dir / "org.winsvpn.bridge.json"
            live_edge.write_text("live-edge\n", encoding="ascii")
            interpreter = _dummy_host_interpreter()
            env = _store_ids_python_env(
                root,
                {"chrome": CALLER_CHROMIUM_ID, "edge": FIXTURE_EDGE_ID},
                {
                    **_framework_relocation_env(interpreter),
                    "PYTHON_BIN": str(interpreter),
                    "WINSVPN_CHROME_STORE_ID": "a" * 32,
                },
            )
            completed = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    str(root / "lib"),
                    "--firefox-manifest-dir",
                    str(root / "firefox"),
                    "--chrome-manifest-dir",
                    str(root / "chrome"),
                    "--edge-manifest-dir",
                    str(edge_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                cwd=str(REPO),
                env=env,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertNotEqual(completed.returncode, 78, completed.stderr)
            self.assertIn("snapshot failed", completed.stderr)
            self.assertEqual(live_edge.read_text(encoding="ascii"), "live-edge\n")
            self.assertFalse((root / "lib" / "wins_bridge_host").exists())

    def test_macos_helper_first_rollback_failure_still_restores_later_files(
        self,
    ) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        installer = HERE / "install_macos_native_host.sh"
        with isolated_store_env():
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                host = _compile_handshake_host(root / "wins_bridge_host")
                dest = root / "lib"
                firefox_dir = root / "firefox"
                chrome_dir = root / "chrome"
                edge_dir = root / "edge"
                dest.mkdir()
                firefox_dir.mkdir()
                chrome_dir.mkdir()
                edge_dir.mkdir()
                live_host = dest / "wins_bridge_host"
                live_firefox = firefox_dir / "org.winsvpn.bridge.json"
                live_chrome = chrome_dir / "org.winsvpn.bridge.json"
                live_edge = edge_dir / "org.winsvpn.bridge.json"
                live_host.write_text("old-host\n", encoding="ascii")
                live_host.chmod(0o755)
                live_firefox.write_text("old-firefox\n", encoding="ascii")
                live_chrome.write_text("old-chrome\n", encoding="ascii")
                live_edge.write_text("old-edge\n", encoding="ascii")
                wrapper = root / "python-wrapper"
                wrapper.write_text(
                    "\n".join(
                        [
                            "#!/bin/bash",
                            "set -euo pipefail",
                            'if [[ " $* " == *" verify-manifests "* ]]; then',
                            '  dest="${WINSVPN_HELPER_DEST}"',
                            '  if [ -f "${dest}/wins_bridge_host" ]; then',
                            '    /usr/bin/chflags uchg "${dest}/wins_bridge_host"',
                            "  fi",
                            '  for backup in "${dest}"/.winsvpn-native-host-rollback.*/host.bin; do',
                            '    if [ -f "${backup}" ]; then',
                            '      /usr/bin/chflags uchg "${backup}"',
                            "    fi",
                            "  done",
                            "  exit 1",
                            "fi",
                            'exec "${WINSVPN_REAL_PYTHON}" "$@"',
                            "",
                        ]
                    ),
                    encoding="ascii",
                )
                wrapper.chmod(0o755)
                env = _blocked_helper_env(
                    root,
                    {
                        "PYTHON_BIN": str(wrapper),
                        "WINSVPN_REAL_PYTHON": sys.executable,
                        "WINSVPN_HELPER_DEST": str(dest),
                    },
                )
                try:
                    completed = subprocess.run(
                        [
                            "bash",
                            str(installer),
                            "--host-path",
                            str(host),
                            "--dest-dir",
                            str(dest),
                            "--firefox-manifest-dir",
                            str(firefox_dir),
                            "--chrome-manifest-dir",
                            str(chrome_dir),
                            "--edge-manifest-dir",
                            str(edge_dir),
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        cwd=str(REPO),
                        env=env,
                    )
                finally:
                    subprocess.run(
                        ["/usr/bin/chflags", "nouchg", str(live_host)],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    for backup in dest.glob(".winsvpn-native-host-rollback.*/host.bin"):
                        subprocess.run(
                            ["/usr/bin/chflags", "nouchg", str(backup)],
                            check=False,
                            capture_output=True,
                            text=True,
                        )
                self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("rollback could not restore", completed.stderr)
                self.assertNotEqual(live_host.read_bytes(), b"old-host\n")
                self.assertEqual(live_firefox.read_text(encoding="ascii"), "old-firefox\n")
                self.assertEqual(live_chrome.read_text(encoding="ascii"), "old-chrome\n")
                self.assertEqual(live_edge.read_text(encoding="ascii"), "old-edge\n")

    def test_macos_helper_refuses_symlink_fifo_socket_hardlink_and_path_swap(
        self,
    ) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        installer = HERE / "install_macos_native_host.sh"
        with isolated_store_env():
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                host = _compile_handshake_host(root / "wins_bridge_host")

                def run_helper(dest: Path, firefox: Path, chrome: Path, edge: Path) -> subprocess.CompletedProcess[str]:
                    return subprocess.run(
                        [
                            "bash",
                            str(installer),
                            "--host-path",
                            str(host),
                            "--dest-dir",
                            str(dest),
                            "--firefox-manifest-dir",
                            str(firefox),
                            "--chrome-manifest-dir",
                            str(chrome),
                            "--edge-manifest-dir",
                            str(edge),
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        cwd=str(REPO),
                        env=_blocked_helper_env(root),
                        timeout=8,
                    )

                victim = root / "victim-host"
                victim.write_text("KEEP-VICTIM\n", encoding="ascii")
                link_dest = root / "link-lib"
                link_dest.mkdir()
                planted = link_dest / "wins_bridge_host"
                planted.symlink_to(victim)
                linked = run_helper(
                    link_dest, root / "link-firefox", root / "link-chrome", root / "link-edge"
                )
                self.assertNotEqual(linked.returncode, 0, linked.stdout)
                self.assertIn("symlink", linked.stderr)
                self.assertEqual(victim.read_text(encoding="ascii"), "KEEP-VICTIM\n")
                self.assertTrue(planted.is_symlink())
                self.assertFalse((root / "link-firefox" / "org.winsvpn.bridge.json").exists())

                fifo_dest = root / "fifo-lib"
                fifo_dest.mkdir()
                os.mkfifo(fifo_dest / "wins_bridge_host")
                fifo_run = run_helper(
                    fifo_dest, root / "fifo-firefox", root / "fifo-chrome", root / "fifo-edge"
                )
                self.assertNotEqual(fifo_run.returncode, 0, fifo_run.stdout)
                self.assertIn("special", fifo_run.stderr)
                self.assertTrue(stat.S_ISFIFO((fifo_dest / "wins_bridge_host").lstat().st_mode))
                self.assertFalse((root / "fifo-firefox" / "org.winsvpn.bridge.json").exists())

                sock_dest = root / "sock-lib"
                sock_dest.mkdir()
                sock_path = sock_dest / "wins_bridge_host"
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.bind(str(sock_path))
                finally:
                    sock.close()
                sock_run = run_helper(
                    sock_dest, root / "sock-firefox", root / "sock-chrome", root / "sock-edge"
                )
                self.assertNotEqual(sock_run.returncode, 0, sock_run.stdout)
                self.assertIn("special", sock_run.stderr)
                self.assertTrue(stat.S_ISSOCK(sock_path.lstat().st_mode))
                self.assertFalse((root / "sock-firefox" / "org.winsvpn.bridge.json").exists())

                hard_dest = root / "hard-lib"
                hard_dest.mkdir()
                live = hard_dest / "wins_bridge_host"
                live.write_text("KEEP-HARDLINK\n", encoding="ascii")
                live.chmod(0o755)
                alias = hard_dest / "alias-host"
                os.link(live, alias)
                hard_run = run_helper(
                    hard_dest, root / "hard-firefox", root / "hard-chrome", root / "hard-edge"
                )
                self.assertNotEqual(hard_run.returncode, 0, hard_run.stdout)
                self.assertIn("hardlinked", hard_run.stderr)
                self.assertEqual(live.read_text(encoding="ascii"), "KEEP-HARDLINK\n")
                self.assertEqual(alias.read_text(encoding="ascii"), "KEEP-HARDLINK\n")
                self.assertFalse((root / "hard-firefox" / "org.winsvpn.bridge.json").exists())

                swap_dest = root / "swap-lib"
                swap_dest.mkdir()
                live_swap = swap_dest / "wins_bridge_host"
                live_swap.write_text("old-swap-host\n", encoding="ascii")
                live_swap.chmod(0o755)
                live_swap.unlink()
                live_swap.symlink_to(victim)
                swapped = run_helper(
                    swap_dest, root / "swap-firefox", root / "swap-chrome", root / "swap-edge"
                )
                self.assertNotEqual(swapped.returncode, 0, swapped.stdout)
                self.assertIn("symlink", swapped.stderr)
                self.assertEqual(victim.read_text(encoding="ascii"), "KEEP-VICTIM\n")
                self.assertTrue(live_swap.is_symlink())
                self.assertFalse((root / "swap-firefox" / "org.winsvpn.bridge.json").exists())


if __name__ == "__main__":
    unittest.main()
