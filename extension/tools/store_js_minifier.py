#!/usr/bin/env python3
"""Fail-closed store JavaScript size transform for extension packages.

Chrome Web Store policy forbids obfuscation and concealment of functionality.
Store-permitted minification is a size transform: comment and whitespace
removal. Identifier mangling, control-flow hiding, packed eval, and source
maps are refused. This module does not claim to protect client-held secrets.

The transform is an official current-stable esbuild binary (0.28.2), discovered
from registry.npmjs.org on 2026-08-24 and then frozen here by exact package
name, tarball URL, archive SHA-256, npm SHA-512 integrity, member set, binary
path, binary SHA-256, and --version string. Build time never floats a version
and never installs a global package. The binary is cache-extracted into
temporary custody and is never written into the git tree or the store zip.

esbuild is MIT-licensed. It is a build-time tool only and is not redistributed
inside Chrome, Edge, or Firefox packages. Authored extension/src remains the
human-readable source. Packaged src/*.js is the store-permitted size transform
of that source.

Producer leak/copy/native-messaging checks run against packaged bytes, so this
transform preserves the exact surface those checks require:
  export const NATIVE_HOST_NAME = 'org.winsvpn.bridge'
  export const STATE = { ... \\n};
  export const STATE_COPY = { ... \\n};
  api.runtime.connectNative(
  this.adapter.connectNative(NATIVE_HOST_NAME
  extends BaseAdapter
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath
from typing import NoReturn

TOOL_NAME = "esbuild"
TOOL_VERSION = "0.28.2"
TOOL_LICENSE = "MIT"
OFFICIAL_REGISTRY_HOST = "registry.npmjs.org"
CACHE_ENV = "WINS_EXTENSION_ESBUILD_CACHE"
FETCH_ENV = "WINS_EXTENSION_ESBUILD_FETCH"
DEFAULT_CACHE_NAME = "winsvpn-extension-esbuild-custody"
JS_SUFFIXES = (".js", ".mjs", ".cjs")
NATIVE_HOST_VALUE = "org.winsvpn.bridge"
NATIVE_HOST_REQUIRED = "export const NATIVE_HOST_NAME = 'org.winsvpn.bridge'"
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_JS_BYTES = 2 * 1024 * 1024
MAX_EXTRACT_MEMBERS = 8
ESBUILD_TIMEOUT_SEC = 30
HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
FORMAT_CHAR_RE = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]"
)
SOURCE_MAP_RE = re.compile(
    r"(?i)source\s*mapping\s*url\s*[=:]|source\s*url\s*[=:]"
)
EXTENSION_ROOT = Path(__file__).resolve().parent.parent
EXTENSION_SRC = EXTENSION_ROOT / "src"
EXPECTED_ICON_MEMBERS = (
    "src/assets/icon16.png",
    "src/assets/icon32.png",
    "src/assets/icon48.png",
    "src/assets/icon128.png",
)
FORBIDDEN_ZIP_PATH_PARTS = frozenset({"meta-inf", "_metadata"})
ALLOWED_PACKAGE_SUFFIXES = frozenset(
    {".js", ".mjs", ".cjs", ".html", ".css", ".png", ".json"}
)
ZIP_UNICODE_PATH_EXTRA = 0x7075
ZIP_UTF8_FLAG = 0x800
ZIP_ENCRYPTED_FLAG = 0x1
ZIP_STRONG_ENCRYPTION_FLAG = 0x40
UNIX_SYMLINK_TYPE = 0o120000
MAX_ZIP_ARCHIVE_BYTES = 32 * 1024 * 1024
_PRODUCER_PACKAGED_JS: dict[str, str] | None = None
OBFUSCATOR_RE = re.compile(
    r"(?i)(?:javascript-obfuscator|controlFlowFlattening|control-flow-flatten|"
    r"_0x[a-f0-9]{4,}|eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e)"
)
IMPORT_FROM_RE = re.compile(r"""from\s*['"]([^'"]+)['"]""")
EXPORT_NAME_RE = re.compile(
    r"export\s+(?:async\s+)?(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)"
)
EXPORT_BRACE_RE = re.compile(r"export\s*\{([^}]*)\}")
CURL_CANDIDATES = ("/usr/bin/curl", "/bin/curl")
ESBUILD_TRANSFORM_FLAGS = (
    "--minify-whitespace",
    "--legal-comments=none",
    "--charset=utf8",
    "--log-level=error",
)
FORBIDDEN_ESBUILD_MINIFY_FLAGS = (
    "--minify",
    "--minify-identifiers",
    "--minify-syntax",
)

# Frozen on 2026-08-24 from registry.npmjs.org/@esbuild/<platform>/0.28.2.
# SHA-256 is the local pin. npm integrity is the official SHA-512 SRI.
PLATFORM_PINS: dict[str, dict[str, object]] = {
    "darwin-arm64": {
        "package": "@esbuild/darwin-arm64",
        "archive_url": "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.28.2.tgz",
        "archive_name": "darwin-arm64-0.28.2.tgz",
        "archive_sha256": "1980cde09749094452b20d36ff267585ccb3f72749c7bc97291cd9996ccf5a2a",
        "archive_bytes": 4434422,
        "archive_sha1": "f83afeeac1d7dac01c7a2fd012b3e451a0591fcc",
        "archive_sri": "sha512-n4KqkOQrraxHJcgjM1RvwbigfQKIKJVpM7xp+KsxiyUSrRdIXnt73VhrPAx0fV44hgfmIVKjxMN9J1t5jySVkw==",
        "binary_rel": "package/bin/esbuild",
        "binary_sha256": "10b6243df618d374bb2d5c9cfbe7052e1405f6aa4e53a6164f11a91b9f2e1384",
        "members": ("package/README.md", "package/bin/esbuild", "package/package.json"),
    },
    "darwin-x64": {
        "package": "@esbuild/darwin-x64",
        "archive_url": "https://registry.npmjs.org/@esbuild/darwin-x64/-/darwin-x64-0.28.2.tgz",
        "archive_name": "darwin-x64-0.28.2.tgz",
        "archive_sha256": "abb6a7a895aaf2cc0df36fecc3bf0042479ffec51a643a056d54e9109f27db55",
        "archive_bytes": 4802970,
        "archive_sha1": "510147c055a795588dbbe14fd6b1b8ad0a2f30de",
        "archive_sri": "sha512-uq6suIWYP37qzGddBKPw5QEQPi6HiLGsO7UmkpfyaYNQ3D+rN6w6WfwH+nuqcGXWvawGwxOEroO4YGnFh95azw==",
        "binary_rel": "package/bin/esbuild",
        "binary_sha256": "7fe5c9c905fff0a05d92db98929434ab4d3b6dd92d7a7688922db74380c75df3",
        "members": ("package/README.md", "package/bin/esbuild", "package/package.json"),
    },
    "linux-arm64": {
        "package": "@esbuild/linux-arm64",
        "archive_url": "https://registry.npmjs.org/@esbuild/linux-arm64/-/linux-arm64-0.28.2.tgz",
        "archive_name": "linux-arm64-0.28.2.tgz",
        "archive_sha256": "a96dbfa41d3ef5dbd1ef22b1c10d5187be9267e86093a870f06402a7ec931596",
        "archive_bytes": 4283627,
        "archive_sha1": "1bdbc651cda9ba9995c53ed9c71ceaa65094762d",
        "archive_sri": "sha512-pW4AC0P3it8c7do9MVM4p51FzHzdM/TZrerurgRcHJ2WTa1VQ1CIq18xncfpBJw4ojkiZZrKW2yIBWBP92j6Ug==",
        "binary_rel": "package/bin/esbuild",
        "binary_sha256": "90bd269553d258e80b19e3ccab4f98f0831f87442a2f056510ce24fd1b425fc2",
        "members": ("package/README.md", "package/bin/esbuild", "package/package.json"),
    },
    "linux-x64": {
        "package": "@esbuild/linux-x64",
        "archive_url": "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.28.2.tgz",
        "archive_name": "linux-x64-0.28.2.tgz",
        "archive_sha256": "9573bb2233aab0f9ea7647d5cca9726113cc1768de61d66b17267f4db84488f6",
        "archive_bytes": 4741809,
        "archive_sha1": "268b36211c146ca54f8fe12c578a8d6ef8979485",
        "archive_sri": "sha512-4xTZr1FUmSoQW4XIWmit3tzQrUTZM+N3P0XV8xROKYF50XfI7xeO90+1bZvNwxIufQ9hDQVRJH5YhgPVF8A/HQ==",
        "binary_rel": "package/bin/esbuild",
        "binary_sha256": "e1698a3d5c6c0798fee4fd3b5cc816651f460c63d390a7a26ea4beb0b1884100",
        "members": ("package/README.md", "package/bin/esbuild", "package/package.json"),
    },
    "win32-arm64": {
        "package": "@esbuild/win32-arm64",
        "archive_url": "https://registry.npmjs.org/@esbuild/win32-arm64/-/win32-arm64-0.28.2.tgz",
        "archive_name": "win32-arm64-0.28.2.tgz",
        "archive_sha256": "b3cffeaa165134f7da679c8619266953afd5f41641a254615a57e757f67c7336",
        "archive_bytes": 4323046,
        "archive_sha1": "ee5ab40fad186201b652a33f8a5eb149e9e42532",
        "archive_sri": "sha512-PIhhEkE9uPBleRBrQEJpUn7MBnibZzbGzYWPmY3x+YoVg/95zbjB4CxPPOQ8l5tYYM4mMaCthF8/1DIfBQQyWQ==",
        "binary_rel": "package/esbuild.exe",
        "binary_sha256": "530fb3933af14eefe85dfd06502f826e6ef60fdf4e75228ea67c696db312ecb1",
        "members": ("package/README.md", "package/esbuild.exe", "package/package.json"),
    },
    "win32-x64": {
        "package": "@esbuild/win32-x64",
        "archive_url": "https://registry.npmjs.org/@esbuild/win32-x64/-/win32-x64-0.28.2.tgz",
        "archive_name": "win32-x64-0.28.2.tgz",
        "archive_sha256": "7286c3611b6f1f4c4d9ec90adcbc478407ff0d28ead96567f361d53e67613e19",
        "archive_bytes": 4829680,
        "archive_sha1": "b21affb804cc167c133d95f45b3a1dc1323b9a87",
        "archive_sri": "sha512-5ebpxr3nWMzrL/rnUI755Jkuee0bHL/Gq0WTF9lvcpv73wAp5eu8MfBUgWK9bhWvZjj7yX8etf/8tI8Ney695g==",
        "binary_rel": "package/esbuild.exe",
        "binary_sha256": "c7bee37877d0aa6a046e52783fa0a2cf1a9ce5579d68bb3083bda99d4bff18ef",
        "members": ("package/README.md", "package/esbuild.exe", "package/package.json"),
    },
}


class MinifyError(RuntimeError):
    """Raised when the store JavaScript size transform cannot proceed."""


def fail(message: str) -> NoReturn:
    raise MinifyError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(fd)
    return digest.hexdigest()


def host_platform_key(
    system: str | None = None, machine: str | None = None
) -> str:
    sysname = (system if system is not None else sys.platform).lower()
    mach = (machine if machine is not None else platform.machine()).lower()
    if sysname == "darwin":
        if mach in {"arm64", "aarch64"}:
            return "darwin-arm64"
        if mach in {"x86_64", "amd64"}:
            return "darwin-x64"
    elif sysname.startswith("linux"):
        if mach in {"arm64", "aarch64"}:
            return "linux-arm64"
        if mach in {"x86_64", "amd64"}:
            return "linux-x64"
    elif sysname in {"win32", "windows", "cygwin"}:
        if mach in {"arm64", "aarch64"}:
            return "win32-arm64"
        if mach in {"x86_64", "amd64"}:
            return "win32-x64"
    fail(f"unsupported esbuild host platform: {sysname} {mach}")


def pin_for_host(
    system: str | None = None, machine: str | None = None
) -> dict[str, object]:
    key = host_platform_key(system, machine)
    pin = PLATFORM_PINS.get(key)
    if pin is None:
        fail(f"no frozen esbuild pin for {key}")
    return pin


def cache_root(override: Path | None = None) -> Path:
    if override is not None:
        return override
    env = os.environ.get(CACHE_ENV, "").strip()
    if env:
        return Path(env)
    return Path.home() / ".cache" / DEFAULT_CACHE_NAME / TOOL_VERSION


def fetch_allowed() -> bool:
    raw = os.environ.get(FETCH_ENV, "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _require_registry_url(url: str) -> None:
    if not url.startswith("https://registry.npmjs.org/"):
        fail("esbuild archive URL is not the frozen official npm registry URL")
    if "github.com" in url.lower():
        fail("esbuild archive URL must not come from GitHub")


def _sri_ok(data: bytes, integrity: str) -> bool:
    if not integrity.startswith("sha512-"):
        return False
    expected = integrity.split("-", 1)[1]
    got = base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    return got == expected


def _curl_bin() -> str:
    for candidate in CURL_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("curl")
    if found:
        return found
    fail("curl is required to retrieve the frozen esbuild archive")


def fetch_archive(url: str, dest: Path, pin: dict[str, object]) -> None:
    _require_registry_url(url)
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".part")
    if partial.exists() or partial.is_symlink():
        partial.unlink()
    curl = _curl_bin()
    result = subprocess.run(
        [
            curl,
            "-fsS",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-redirs",
            "2",
            "--max-filesize",
            str(MAX_ARCHIVE_BYTES),
            "-o",
            str(partial),
            url,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if result.returncode != 0:
        if partial.exists():
            partial.unlink()
        err = (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
        fail(f"failed to retrieve frozen esbuild archive: {err}")
    payload = partial.read_bytes()
    verify_archive_bytes(payload, pin)
    os.replace(partial, dest)


def verify_archive_bytes(payload: bytes, pin: dict[str, object]) -> None:
    expected_bytes = int(pin["archive_bytes"])
    if len(payload) != expected_bytes:
        fail(
            f"esbuild archive size {len(payload)} does not match frozen "
            f"{expected_bytes}"
        )
    digest = sha256_bytes(payload)
    expected = str(pin["archive_sha256"])
    if not HEX64_RE.fullmatch(expected) or digest != expected:
        fail("esbuild archive SHA-256 does not match the frozen pin")
    sha1 = hashlib.sha1(payload).hexdigest()
    if sha1 != str(pin["archive_sha1"]):
        fail("esbuild archive npm SHA-1 does not match the frozen pin")
    if not _sri_ok(payload, str(pin["archive_sri"])):
        fail("esbuild archive npm SHA-512 integrity does not match the frozen pin")


def _safe_member_path(name: str) -> str:
    if not name or "\\" in name or name.startswith("/") or "\x00" in name:
        fail(f"unsafe esbuild archive member path: {name}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        fail(f"unsafe esbuild archive member path: {name}")
    return path.as_posix()


def extract_archive(archive: Path, dest: Path, pin: dict[str, object]) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=False)
    expected = frozenset(str(item) for item in pin["members"])
    binary_rel = str(pin["binary_rel"])
    found: set[str] = set()
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > MAX_EXTRACT_MEMBERS:
            fail("esbuild archive has too many members")
        for info in members:
            name = _safe_member_path(info.name)
            if info.issym() or info.islnk():
                fail(f"esbuild archive member is a link: {name}")
            if info.isdir():
                continue
            if not info.isreg():
                fail(f"esbuild archive member is not a regular file: {name}")
            if name not in expected:
                fail(f"unexpected esbuild archive member: {name}")
            if info.size < 0 or info.size > MAX_MEMBER_BYTES:
                fail(f"esbuild archive member exceeds size limit: {name}")
            extracted = tf.extractfile(info)
            if extracted is None:
                fail(f"esbuild archive member could not be read: {name}")
            payload = extracted.read(MAX_MEMBER_BYTES + 1)
            if len(payload) != info.size:
                fail(f"esbuild archive member size mismatch: {name}")
            out = dest.joinpath(*name.split("/"))
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(payload)
            mode = 0o555 if name == binary_rel else 0o444
            out.chmod(mode)
            found.add(name)
    if found != expected:
        fail("esbuild archive member set does not match the frozen pin")
    binary = dest.joinpath(*binary_rel.split("/"))
    if sha256_file(binary) != str(pin["binary_sha256"]):
        fail("esbuild binary SHA-256 does not match the frozen pin")
    document = json.loads( (dest / "package" / "package.json").read_text(encoding="utf-8") )
    if document.get("name") != pin["package"] or document.get("version") != TOOL_VERSION:
        fail("esbuild package.json identity does not match the frozen pin")
    if str(document.get("license") or "").upper() != TOOL_LICENSE:
        fail("esbuild package.json license is not the frozen MIT pin")
    return binary


def _esbuild_env(work: Path) -> dict[str, str]:
    env = {
        "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "TEMP": str(work / "tmp"),
        "TMP": str(work / "tmp"),
        "TZ": "UTC",
        "LANG": "C",
        "LC_ALL": "C",
    }
    (work / "home").mkdir(parents=True, exist_ok=True)
    (work / "tmp").mkdir(parents=True, exist_ok=True)
    return env


def _forbidden_esbuild_arg(arg: str) -> str | None:
    lowered = arg.lower()
    if lowered.startswith("--sourcemap"):
        return "esbuild source-map flags are forbidden"
    flag = lowered.split("=", 1)[0]
    if flag not in FORBIDDEN_ESBUILD_MINIFY_FLAGS:
        return None
    if flag == "--minify":
        return "identifier-mangling --minify is forbidden; whitespace-only is required"
    if flag == "--minify-identifiers":
        return (
            "identifier-mangling --minify-identifiers is forbidden; "
            "whitespace-only is required"
        )
    return (
        "identifier-mangling --minify-syntax is forbidden; "
        "whitespace-only is required"
    )


def run_esbuild(
    binary: Path, args: list[str], *, env: dict[str, str], cwd: Path
) -> subprocess.CompletedProcess[str]:
    for arg in args:
        reason = _forbidden_esbuild_arg(arg)
        if reason is not None:
            fail(reason)
    argv = [str(binary), *args]
    return subprocess.run(
        argv,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=ESBUILD_TIMEOUT_SEC,
    )


def require_esbuild_version(binary: Path, *, env: dict[str, str], cwd: Path) -> None:
    result = run_esbuild(binary, ["--version"], env=env, cwd=cwd)
    if result.returncode != 0:
        fail(f"esbuild --version failed: {(result.stderr or result.stdout).strip()}")
    version = (result.stdout or "").strip()
    if version != TOOL_VERSION:
        fail(f"esbuild version {version!r} does not match frozen {TOOL_VERSION!r}")


_ENGINE_CUSTODY: list[tempfile.TemporaryDirectory] = []
_ENGINE_SNAPSHOTS: dict[str, Path] = {}


def private_engine_snapshot(binary: Path, expected_sha256: str) -> Path:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(binary, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail("esbuild source is not a regular single-link file")
        if info.st_size <= 0 or info.st_size > MAX_MEMBER_BYTES:
            fail("esbuild source size is outside the reviewed bound")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(MAX_MEMBER_BYTES + 1)
    finally:
        os.close(fd)

    if len(payload) > MAX_MEMBER_BYTES:
        fail("esbuild snapshot exceeds the reviewed bound")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        fail("esbuild snapshot SHA-256 does not match the frozen pin")

    cached = _ENGINE_SNAPSHOTS.get(expected_sha256)
    if cached is not None:
        if sha256_file(cached) != expected_sha256:
            fail("private esbuild snapshot failed verification")
        return cached

    custody = tempfile.TemporaryDirectory(prefix="winsvpn-esbuild-exec-")
    try:
        directory = Path(custody.name)
        directory.chmod(0o700)
        destination = directory / binary.name
        out_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o500,
        )
        with os.fdopen(out_fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if sha256_file(destination) != expected_sha256:
            fail("private esbuild snapshot failed verification")
    except BaseException:
        custody.cleanup()
        raise

    _ENGINE_CUSTODY.append(custody)
    _ENGINE_SNAPSHOTS[expected_sha256] = destination
    return destination


def load_engine(
    *,
    cache: Path | None = None,
    allow_fetch: bool | None = None,
    system: str | None = None,
    machine: str | None = None,
) -> Path:
    pin = pin_for_host(system, machine)
    root = cache_root(cache)
    platform_key = host_platform_key(system, machine)
    archive_sha = str(pin["archive_sha256"])
    slot = root / platform_key / archive_sha
    archive = slot / str(pin["archive_name"])
    tree = slot / "tree"
    binary = tree.joinpath(*str(pin["binary_rel"]).split("/"))
    if archive.is_file():
        verify_archive_bytes(archive.read_bytes(), pin)
    else:
        if not (fetch_allowed() if allow_fetch is None else allow_fetch):
            fail("frozen esbuild archive is missing and fetch is disabled")
        fetch_archive(str(pin["archive_url"]), archive, pin)
        archive.chmod(0o444)
    if not binary.is_file() or sha256_file(binary) != str(pin["binary_sha256"]):
        extract_archive(archive, tree, pin)
    if sha256_file(binary) != str(pin["binary_sha256"]):
        fail("esbuild binary SHA-256 does not match the frozen pin")
    binary = private_engine_snapshot(binary, str(pin["binary_sha256"]))
    with tempfile.TemporaryDirectory(prefix="winsvpn-esbuild-ver-") as tmp:
        work = Path(tmp)
        require_esbuild_version(binary, env=_esbuild_env(work), cwd=work)
    return binary


def _strip_format_chars(text: str) -> str:
    return FORMAT_CHAR_RE.sub("", text)


def source_map_haystack(text: str) -> str:
    return _strip_format_chars(text)


def source_map_reference_present(text: str) -> bool:
    return SOURCE_MAP_RE.search(source_map_haystack(text)) is not None


def pretty_counters(text: str) -> tuple[int, int]:
    indented = 0
    comment_lines = 0
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped and stripped != line:
            indented += 1
        if (
            stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
        ):
            comment_lines += 1
    return indented, comment_lines


def is_pretty_javascript(text: str) -> bool:
    indented, comment_lines = pretty_counters(text)
    return indented >= 1 or comment_lines >= 1


def reject_javascript_evasions(label: str, text: str) -> None:
    if source_map_reference_present(text):
        fail(f"{label} contains a source-map reference")
    if OBFUSCATOR_RE.search(text):
        fail(f"{label} uses forbidden JavaScript obfuscation")
    if is_pretty_javascript(text):
        fail(f"{label} is not store-permitted minified JavaScript")


def reject_packaged_javascript(label: str, text: str) -> None:
    reject_javascript_evasions(label, text)
    require_esbuild_output_equivalence(label, text)


def packaged_javascript_names(names: list[str]) -> list[str]:
    found: list[str] = []
    for name in names:
        folded = name.casefold()
        if folded.endswith("/") or "\\" in name:
            continue
        if folded.endswith(JS_SUFFIXES):
            found.append(name)
    return found


def reject_packaged_zip_javascript(archive: zipfile.ZipFile) -> None:
    """Refuse a store zip whose JavaScript is missing, pretty, mapped, or obfuscated."""

    names = packaged_javascript_names(list(archive.namelist()))
    if not names:
        fail("package contains no JavaScript; minification cannot be proven")
    for name in names:
        payload = archive.read(name)
        if len(payload) > MAX_JS_BYTES:
            fail(f"{name} exceeds the packaged JavaScript size ceiling")
        try:
            text = payload.decode("utf-8")
        except UnicodeError:
            fail(f"{name} is not UTF-8 JavaScript")
        reject_packaged_javascript(name, text)


def _is_comment_only_line(stripped: str) -> bool:
    if stripped.startswith("//") or stripped.startswith("/*"):
        return True
    if stripped in {"*", "*/"} or stripped.startswith("* "):
        return True
    return False


def flatten_noncode_lines(text: str) -> str:
    kept: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip(" \t")
        if not stripped or _is_comment_only_line(stripped):
            continue
        kept.append(stripped)
    return "\n".join(kept) + ("\n" if kept else "")


def restore_native_host_name(text: str) -> str:
    compact_dq = f'export const NATIVE_HOST_NAME="{NATIVE_HOST_VALUE}"'
    compact_sq = f"export const NATIVE_HOST_NAME='{NATIVE_HOST_VALUE}'"
    if compact_dq in text:
        text = text.replace(compact_dq, NATIVE_HOST_REQUIRED)
    if compact_sq in text:
        text = text.replace(compact_sq, NATIVE_HOST_REQUIRED)
    return text


def _skip_string(text: str, i: int, quote: str) -> int:
    i += 1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    fail("unterminated JavaScript string in store size transform")


def match_braces(text: str, open_at: int) -> int:
    if open_at >= len(text) or text[open_at] != "{":
        fail("object expander expected '{'")
    depth = 0
    i = open_at
    while i < len(text):
        ch = text[i]
        if ch in {'"', "'", "`"}:
            i = _skip_string(text, i, ch)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    fail("unbalanced object braces in store size transform")


def split_top_level_commas(body: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth_brace = 0
    depth_brack = 0
    depth_paren = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch in {'"', "'", "`"}:
            start = i
            i = _skip_string(body, i, ch)
            buf.append(body[start:i])
            continue
        if ch == "{":
            depth_brace += 1
            buf.append(ch)
        elif ch == "}":
            depth_brace -= 1
            buf.append(ch)
        elif ch == "[":
            depth_brack += 1
            buf.append(ch)
        elif ch == "]":
            depth_brack -= 1
            buf.append(ch)
        elif ch == "(":
            depth_paren += 1
            buf.append(ch)
        elif ch == ")":
            depth_paren -= 1
            buf.append(ch)
        elif (
            ch == ","
            and depth_brace == 0
            and depth_brack == 0
            and depth_paren == 0
        ):
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def expand_export_object(text: str, name: str) -> str:
    needle = f"export const {name}="
    start = text.find(needle)
    if start < 0:
        fail(f"missing {needle} after the store size transform")
    cursor = start + len(needle)
    while cursor < len(text) and text[cursor] in " \t":
        cursor += 1
    if cursor >= len(text) or text[cursor] != "{":
        fail(f"{name} export is not an object literal")
    close = match_braces(text, cursor)
    parts = split_top_level_commas(text[cursor + 1 : close])
    if len(parts) < 2:
        fail(f"{name} object lost its keys during the store size transform")
    rebuilt = needle + "{\n" + ",\n".join(parts) + "\n}"
    after = close + 1
    suffix = ""
    if after < len(text) and text[after] == ";":
        suffix = ";"
        after += 1
    return text[:start] + rebuilt + suffix + text[after:]


def apply_producer_surface(text: str, label: str) -> str:
    text = flatten_noncode_lines(text)
    text = restore_native_host_name(text)
    if "export const STATE=" in text:
        text = expand_export_object(text, "STATE")
    if "export const STATE_COPY=" in text:
        text = expand_export_object(text, "STATE_COPY")
    if "export const NATIVE_HOST_NAME=" in text or "export const NATIVE_HOST_NAME =" in text:
        if NATIVE_HOST_REQUIRED not in text:
            fail(f"{label} lost NATIVE_HOST_NAME producer form")
    if "export const STATE=" in text:
        if re.search(r"export const STATE=\{(.*?)\n\};", text, re.S) is None:
            fail(f"{label} lost STATE producer form")
        match = re.search(r"export const STATE=\{(.*?)\n\};", text, re.S)
        keys = re.findall(r"^\s*([A-Z_]+)\s*:", match.group(1), re.M) if match else []
        if len(keys) < 2:
            fail(f"{label} STATE keys were dropped")
    if "export const STATE_COPY=" in text:
        if re.search(r"export const STATE_COPY=\{(.*?)\n\};", text, re.S) is None:
            fail(f"{label} lost STATE_COPY producer form")
    return text


def quoted_string_values(text: str) -> list[str]:
    values: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in {"'", '"'}:
            start = i + 1
            i = _skip_string(text, i, ch)
            values.append(text[start : i - 1])
            continue
        if ch == "`":
            i = _skip_string(text, i, "`")
            continue
        if ch == "/" and i + 1 < len(text) and text[i + 1] == "/":
            newline = text.find("\n", i)
            i = len(text) if newline < 0 else newline + 1
            continue
        if ch == "/" and i + 1 < len(text) and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            continue
        i += 1
    return values


def export_names(text: str) -> set[str]:
    names = set(EXPORT_NAME_RE.findall(text))
    for group in EXPORT_BRACE_RE.findall(text):
        for part in group.split(","):
            token = part.strip()
            if not token:
                continue
            if " as " in f" {token} ":
                token = token.split(" as ")[0].strip()
            names.add(token)
    return names


def import_specifiers(text: str) -> list[str]:
    return IMPORT_FROM_RE.findall(text)


def semantic_fingerprint(text: str) -> dict[str, object]:
    return {
        "imports": import_specifiers(text),
        "exports": sorted(export_names(text)),
        "strings": quoted_string_values(text),
    }


def reject_semantic_drift(label: str, source: str, transformed: str) -> None:
    before = semantic_fingerprint(source)
    after = semantic_fingerprint(transformed)
    if before["imports"] != after["imports"]:
        fail(f"{label} import specifiers changed during the store size transform")
    if before["exports"] != after["exports"]:
        fail(f"{label} export names changed during the store size transform")
    before_strings = set(before["strings"])
    after_strings = set(after["strings"])
    missing = before_strings - after_strings
    # Adjacent-string folding is a size transform. Each authored literal must
    # still appear in the packaged text; losing it is semantic drift.
    for item in missing:
        if item not in transformed:
            fail(f"{label} dropped string literals during the store size transform")
    required_substrings = (
        "api.runtime.connectNative(",
        "this.adapter.connectNative(NATIVE_HOST_NAME",
        "extends BaseAdapter",
        NATIVE_HOST_REQUIRED,
    )
    for needle in required_substrings:
        if needle in source and needle not in transformed:
            fail(f"{label} lost required producer token {needle!r}")


def javascript_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            fail(f"staged JavaScript path is a symbolic link: {path}")
        if not stat.S_ISREG(info.st_mode):
            continue
        if path.suffix.casefold() in JS_SUFFIXES:
            files.append(path)
        if path.suffix.casefold() == ".map" or path.name.casefold().endswith(".js.map"):
            fail(f"source map artifact is forbidden: {path}")
    return files


def _decode_js(label: str, data: bytes) -> str:
    if len(data) > MAX_JS_BYTES:
        fail(f"{label} exceeds the JavaScript size limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not UTF-8 text: {exc}")


def transform_javascript(
    source: str,
    *,
    binary: Path,
    label: str,
) -> str:
    if not source:
        fail(f"{label} is empty")
    with tempfile.TemporaryDirectory(prefix="winsvpn-esbuild-run-") as tmp:
        work = Path(tmp)
        env = _esbuild_env(work)
        infile = work / "input.js"
        outfile = work / "output.js"
        infile.write_text(source, encoding="utf-8")
        args = [
            str(infile),
            *ESBUILD_TRANSFORM_FLAGS,
            f"--outfile={outfile}",
        ]
        first = run_esbuild(binary, args, env=env, cwd=work)
        if first.returncode != 0:
            fail(
                f"esbuild refused {label}: "
                f"{(first.stderr or first.stdout or '').strip() or first.returncode}"
            )
        if not outfile.is_file():
            fail(f"esbuild skipped {label}")
        sidecar = Path(str(outfile) + ".map")
        if sidecar.exists() or (work / "output.js.map").exists():
            fail(f"esbuild emitted a source map for {label}")
        transformed = _decode_js(label, outfile.read_bytes())
        outfile.unlink()
        second = run_esbuild(binary, args, env=env, cwd=work)
        if second.returncode != 0 or not outfile.is_file():
            fail(f"esbuild nondeterminism check failed for {label}")
        again = _decode_js(label, outfile.read_bytes())
        if again != transformed:
            fail(f"{label} esbuild output is not deterministic")
    restored = apply_producer_surface(transformed, label)
    reject_javascript_evasions(label, restored)
    reject_semantic_drift(label, source, restored)
    if is_pretty_javascript(source) and restored == source:
        fail(f"{label} was skipped by the store size transform")
    return restored


def intended_javascript_members() -> frozenset[str]:
    members: list[str] = []
    for path in authored_source_files():
        relative = "src/" + path.relative_to(EXTENSION_SRC).as_posix()
        if relative.casefold().endswith(JS_SUFFIXES):
            members.append(relative)
    if not members:
        fail("authored extension source contains no JavaScript")
    return frozenset(members)


def minify_package_javascript(
    pkg: Path,
    *,
    binary: Path | None = None,
    cache: Path | None = None,
    allow_fetch: bool | None = None,
    require_intended: bool = True,
) -> None:
    src = pkg / "src"
    if not src.is_dir():
        fail("staged package is missing src/")
    files = javascript_files(src)
    if not files:
        fail("staged package contains no JavaScript; minification cannot be proven")
    staged_names = {path.relative_to(pkg).as_posix(): path for path in files}
    intended = intended_javascript_members() if require_intended else None
    if intended is not None:
        extra = set(staged_names) - intended
        missing = intended - set(staged_names)
        if missing:
            fail(
                "intended JavaScript members were not staged: "
                + ", ".join(sorted(missing))
            )
        if extra:
            fail(
                "unexpected JavaScript members were staged: "
                + ", ".join(sorted(extra))
            )
        names = sorted(intended)
    else:
        names = sorted(staged_names)
    fetch = False if allow_fetch is None else allow_fetch
    engine = binary if binary is not None else load_engine(
        cache=cache, allow_fetch=fetch
    )
    processed: set[str] = set()
    for relative in names:
        path = pkg.joinpath(*relative.split("/"))
        original_bytes = path.read_bytes()
        original = _decode_js(relative, original_bytes)
        if intended is not None:
            authored_path = EXTENSION_SRC.joinpath(*relative.split("/")[1:])
            authored_bytes = authored_path.read_bytes()
            if original_bytes != authored_bytes:
                fail(f"{relative} staged bytes do not match authored source")
        transformed = transform_javascript(
            original, binary=engine, label=relative
        )
        if is_pretty_javascript(original) and transformed == original:
            fail(f"{relative} was skipped by the store size transform")
        encoded = transformed.encode("utf-8")
        if encoded == original_bytes and is_pretty_javascript(original):
            fail(f"{relative} is byte-identical to authored source")
        path.write_bytes(encoded)
        if path.read_bytes() != encoded:
            fail(f"{relative} mutated after the store size transform")
        processed.add(relative)
    leftover = [
        path.relative_to(pkg).as_posix()
        for path in javascript_files(src)
        if path.relative_to(pkg).as_posix() not in processed
    ]
    if leftover:
        fail("JavaScript files were skipped: " + ", ".join(leftover))
    if intended is not None:
        missing_processed = intended - processed
        if missing_processed:
            fail(
                "intended JavaScript members were not minified: "
                + ", ".join(sorted(missing_processed))
            )
    for relative in sorted(processed):
        path = pkg.joinpath(*relative.split("/"))
        text = _decode_js(relative, path.read_bytes())
        reject_packaged_javascript(relative, text)
        if intended is not None:
            authored_bytes = EXTENSION_SRC.joinpath(
                *relative.split("/")[1:]
            ).read_bytes()
            if path.read_bytes() == authored_bytes and is_pretty_javascript(
                _decode_js(relative, authored_bytes)
            ):
                fail(f"{relative} is byte-identical to authored source")
        if relative.endswith("core/constants.js"):
            if NATIVE_HOST_REQUIRED not in text:
                fail("constants.js lost NATIVE_HOST_NAME producer form")
        if relative.endswith("adapters/base.js"):
            if "api.runtime.connectNative(" not in text:
                fail("base.js lost api.runtime.connectNative(")
        if relative.endswith("background/controller.js"):
            if "this.adapter.connectNative(NATIVE_HOST_NAME" not in text:
                fail("controller.js lost adapter.connectNative(NATIVE_HOST_NAME")


def reset_producer_javascript_cache() -> None:
    global _PRODUCER_PACKAGED_JS
    _PRODUCER_PACKAGED_JS = None


def _ignore_source_name(name: str) -> bool:
    if name.startswith("._") or name in {".DS_Store", "__pycache__"}:
        return True
    if name.endswith(".pyc") or name.endswith(".bak_20260807_webrequest"):
        return True
    return False


def authored_source_files() -> list[Path]:
    files: list[Path] = []
    if not EXTENSION_SRC.is_dir():
        fail("authored extension source is missing")
    for path in sorted(EXTENSION_SRC.rglob("*")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            fail(f"authored source is a symbolic link: {path}")
        if not stat.S_ISREG(info.st_mode):
            continue
        if _ignore_source_name(path.name):
            continue
        files.append(path)
    if not files:
        fail("authored extension source contains no files")
    return files


def expected_package_members() -> frozenset[str]:
    members = {"manifest.json"}
    for path in authored_source_files():
        members.add("src/" + path.relative_to(EXTENSION_SRC).as_posix())
    members.update(EXPECTED_ICON_MEMBERS)
    return frozenset(members)


def producer_packaged_javascript(*, binary: Path | None = None) -> dict[str, str]:
    global _PRODUCER_PACKAGED_JS
    if _PRODUCER_PACKAGED_JS is not None:
        return dict(_PRODUCER_PACKAGED_JS)
    engine = binary if binary is not None else load_engine(allow_fetch=False)
    packaged: dict[str, str] = {}
    for relative in sorted(intended_javascript_members()):
        path = EXTENSION_SRC.joinpath(*relative.split("/")[1:])
        original = _decode_js(relative, path.read_bytes())
        packaged[relative] = transform_javascript(
            original, binary=engine, label=relative
        )
    if not packaged:
        fail("authored extension source contains no JavaScript")
    _PRODUCER_PACKAGED_JS = packaged
    return dict(packaged)


def require_esbuild_output_equivalence(
    label: str,
    packaged: str,
    *,
    source: str | None = None,
    binary: Path | None = None,
) -> None:
    engine = binary if binary is not None else load_engine(allow_fetch=False)
    expected = transform_javascript(
        source if source is not None else packaged,
        binary=engine,
        label=label,
    )
    if packaged != expected:
        fail(f"{label} is not the reproducible esbuild producer output")


def _zip_extra_field_types(extra: bytes) -> set[int]:
    types: set[int] = set()
    offset = 0
    extra = extra or b""
    while offset + 4 <= len(extra):
        code = int.from_bytes(extra[offset : offset + 2], "little")
        size = int.from_bytes(extra[offset + 2 : offset + 4], "little")
        offset += 4
        if size < 0 or offset + size > len(extra):
            fail("zip extra field is truncated or malformed")
        types.add(code)
        offset += size
    if offset != len(extra):
        fail("zip extra field is truncated or malformed")
    return types


def _zip_member_declared_name(info: zipfile.ZipInfo) -> str:
    extra_types = _zip_extra_field_types(info.extra)
    if ZIP_UNICODE_PATH_EXTRA in extra_types:
        fail(f"ambiguous zip unicode path extra field: {info.filename}")
    if info.filename != info.orig_filename:
        fail(f"ambiguous zip member path encoding: {info.orig_filename!r}")
    name = info.orig_filename
    utf8 = bool(info.flag_bits & ZIP_UTF8_FLAG)
    if not utf8 and not name.isascii():
        fail(f"non-UTF8 zip member path is ambiguous: {name}")
    return name


def _unix_file_type(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0o170000


def zip_hygiene_failures(archive: zipfile.ZipFile) -> list[str]:
    """Producer ZIP hygiene: comments, NFC, extras, nested META-INF, maps, closure."""

    failures: list[str] = []
    if archive.comment:
        failures.append("zip comments are forbidden")
        if source_map_reference_present(
            archive.comment.decode("utf-8", "replace")
        ):
            failures.append("zip comment contains a source-map reference")
    expected = expected_package_members()
    seen_names: set[str] = set()
    seen_normalized: dict[str, str] = {}
    seen_folded: dict[str, str] = {}
    file_members: set[str] = set()
    try:
        infos = list(archive.infolist())
    except zipfile.BadZipFile as exc:
        return [f"BadZipFile: {exc}"]
    for info in infos:
        try:
            if info.flag_bits & (ZIP_ENCRYPTED_FLAG | ZIP_STRONG_ENCRYPTION_FLAG):
                failures.append(f"encrypted zip member: {info.filename}")
                continue
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                failures.append(
                    f"unsupported zip compression method: {info.filename}"
                )
                continue
            name = _zip_member_declared_name(info)
        except MinifyError as exc:
            failures.append(str(exc))
            continue
        if name in seen_names:
            failures.append(f"duplicate zip member name: {name}")
            continue
        seen_names.add(name)
        if "\x00" in name or any(ord(character) < 32 for character in name):
            failures.append(f"zip member path contains a control character: {name}")
            continue
        if unicodedata.normalize("NFC", name) != name:
            failures.append(f"non-NFC zip member path: {name}")
            continue
        if "\\" in name:
            failures.append(f"backslash zip member path: {name}")
            continue
        if name.startswith("/") or name.endswith("/"):
            failures.append(f"unsafe zip member path: {name}")
            continue
        parts = name.split("/")
        if not parts or any(part in {"", ".", ".."} for part in parts):
            failures.append(f"ambiguous zip member path: {name}")
            continue
        if any(unicodedata.normalize("NFC", part) != part for part in parts):
            failures.append(f"non-NFC zip member path: {name}")
            continue
        previous = seen_normalized.get(name)
        if previous is not None:
            failures.append(
                f"ambiguous normalized zip member paths: {previous} and {name}"
            )
            continue
        folded = name.casefold()
        folded_previous = seen_folded.get(folded)
        if folded_previous is not None:
            failures.append(
                f"Unicode or case-fold zip member collision: {folded_previous} and {name}"
            )
            continue
        seen_normalized[name] = name
        seen_folded[folded] = name
        file_type = _unix_file_type(info)
        if file_type == UNIX_SYMLINK_TYPE or stat.S_ISLNK(file_type):
            failures.append(f"zip member is a symbolic link: {name}")
            continue
        if info.is_dir():
            failures.append(f"zip directory members are forbidden: {name}")
            continue
        posix = PurePosixPath(name)
        folded_parts = {part.casefold() for part in posix.parts}
        if folded_parts & FORBIDDEN_ZIP_PATH_PARTS:
            failures.append(
                f"store-upload zip must not contain {name} "
                "(already packed or already signed)"
            )
        suffix = posix.suffix.casefold()
        if suffix == ".map" or posix.name.casefold().endswith(".js.map"):
            failures.append(f"source map artifact is forbidden: {name}")
        if name != "manifest.json" and not name.startswith("src/"):
            failures.append(f"extra zip member is forbidden: {name}")
        elif name != "manifest.json" and suffix not in ALLOWED_PACKAGE_SUFFIXES:
            failures.append(f"forbidden packaged suffix: {name}")
        file_members.add(name)
    extra = file_members - expected
    missing = expected - file_members
    if extra:
        failures.append(
            "package member set has extra members: " + ", ".join(sorted(extra))
        )
    if missing:
        failures.append(
            "package member set is missing producer members: "
            + ", ".join(sorted(missing))
        )
    return failures


def require_zip_javascript_matches_producer(
    archive: zipfile.ZipFile, *, binary: Path | None = None
) -> None:
    expected = producer_packaged_javascript(binary=binary)
    names = packaged_javascript_names(list(archive.namelist()))
    extra = set(names) - set(expected)
    missing = set(expected) - set(names)
    if extra or missing:
        fail("package JavaScript member set is not the producer closure")
    for name in names:
        payload = archive.read(name)
        if len(payload) > MAX_JS_BYTES:
            fail(f"{name} exceeds the packaged JavaScript size ceiling")
        try:
            text = payload.decode("utf-8")
        except UnicodeError:
            fail(f"{name} is not UTF-8 JavaScript")
        reject_javascript_evasions(name, text)
        if text != expected[name]:
            fail(f"{name} is not the reproducible esbuild producer output")


def require_static_source_members(archive: zipfile.ZipFile) -> None:
    for path in authored_source_files():
        relative = "src/" + path.relative_to(EXTENSION_SRC).as_posix()
        if relative.endswith(JS_SUFFIXES):
            continue
        try:
            packaged = archive.read(relative)
        except KeyError:
            fail(f"{relative} is missing from the producer member closure")
        authored = path.read_bytes()
        if packaged != authored:
            fail(f"{relative} does not match authored source bytes")


def read_regular_nofollow(
    path: Path,
    label: str,
    *,
    maximum: int = MAX_ZIP_ARCHIVE_BYTES,
    root: Path | None = None,
) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if root is not None:
        stop = Path(os.path.abspath(os.fspath(root)))
        try:
            relative = absolute.relative_to(stop)
        except ValueError:
            stop = absolute.parent
            relative = Path(absolute.name)
    else:
        stop = absolute.parent
        relative = Path(absolute.name)
    if (
        not relative.parts
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        fail(f"{label} path is not canonical")
    current = stop
    try:
        info = current.lstat()
    except OSError as suc:
        fail(f"{label} is missing")
        raise suc
    if stat.S_ISLNK(info.st_mode):
        fail(f"{label} traverses a symbolic link")
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{label} parent is not a directory")
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            info = current.lstat()
        except OSError as suc:
            fail(f"{label} is missing")
            raise suc
        if stat.S_ISLNK(info.st_mode):
            fail(f"{label} traverses a symbolic link")
        is_leaf = index == len(relative.parts) - 1
        if is_leaf:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail(f"{label} must be a distinct regular file, not a hard link")
            if info.st_size <= 0 or info.st_size > maximum:
                fail(f"{label} size is not exact")
        elif not stat.S_ISDIR(info.st_mode):
            fail(f"{label} parent is not a directory")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as suc:
        fail(f"{label} cannot be opened without following")
        raise suc
    try:
        opened = os.fstat(descriptor)
        before = absolute.lstat()
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            stat.S_IFMT(before.st_mode),
        )
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            stat.S_IFMT(opened.st_mode),
        )
        if identity != opened_identity or not stat.S_ISREG(opened.st_mode):
            fail(f"{label} changed, is not regular, or has a hardlink alias")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                fail(f"{label} ended before its declared size")
            chunks.append(block)
            remaining -= len(block)
        extra = os.read(descriptor, 1)
        if extra:
            fail(f"{label} grew while it was read")
        finished = os.fstat(descriptor)
        after = absolute.lstat()
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        stat.S_IFMT(after.st_mode),
    )
    finished_identity = (
        finished.st_dev,
        finished.st_ino,
        finished.st_nlink,
        finished.st_size,
        finished.st_mtime_ns,
        stat.S_IFMT(finished.st_mode),
    )
    if (
        identity != after_identity
        or identity != finished_identity
        or len(payload) != before.st_size
        or stat.S_ISLNK(after.st_mode)
    ):
        fail(f"{label} was swapped or is not a regular single-inode file")
    return payload
