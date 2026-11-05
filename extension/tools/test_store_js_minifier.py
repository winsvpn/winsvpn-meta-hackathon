#!/usr/bin/env python3
"""Fail-closed tests for the extension store JavaScript size transform."""
from __future__ import annotations

import io
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXT = TOOLS.parent
ROOT = EXT.parent
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(ROOT / "tools"))

import store_js_minifier as minifier  # noqa: E402

PRETTY_JS = """export function start() {
  const ok = true;
  return ok;
}
"""
FAKE_ESBUILD_PY = r"""#!/usr/bin/env python3
import sys
from pathlib import Path
MODE = %r
STAMP = Path(%r)
args = sys.argv[1:]
if args == ["--version"]:
    print(%r)
    raise SystemExit(0)
outfile = None
infile = None
for arg in args:
    if arg.startswith("--outfile="):
        outfile = Path(arg.split("=", 1)[1])
    elif arg.startswith("--"):
        continue
    else:
        infile = Path(arg)
if infile is None or outfile is None:
    raise SystemExit(2)
text = infile.read_text(encoding="utf-8")
if MODE == "skip":
    raise SystemExit(0)
if MODE == "pretty":
    out = text
elif MODE == "sourcemap":
    out = "export const ok=true;\n//# sourceMappingURL=hidden.js.map\n"
    Path(str(outfile) + ".map").write_text("{}", encoding="utf-8")
elif MODE == "drift":
    out = text.replace("org.winsvpn.bridge", "evil.example")
    out = out.replace("\n", "")
    if not out.endswith("\n"):
        out += "\n"
elif MODE == "nondet":
    count = int(STAMP.read_text(encoding="utf-8") or "0") + 1
    STAMP.write_text(str(count), encoding="utf-8")
    out = "export const n=" + str(count) + ";\n"
else:
    out = "export const ok=true;\n"
outfile.write_text(out, encoding="utf-8")
"""


def _load_builder():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "extension_build_store_js_minifier", EXT / "build.py"
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def test_private_engine_snapshot_survives_cache_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"reviewed executable fixture\n"
    source = tmp_path / "esbuild"
    source.write_bytes(payload)
    expected = minifier.sha256_bytes(payload)

    monkeypatch.setattr(minifier, "_ENGINE_SNAPSHOTS", {})
    monkeypatch.setattr(minifier, "_ENGINE_CUSTODY", [])

    try:
        snapshot = minifier.private_engine_snapshot(source, expected)
        assert snapshot.read_bytes() == payload
        assert minifier.private_engine_snapshot(source, expected) == snapshot

        source.write_bytes(b"replacement executable fixture\n")
        assert snapshot.read_bytes() == payload

        with pytest.raises(minifier.MinifyError, match="does not match"):
            minifier.private_engine_snapshot(source, expected)

        assert snapshot.read_bytes() == payload
    finally:
        for custody in minifier._ENGINE_CUSTODY:
            custody.cleanup()


def _pin() -> dict[str, object]:
    return minifier.pin_for_host()


def _seed_cache(cache: Path) -> Path:
    pin = _pin()
    slot = cache / minifier.host_platform_key() / str(pin["archive_sha256"])
    slot.mkdir(parents=True, exist_ok=True)
    dest = slot / str(pin["archive_name"])
    discovered = (
        Path("/tmp/winsvpn-esbuild-discovery/archives") / str(pin["archive_name"])
    )
    if dest.is_file() and minifier.sha256_file(dest) == pin["archive_sha256"]:
        return cache
    configured = (
        minifier.cache_root() / minifier.host_platform_key()
        / str(pin["archive_sha256"]) / str(pin["archive_name"])
    )
    for source in (configured, discovered):
        if source.is_file():
            payload = source.read_bytes()
            minifier.verify_archive_bytes(payload, pin)
            dest.write_bytes(payload)
            dest.chmod(0o444)
            return cache
    if os.environ.get(minifier.FETCH_ENV, "").strip() != "1":
        pytest.skip(
            "frozen esbuild archive is not cached locally; set "
            f"{minifier.FETCH_ENV}=1 to fetch the pinned archive"
        )
    minifier.fetch_archive(str(pin["archive_url"]), dest, pin)
    dest.chmod(0o444)
    return cache


@pytest.fixture
def esbuild_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cache = tmp_path / "esbuild-cache"
    _seed_cache(cache)
    monkeypatch.setenv(minifier.CACHE_ENV, str(cache))
    monkeypatch.setenv(minifier.FETCH_ENV, "0")
    return cache


def _write_fake_esbuild(tmp_path: Path, mode: str, version: str = "0.28.2") -> Path:
    fake = tmp_path / "fake-esbuild"
    stamp = tmp_path / "fake-stamp"
    stamp.write_text("0", encoding="ascii")
    fake.write_text(
        FAKE_ESBUILD_PY % (mode, str(stamp), version),
        encoding="ascii",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    return fake


def test_host_platform_and_pins_are_frozen():
    key = minifier.host_platform_key()
    pin = minifier.PLATFORM_PINS[key]
    assert pin["package"].startswith("@esbuild/")
    assert str(pin["archive_url"]).startswith("https://registry.npmjs.org/@esbuild/")
    assert pin["archive_url"].endswith(f"{key}-{minifier.TOOL_VERSION}.tgz")
    assert minifier.TOOL_VERSION == "0.28.2"
    assert minifier.TOOL_LICENSE == "MIT"
    for item in minifier.PLATFORM_PINS.values():
        assert minifier.HEX64_RE.fullmatch(str(item["archive_sha256"]))
        assert minifier.HEX64_RE.fullmatch(str(item["binary_sha256"]))
        assert str(item["archive_sri"]).startswith("sha512-")


def test_missing_tool_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(minifier.CACHE_ENV, str(tmp_path / "empty-cache"))
    monkeypatch.setenv(minifier.FETCH_ENV, "0")
    with pytest.raises(minifier.MinifyError, match="missing and fetch is disabled"):
        minifier.load_engine(allow_fetch=False)


def test_wrong_archive_hash_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pin = _pin()
    cache = tmp_path / "bad-hash-cache"
    slot = cache / minifier.host_platform_key() / str(pin["archive_sha256"])
    slot.mkdir(parents=True)
    archive = slot / str(pin["archive_name"])
    archive.write_bytes(b"\x00" * int(pin["archive_bytes"]))
    archive.chmod(0o444)
    monkeypatch.setenv(minifier.CACHE_ENV, str(cache))
    with pytest.raises(minifier.MinifyError, match="SHA-256"):
        minifier.load_engine(cache=cache, allow_fetch=False)


def test_wrong_archive_size_refuses():
    pin = _pin()
    with pytest.raises(minifier.MinifyError, match="size"):
        minifier.verify_archive_bytes(b"too-small", pin)


def test_wrong_binary_hash_refuses(tmp_path: Path, esbuild_cache: Path):
    pin = _pin()
    archive = (
        esbuild_cache
        / minifier.host_platform_key()
        / str(pin["archive_sha256"])
        / str(pin["archive_name"])
    )
    mutated = tmp_path / "mutated.tgz"
    with tarfile.open(archive, "r:gz") as reader, tarfile.open(mutated, "w:gz") as writer:
        for info in reader.getmembers():
            extracted = reader.extractfile(info)
            payload = extracted.read() if extracted is not None else b""
            if info.name == pin["binary_rel"]:
                payload = payload[:-1] + bytes([payload[-1] ^ 0xFF])
                info.size = len(payload)
            from io import BytesIO

            writer.addfile(info, BytesIO(payload))
    with pytest.raises(minifier.MinifyError, match="binary SHA-256"):
        minifier.extract_archive(mutated, tmp_path / "tree", pin)


def test_wrong_version_refuses(esbuild_cache: Path, monkeypatch: pytest.MonkeyPatch):
    binary = minifier.load_engine(cache=esbuild_cache, allow_fetch=False)
    real = minifier.run_esbuild

    def lie(binpath, args, *, env, cwd):
        if args == ["--version"]:
            return subprocess.CompletedProcess(args, 0, stdout="0.0.0\n", stderr="")
        return real(binpath, args, env=env, cwd=cwd)

    monkeypatch.setattr(minifier, "run_esbuild", lie)
    with tempfile_work() as work:
        with pytest.raises(minifier.MinifyError, match="version"):
            minifier.require_esbuild_version(
                binary, env=minifier._esbuild_env(work), cwd=work
            )


def tempfile_work():
    import tempfile
    from contextlib import contextmanager

    @contextmanager
    def _ctx():
        with tempfile.TemporaryDirectory(prefix="winsvpn-esbuild-test-") as tmp:
            yield Path(tmp)

    return _ctx()


def test_pretty_javascript_is_rejected(esbuild_cache: Path):
    with pytest.raises(minifier.MinifyError, match="not store-permitted minified"):
        minifier.reject_packaged_javascript("pretty.js", PRETTY_JS)
    binary = minifier.load_engine(cache=esbuild_cache, allow_fetch=False)
    minified = minifier.transform_javascript(
        PRETTY_JS, binary=binary, label="pretty.js"
    )
    minifier.reject_packaged_javascript("minified.js", minified)


def test_packaged_zip_javascript_must_be_store_minified(
    tmp_path: Path, esbuild_cache: Path
):
    import zipfile

    binary = minifier.load_engine(cache=esbuild_cache, allow_fetch=False)
    minified_js = minifier.transform_javascript(
        PRETTY_JS, binary=binary, label="pretty.js"
    )
    minified = tmp_path / "minified.zip"
    with zipfile.ZipFile(minified, "w") as archive:
        archive.writestr("src/background/background.js", minified_js)
    with zipfile.ZipFile(minified) as archive:
        minifier.reject_packaged_zip_javascript(archive)

    pretty = tmp_path / "pretty.zip"
    with zipfile.ZipFile(pretty, "w") as archive:
        archive.writestr("src/background/background.js", PRETTY_JS)
    with zipfile.ZipFile(pretty) as archive:
        with pytest.raises(minifier.MinifyError, match="not store-permitted minified"):
            minifier.reject_packaged_zip_javascript(archive)

    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty, "w") as archive:
        archive.writestr("manifest.json", "{}\n")
    with zipfile.ZipFile(empty) as archive:
        with pytest.raises(minifier.MinifyError, match="minification cannot be proven"):
            minifier.reject_packaged_zip_javascript(archive)


def test_zero_indent_pretty_javascript_is_not_esbuild_output(esbuild_cache: Path):
    zero = "export function start() {\nconst ok = true;\nreturn ok;\n}\n"
    assert not minifier.is_pretty_javascript(zero)
    with pytest.raises(
        minifier.MinifyError, match="not the reproducible esbuild producer output"
    ):
        minifier.reject_packaged_javascript("zero.js", zero)


def test_nbsp_indent_and_inline_comment_evasions_are_rejected(esbuild_cache: Path):
    nbsp = "export function start() {\n\u00a0const ok=true;\nreturn ok;\n}\n"
    with pytest.raises(minifier.MinifyError, match="not store-permitted minified"):
        minifier.reject_javascript_evasions("nbsp.js", nbsp)
    inline = "export function start(){const ok=true;/*hide*/return ok}\n"
    with pytest.raises(
        minifier.MinifyError,
        match="not the reproducible esbuild producer output|not store-permitted minified",
    ):
        minifier.reject_packaged_javascript("inline.js", inline)


def test_zwsp_and_colon_source_map_evasions_are_rejected():
    zwsp = "export const ok=true;\n//# sourceMappingURL\u200b=hidden.js.map\n"
    colon = "export const ok=true;\n//# sourceMappingURL:hidden.js.map\n"
    with pytest.raises(minifier.MinifyError, match="source-map"):
        minifier.reject_javascript_evasions("zwsp.js", zwsp)
    with pytest.raises(minifier.MinifyError, match="source-map"):
        minifier.reject_javascript_evasions("colon.js", colon)


def test_sourcemap_javascript_is_rejected():
    with pytest.raises(minifier.MinifyError, match="source-map"):
        minifier.reject_packaged_javascript(
            "mapped.js", "export const ok=true;\n//# sourceMappingURL=app.js.map\n"
        )


def test_obfuscated_javascript_is_rejected():
    with pytest.raises(minifier.MinifyError, match="obfuscation"):
        minifier.reject_packaged_javascript(
            "obf.js", "var _0xabcd=function(){return 1;}\n"
        )


def test_pretty_esbuild_output_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fake = _write_fake_esbuild(tmp_path, "pretty")
    monkeypatch.setattr(minifier, "flatten_noncode_lines", lambda text: text)
    with pytest.raises(minifier.MinifyError, match="not store-permitted minified"):
        minifier.transform_javascript(PRETTY_JS, binary=fake, label="pretty.js")


def test_sourcemap_esbuild_output_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fake = _write_fake_esbuild(tmp_path, "sourcemap")
    with pytest.raises(minifier.MinifyError, match="source map"):
        minifier.transform_javascript(PRETTY_JS, binary=fake, label="mapped.js")


def test_semantic_drift_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fake = _write_fake_esbuild(tmp_path, "drift")
    source = "export const NATIVE_HOST_NAME = 'org.winsvpn.bridge';\n"
    with pytest.raises(minifier.MinifyError, match="dropped string|producer form|token"):
        minifier.transform_javascript(source, binary=fake, label="constants.js")


def test_nondeterminism_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fake = _write_fake_esbuild(tmp_path, "nondet")
    with pytest.raises(minifier.MinifyError, match="not deterministic"):
        minifier.transform_javascript(
            "export const n=1;\n", binary=fake, label="n.js"
        )


def test_skipped_file_is_rejected(
    tmp_path: Path, esbuild_cache: Path, monkeypatch: pytest.MonkeyPatch
):
    pkg = tmp_path / "pkg"
    (pkg / "src" / "core").mkdir(parents=True)
    (pkg / "src" / "core" / "kept.js").write_text(
        "export const ok = true;\n", encoding="utf-8"
    )
    (pkg / "src" / "core" / "left_pretty.js").write_text(PRETTY_JS, encoding="utf-8")
    real = minifier.transform_javascript

    def skip_one(source, *, binary, label):
        if label.endswith("left_pretty.js"):
            return source
        return real(source, binary=binary, label=label)

    monkeypatch.setattr(minifier, "transform_javascript", skip_one)
    engine = minifier.load_engine(cache=esbuild_cache, allow_fetch=False)
    with pytest.raises(
        minifier.MinifyError, match="was skipped by the store size transform"
    ):
        minifier.minify_package_javascript(
            pkg, binary=engine, require_intended=False
        )


def test_source_maps_in_tree_are_rejected(tmp_path: Path, esbuild_cache: Path):
    pkg = tmp_path / "pkg"
    (pkg / "src").mkdir(parents=True)
    (pkg / "src" / "ok.js").write_text("export const ok=true;\n", encoding="utf-8")
    (pkg / "src" / "ok.js.map").write_text("{}", encoding="utf-8")
    engine = minifier.load_engine(cache=esbuild_cache, allow_fetch=False)
    with pytest.raises(minifier.MinifyError, match="source map"):
        minifier.minify_package_javascript(
            pkg, binary=engine, require_intended=False
        )


def test_producer_surface_restores_required_forms(esbuild_cache: Path):
    compact = (
        'export const NATIVE_HOST_NAME="org.winsvpn.bridge";'
        'export const STATE={OFF:"off",PROTECTED:"protected"};'
        'export const STATE_COPY={[STATE.OFF]:{headline:"Off"},'
        '[STATE.PROTECTED]:{headline:"On"}};\n'
    )
    restored = minifier.apply_producer_surface(compact, "constants.js")
    assert minifier.NATIVE_HOST_REQUIRED in restored
    assert restored.split("export const STATE=")[1].startswith("{\nOFF:")
    assert "[STATE.OFF]:" in restored
    minifier.reject_packaged_javascript("restored.js", restored)


def test_staged_package_is_store_minified_and_reproducible(
    tmp_path: Path, esbuild_cache: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv(minifier.CACHE_ENV, str(esbuild_cache))
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    first = builder.stage("chrome")
    second = builder.stage("edge")
    third = builder.stage("firefox")

    def js_map(pkg: Path) -> dict[str, bytes]:
        return {
            path.relative_to(pkg / "src").as_posix(): path.read_bytes()
            for path in sorted((pkg / "src").rglob("*.js"))
        }

    chrome_js = js_map(first)
    assert chrome_js
    assert chrome_js == js_map(second) == js_map(third)
    intended = minifier.intended_javascript_members()
    assert "src/adapters/base.js" in intended
    assert set("src/" + name for name in chrome_js) == intended
    for relative, payload in chrome_js.items():
        text = payload.decode("utf-8")
        authored = (EXT / "src" / relative).read_bytes()
        minifier.reject_packaged_javascript("src/" + relative, text)
        assert payload != authored
        assert minifier.is_pretty_javascript(authored.decode("utf-8"))
        assert not minifier.is_pretty_javascript(text)
        assert b"sourceMappingURL" not in payload
        assert b"javascript-obfuscator" not in payload
    constants = (first / "src" / "core" / "constants.js").read_text(encoding="utf-8")
    assert minifier.NATIVE_HOST_REQUIRED in constants
    assert "api.runtime.connectNative(" in (
        first / "src" / "adapters" / "base.js"
    ).read_text(encoding="utf-8")
    assert "this.adapter.connectNative(NATIVE_HOST_NAME" in (
        first / "src" / "background" / "controller.js"
    ).read_text(encoding="utf-8")


def test_builder_does_not_name_forbidden_minify_flags():
    text = (EXT / "build.py").read_text(encoding="utf-8")
    assert "--minify" not in text
    assert "--sourcemap" not in text
    assert "javascript-obfuscator" not in text
    assert "byte-identical copy of" in text
    assert "No dependencies. Standard library only" in text
    assert 'shutil.copytree(' in text


def test_forbidden_identifier_minify_flags_are_refused_like_minify(
    tmp_path: Path,
):
    fake = _write_fake_esbuild(tmp_path, "ok")
    env = minifier._esbuild_env(tmp_path)
    infile = tmp_path / "input.js"
    infile.write_text("export const ok = true;\n", encoding="utf-8")
    for flag in (
        "--minify",
        "--minify-identifiers",
        "--minify-syntax",
        "--minify-identifiers=true",
        "--minify-syntax=true",
        "--sourcemap",
        "--sourcemap=inline",
    ):
        with pytest.raises(minifier.MinifyError, match="forbidden"):
            minifier.run_esbuild(
                fake,
                [str(infile), flag, f"--outfile={tmp_path / 'out.js'}"],
                env=env,
                cwd=tmp_path,
            )
    minifier.run_esbuild(
        fake,
        [
            str(infile),
            "--minify-whitespace",
            "--legal-comments=none",
            f"--outfile={tmp_path / 'ok.js'}",
        ],
        env=env,
        cwd=tmp_path,
    )


def test_hostile_producer_zip_evasions_fail_closed(esbuild_cache: Path, tmp_path: Path):
    import zipfile

    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    chrome = builder.zip_package(builder.stage("chrome"), "chrome").read_bytes()
    member = "src/core/constants.js"
    with zipfile.ZipFile(io.BytesIO(chrome)) as archive:
        original = archive.read(member)

    def rewrite(replace=None, comment=None, extra=None):
        source = zipfile.ZipFile(io.BytesIO(chrome))
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dest:
            for info in source.infolist():
                data = source.read(info.filename)
                if replace and info.filename in replace:
                    data = replace[info.filename]
                dest.writestr(info.filename, data)
            if extra:
                for name, body in extra.items():
                    dest.writestr(name, body)
            if comment is not None:
                dest.comment = comment
        return out.getvalue()

    cases = (
        rewrite(replace={member: b" " + original}),
        rewrite(
            replace={
                member: b"export function start() {\nconst ok = true;\nreturn ok;\n}\n"
            }
        ),
        rewrite(replace={member: original.replace(b"\n", b"\n\xc2\xa0", 1)}),
        rewrite(replace={member: original + b"\n//# sourceMappingURL:hidden.js.map\n"}),
        rewrite(
            replace={member: original + b"\n//# source Mapping URL = hidden.js.map\n"}
        ),
        rewrite(
            replace={
                member: original
                + "//# sourceMappingURL\u200b=hidden.js.map\n".encode("utf-8")
            }
        ),
        rewrite(comment=b"sourceMappingURL=hidden.js.map"),
        rewrite(comment=b"sourceMappingURL:hidden.js.map"),
        rewrite(replace={member: original + b"\n"}),
        rewrite(replace={member: b"const ok=true;function start(){return 1;}\n"}),
    )
    for payload in cases:
        producer_failed = False
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                minifier.require_zip_javascript_matches_producer(archive)
        except minifier.MinifyError:
            producer_failed = True
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            failures = minifier.zip_hygiene_failures(archive)
        assert producer_failed or failures


def test_whitespace_only_producer_does_not_claim_secret_protection():
    text = (TOOLS / "store_js_minifier.py").read_text(encoding="utf-8")
    assert "does not claim to protect client-held secrets" in text
    assert "--minify-whitespace" in text
    assert "--minify-identifiers" in text
    assert "--minify-syntax" in text
    assert "identifier-mangling --minify-identifiers is forbidden" in text
    assert "identifier-mangling --minify-syntax is forbidden" in text


def test_load_engine_is_byte_stable(esbuild_cache: Path):
    first = minifier.load_engine(cache=esbuild_cache, allow_fetch=False)
    second = minifier.load_engine(cache=esbuild_cache, allow_fetch=False)
    assert first == second
    assert minifier.sha256_file(first) == _pin()["binary_sha256"]
    with tempfile_work() as work:
        minifier.require_esbuild_version(
            first, env=minifier._esbuild_env(work), cwd=work
        )


def test_intended_javascript_members_cover_every_authored_js():
    intended = minifier.intended_javascript_members()
    assert "src/adapters/base.js" in intended
    assert "src/adapters/chromium.js" in intended
    assert "src/adapters/firefox.js" in intended
    assert "src/background/controller.js" in intended
    assert "src/core/constants.js" in intended
    discovered = {
        "src/" + path.relative_to(minifier.EXTENSION_SRC).as_posix()
        for path in minifier.javascript_files(minifier.EXTENSION_SRC)
        if not minifier._ignore_source_name(path.name)
    }
    assert intended == discovered
    for name in sorted(intended):
        authored = (EXT / name).read_bytes()
        assert minifier.is_pretty_javascript(authored.decode("utf-8"))


def test_partial_package_without_intended_members_is_refused(
    tmp_path: Path, esbuild_cache: Path
):
    pkg = tmp_path / "pkg"
    (pkg / "src").mkdir(parents=True)
    (pkg / "src" / "only.js").write_text("export const ok = true;\n", encoding="utf-8")
    engine = minifier.load_engine(cache=esbuild_cache, allow_fetch=False)
    with pytest.raises(
        minifier.MinifyError, match="intended JavaScript members were not staged"
    ):
        minifier.minify_package_javascript(pkg, binary=engine)


def test_skipped_intended_base_js_is_refused(
    tmp_path: Path, esbuild_cache: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv(minifier.CACHE_ENV, str(esbuild_cache))
    monkeypatch.setenv(minifier.FETCH_ENV, "0")
    real = minifier.transform_javascript

    def skip_base(source, *, binary, label):
        if label.endswith("adapters/base.js"):
            return source
        return real(source, binary=binary, label=label)

    monkeypatch.setattr(minifier, "transform_javascript", skip_base)
    builder = _load_builder()
    builder.DIST = tmp_path / "dist"
    with pytest.raises(
        minifier.MinifyError, match="was skipped by the store size transform"
    ):
        builder.stage("chrome")
    minifier.reset_producer_javascript_cache()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
