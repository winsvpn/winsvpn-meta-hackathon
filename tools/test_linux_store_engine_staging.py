#!/usr/bin/env python3
"""Offline Linux Snap/Flatpak engine staging: clean success and hostile binds.

Real Linux ELF compile of Winn/AWG/Xray is still pending GCP. These tests
bind sources and install synthetic payloads only.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
BIND_PATH = ROOT / "linux/packaging/store_engine_bind.py"
PRODUCER = ROOT / "tools/build_linux_release.sh"
WINN = ROOT / "tools/build_winn_protocol_engine.sh"
XRAY = ROOT / "tools/build_xray_engine.sh"
STAGE = ROOT / "linux/packaging/stage_store_engines.sh"
XRAY_LICENSE = ROOT / "installer/windows/licenses/Xray-core-MPL-2.0.txt"


def _load_bind():
    spec = importlib.util.spec_from_file_location(
        "_winsvpn_test_store_engine_bind", BIND_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load store engine binder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BIND = _load_bind()
XRAY_LICENSE_BYTES = XRAY_LICENSE.read_bytes()


def synthetic_elf64(machine: int) -> bytes:
    data = bytearray(64)
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        2,
        machine,
        1,
        0,
        0,
        0,
        0,
        64,
        56,
        0,
        0,
        0,
        0,
    )
    return bytes(data)


def _write_go_archive(path: pathlib.Path, machine: int, *, members=None) -> str:
    buffer = io.BytesIO()
    go_bin = synthetic_elf64(machine)
    version = b"go1.27.1\n"
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        if members is None:
            members = (
                ("go/bin/go", go_bin, 0o755, tarfile.REGTYPE, ""),
                ("go/VERSION", version, 0o644, tarfile.REGTYPE, ""),
            )
        for name, payload, mode, kind, linkname in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload) if kind == tarfile.REGTYPE else 0
            info.mode = mode
            info.type = kind
            info.linkname = linkname
            archive.addfile(info, io.BytesIO(payload) if payload else None)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = buffer.getvalue()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _xray_fixture_tar_bytes() -> bytes:
    buffer = io.BytesIO()
    prefix = BIND.CONTRACT.XRAY_SOURCE_STRIP_PREFIX
    go_mod = b"module github.com/xtls/xray-core\n"
    with tarfile.open(
        fileobj=buffer, mode="w:gz", format=tarfile.USTAR_FORMAT
    ) as archive:
        directory = tarfile.TarInfo(prefix)
        directory.type = tarfile.DIRTYPE
        directory.size = 0
        archive.addfile(directory)
        for name, payload in (
            (f"{prefix}/LICENSE", XRAY_LICENSE_BYTES),
            (f"{prefix}/go.mod", go_mod),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _layout_xray(xray: pathlib.Path) -> str:
    pin = BIND.CONTRACT.xray_owner_tree_sha256_from_archive_bytes(
        _xray_fixture_tar_bytes()
    )
    xray.mkdir()
    (xray / "LICENSE").write_bytes(XRAY_LICENSE_BYTES)
    (xray / "go.mod").write_text(
        "module github.com/xtls/xray-core\n", encoding="ascii"
    )
    (xray / BIND.CONTRACT.XRAY_IDENTITY_RELATIVE).write_text(
        BIND.CONTRACT.XRAY_IDENTITY_TEXT, encoding="ascii"
    )
    tree = BIND.hash_regular_tree(xray, "fixture Xray tree")
    if tree != pin:
        raise RuntimeError("fixture Xray layout does not match owner-tree pin")
    return pin


def _write_source_root(root: pathlib.Path, arch: str) -> dict[str, str]:
    machine = 62 if arch == "x64" else 183
    go_digest = _write_go_archive(
        root / "go-sdk" / BIND.go_archive_name(arch), machine
    )
    cache = root / "go-mod-cache" / "cache" / "download" / "example.org" / "mod"
    cache.mkdir(parents=True)
    (cache / "@v").mkdir()
    (cache / "@v" / "v0.0.0.mod").write_text(
        "module example.org/mod\n", encoding="ascii"
    )
    xray = root / "xray-core"
    xray_tree = _layout_xray(xray)
    if arch == "arm64":
        prebuilt = root / "awg-prebuilt"
        prebuilt.mkdir()
        (prebuilt / "awg").write_bytes(synthetic_elf64(183))
        (prebuilt / "awg-quick").write_bytes(b"#!/bin/sh\nexit 0\n")
        (prebuilt / "awg").chmod(0o755)
        (prebuilt / "awg-quick").chmod(0o755)
    (root / "amneziawg-go").mkdir()
    (root / ".winsvpn-store-fixture").write_text("must-not-relax-pins\n", encoding="ascii")
    module_tree = BIND.hash_regular_tree(root / "go-mod-cache", "fixture module tree")
    pins = {
        "go": go_digest,
        "module": module_tree,
        "xray": xray_tree,
        "license": hashlib.sha256(XRAY_LICENSE_BYTES).hexdigest(),
    }
    if arch == "arm64":
        pins["awg"] = hashlib.sha256((root / "awg-prebuilt" / "awg").read_bytes()).hexdigest()
        pins["quick"] = hashlib.sha256(
            (root / "awg-prebuilt" / "awg-quick").read_bytes()
        ).hexdigest()
    return pins


def _payloads(directory: pathlib.Path, machine: int) -> dict[str, pathlib.Path]:
    directory.mkdir(parents=True, exist_ok=True)
    files = {
        "winn-datapath": synthetic_elf64(machine),
        "awg": synthetic_elf64(machine),
        "awg-quick": b"#!/bin/sh\nexit 0\n",
        "amneziawg-go": synthetic_elf64(machine),
        "xray": synthetic_elf64(machine),
    }
    out: dict[str, pathlib.Path] = {}
    for name, payload in files.items():
        path = directory / name
        path.write_bytes(payload)
        path.chmod(0o755)
        out[name] = path
    return out


def _prepare_kwargs(pins: dict[str, str], arch: str) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "expected_go_archive_sha256": pins["go"],
        "expected_module_tree_sha256": pins["module"],
        "expected_xray_tree_sha256": pins["xray"],
        "expected_xray_license_sha256": pins["license"],
        "require_go_elf": False,
    }
    if arch == "arm64":
        kwargs["expected_awg_sha256"] = pins["awg"]
        kwargs["expected_quick_sha256"] = pins["quick"]
    return kwargs


class LinuxStoreEngineStagingTests(unittest.TestCase):
    def test_go_archive_extractor_has_no_version_dependent_extractall_path(self) -> None:
        source = pathlib.Path(BIND.__file__).read_text(encoding="utf-8")
        self.assertNotIn("extractall(", source)
        self.assertNotIn("tarfile.data_filter", source)
        self.assertIn("_extract_validated_members", source)

    def setUp(self) -> None:
        self._socket_patch = mock.patch(
            "socket.socket", side_effect=AssertionError("network")
        )
        self._socket_patch.start()
        self.addCleanup(self._socket_patch.stop)

    def test_builders_keep_store_offline_and_nonstore_gomodcache_strings(self) -> None:
        producer = PRODUCER.read_text(encoding="utf-8")
        winn = WINN.read_text(encoding="utf-8")
        xray = XRAY.read_text(encoding="utf-8")
        self.assertIn("linux/packaging/store_engine_bind.py", producer)
        self.assertIn("python3 -I", producer)
        self.assertIn('python3 -I "${ROOT}/linux/packaging/store_engine_bind.py"', producer)
        self.assertIn("export GOPROXY=off", producer)
        self.assertIn('export GOMODCACHE="${WINS_STORE_GOMODCACHE:?}"', producer)
        self.assertIn('export GOCACHE="${WINS_STORE_GOCACHE:?}"', producer)
        self.assertLess(
            producer.index('export GOCACHE="${WINS_STORE_GOCACHE:?}"'),
            producer.index("Building mandatory Winn Protocol v3 engine"),
        )
        self.assertIn("winsvpn_install_bound_engine", producer)
        self.assertIn("winsvpn_stage_bound_engine", producer)
        self.assertIn(
            'winsvpn_stage_bound_engine "$tmp_dir/awg" "$dest_abs/awg" "awg"',
            producer,
        )
        self.assertIn(
            'winsvpn_stage_bound_engine "$tmp_dir/xray/xray" "$dest_abs/xray" "xray"',
            producer,
        )
        self.assertIn(
            'winn_digest="$(winsvpn_sha256_bind_file "$tmp_dir/winn/winn-datapath")"',
            producer,
        )
        self.assertIn(
            'installed_winn="$(winsvpn_install_bound_engine "$tmp_dir/winn/winn-datapath" "$dest_abs/winn-datapath" "winn-datapath")"',
            producer,
        )
        self.assertIn("export GOSUMDB=off", producer)
        self.assertIn("WINS_STORE_GOMODCACHE", winn)
        self.assertIn("GOPROXY=off", winn)
        self.assertIn('export GOMODCACHE="${WORK_ROOT}/go-mod-cache"', xray)
        self.assertIn("declared Go SDK must be archive-bound before Xray build", xray)
        self.assertIn("XRAY_IDENTITY_SHA256", xray)
        self.assertIn("XRAY_LICENSE_SHA256", xray)
        self.assertIn("XRAY_SOURCE_TREE_SHA256", xray)
        self.assertIn("hash_regular_tree", xray)
        self.assertIn("Xray source tree does not match the authenticated identity", xray)
        self.assertIn("filter=\"data\"", xray)
        self.assertIn("describe --always --dirty", xray)
        self.assertNotIn("${WINS_ENGINE_SOURCE_ROOT}/go-sdk/go/bin/go", xray)
        self.assertIn("clang version 14.0.6", producer)
        self.assertIn("awg-prebuilt", producer)
        self.assertIn("winsvpn_sha256_bind_file", producer)
        self.assertNotIn("fixture_pins_allowed", BIND_PATH.read_text(encoding="utf-8"))
        self.assertNotIn('"unittest" in sys.modules', BIND_PATH.read_text(encoding="utf-8"))
        binder = BIND_PATH.read_text(encoding="utf-8")
        self.assertNotIn("--go-archive-sha256", binder)
        self.assertNotIn("--module-tree-sha256", binder)
        self.assertNotIn("--xray-tree-sha256", binder)
        self.assertIn("CC=\"${AWG_ARM64_CLANG}\"", producer)
        self.assertIn("/usr/bin/clang", producer)
        self.assertIn("arm64 AWG clang must be the package executable", producer)
        self.assertIn("io.BytesIO(payload)", binder)
        self.assertIn("ARCHIVE_BYTES_MAX", binder)
        self.assertNotIn("os.lseek(fd, 0, os.SEEK_SET)", binder)
        self.assertNotIn("os.fdopen(fd, \"rb\")", binder)
        self.assertNotIn("return str(invoked_path)", binder)

    def test_clean_offline_stage_isolated_offline_installs_winn_then_awg_then_xray(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "arm64")
            tmp = base / "bind-tmp"
            tmp.mkdir()
            dest = base / "stage"
            dest.mkdir()
            payloads = _payloads(base / "payloads", 183)
            order: list[str] = []
            real_install = BIND.install_bound_payload

            def record(source_path, dest_path, label, mode=0o755):
                if label in (
                    "winn-datapath",
                    "awg",
                    "awg-quick",
                    "amneziawg-go",
                    "xray",
                ):
                    order.append(label)
                return real_install(source_path, dest_path, label, mode=mode)

            with mock.patch.object(BIND, "install_bound_payload", record):
                env = BIND.stage_isolated_offline(
                    source,
                    dest,
                    "arm64",
                    payloads,
                    tmp=tmp,
                    repo=ROOT,
                    **_prepare_kwargs(pins, "arm64"),
                )
            self.assertEqual(
                order, ["winn-datapath", "awg", "awg-quick", "amneziawg-go", "xray"]
            )
            self.assertEqual(env["GOPROXY"], "off")
            self.assertNotEqual(
                env["WINS_STORE_GOMODCACHE"],
                str(pathlib.Path.home() / "go" / "pkg" / "mod"),
            )
            self.assertEqual(env["WINS_RELEASE_GO_TREE_SHA256"], pins["go"])
            self.assertEqual(env["XRAY_BUILD_COMMID"], "v26.9.30")
            self.assertEqual(env["WINN_DATAPATH_BIND"], BIND.WINN_DATAPATH_BIND)
            self.assertEqual(env["XRAY_SOURCE_TREE_SHA256"], pins["xray"])
            self.assertEqual(env["WINS_STORE_GOMODCACHE_TREE_SHA256"], pins["module"])
            isolated_gocache = pathlib.Path(env["GOCACHE"])
            self.assertTrue(isolated_gocache.is_dir())
            self.assertEqual(env["WINS_STORE_GOCACHE"], env["GOCACHE"])
            for name in ("winn-datapath", "awg", "awg-quick", "amneziawg-go", "xray"):
                self.assertTrue((dest / name).is_file())
                self.assertFalse((dest / name).is_symlink())

    def test_production_prepare_cli_uses_isolated_module_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "x64")
            tmp = base / "bind-tmp"
            tmp.mkdir()
            previous_mod = os.environ.get("GOMODCACHE")
            previous_go = os.environ.get("GOCACHE")
            previous_proxy = os.environ.get("GOPROXY")
            os.environ["GOMODCACHE"] = str(base / "hostile-host-cache")
            os.environ["GOCACHE"] = str(base / "hostile-go-cache")
            os.environ["GOPROXY"] = "https://proxy.golang.org,direct"
            try:
                env = BIND.prepare(
                    source,
                    tmp,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )
            finally:
                if previous_mod is None:
                    os.environ.pop("GOMODCACHE", None)
                else:
                    os.environ["GOMODCACHE"] = previous_mod
                if previous_go is None:
                    os.environ.pop("GOCACHE", None)
                else:
                    os.environ["GOCACHE"] = previous_go
                if previous_proxy is None:
                    os.environ.pop("GOPROXY", None)
                else:
                    os.environ["GOPROXY"] = previous_proxy
            self.assertEqual(env["GOPROXY"], "off")
            self.assertNotEqual(
                env["WINS_STORE_GOMODCACHE"], str(base / "hostile-host-cache")
            )
            self.assertNotEqual(env["GOCACHE"], str(base / "hostile-go-cache"))
            self.assertEqual(env["WINS_RELEASE_GO_TREE_SHA256"], pins["go"])
            self.assertEqual(env["XRAY_SOURCE_TREE_SHA256"], pins["xray"])
            self.assertEqual(
                env["XRAY_SOURCE_TREE_SHA256"],
                BIND.CONTRACT.xray_owner_tree_sha256_from_archive_bytes(
                    _xray_fixture_tar_bytes()
                ),
            )

    def test_prepare_without_fixture_hash_refuses_unauthenticated_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary) / "engine-sources"
            source.mkdir()
            _write_source_root(source, "x64")
            tmp = pathlib.Path(temporary) / "bind-tmp"
            tmp.mkdir()
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(BIND_PATH),
                    "prepare",
                    "--source-root",
                    str(source),
                    "--tmp",
                    str(tmp),
                    "--arch",
                    "x64",
                    "--repo",
                    str(ROOT),
                    "--out-env",
                    str(pathlib.Path(temporary) / "env"),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 65, completed.stdout)
            self.assertIn("STORE ENGINE BIND ERROR", completed.stderr)
            self.assertIn("owner input required", completed.stderr)
            self.assertRegex(
                completed.stderr,
                r"reviewed (Xray source|Go module cache) archive is absent",
            )

    def test_hostile_dirty_host_module_cache_is_isolated_or_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "x64")
            attacker = base / "hostile-mod"
            attacker.mkdir()
            (attacker / "evil").mkdir()
            (attacker / "evil" / "payload").write_text("stolen\n", encoding="ascii")
            tmp = base / "bind-tmp"
            tmp.mkdir()
            previous = os.environ.get("GOMODCACHE")
            os.environ["GOMODCACHE"] = str(attacker)
            try:
                env = BIND.prepare(
                    source,
                    tmp,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )
            finally:
                if previous is None:
                    os.environ.pop("GOMODCACHE", None)
                else:
                    os.environ["GOMODCACHE"] = previous
            isolated = pathlib.Path(env["WINS_STORE_GOMODCACHE"])
            self.assertTrue(isolated.is_dir())
            self.assertNotEqual(isolated.resolve(), attacker.resolve())
            self.assertFalse((isolated / "evil").exists())
            self.assertTrue(
                (isolated / "cache" / "download" / "example.org" / "mod" / "@v" / "v0.0.0.mod").is_file()
            )

            home_tmp = base / "bind-home"
            home_tmp.mkdir()
            os.environ["GOMODCACHE"] = str(pathlib.Path.home() / "go" / "pkg" / "mod")
            try:
                with self.assertRaisesRegex(
                    BIND.StoreEngineBindError, BIND.HOST_GOMODCACHE_REFUSAL
                ):
                    BIND.prepare(
                        source,
                        home_tmp,
                        "x64",
                        repo=ROOT,
                        **_prepare_kwargs(pins, "x64"),
                    )
            finally:
                if previous is None:
                    os.environ.pop("GOMODCACHE", None)
                else:
                    os.environ["GOMODCACHE"] = previous

    def test_hostile_version_wrapper_without_archive_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary) / "engine-sources"
            wrapper = source / "go-sdk" / "go" / "bin" / "go"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text(
                "#!/bin/sh\nprintf 'go version go1.27.1 linux/arm64\\n'\n",
                encoding="ascii",
            )
            wrapper.chmod(0o755)
            (source / "go-mod-cache").mkdir()
            (source / "go-mod-cache" / "keep").write_text("x\n", encoding="ascii")
            xray = source / "xray-core"
            xray.mkdir()
            (xray / ".winsvpn-xray-identity").write_text(
                BIND.CONTRACT.XRAY_IDENTITY_TEXT, encoding="ascii"
            )
            tmp = pathlib.Path(temporary) / "tmp"
            tmp.mkdir()
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, BIND.GO_WRAPPER_REFUSAL
            ):
                BIND.bind_go_archive(source, tmp, "arm64", require_elf=False)

    def test_hostile_winn_datapath_symlink_path_swap_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "arm64")
            real = base / "real-winn"
            real.write_bytes(synthetic_elf64(183))
            swapped = base / "payloads"
            swapped.mkdir()
            payloads = _payloads(swapped, 183)
            payloads["winn-datapath"].unlink()
            payloads["winn-datapath"].symlink_to(real)
            dest = base / "stage"
            dest.mkdir()
            tmp = base / "tmp"
            tmp.mkdir()
            with self.assertRaisesRegex(BIND.StoreEngineBindError, "symbolic link"):
                BIND.stage_isolated_offline(
                    source,
                    dest,
                    "arm64",
                    payloads,
                    tmp=tmp,
                    repo=ROOT,
                    **_prepare_kwargs(pins, "arm64"),
                )

    def test_hostile_wrong_hash_link_archive_extracts_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            outside = base / "outside.txt"
            outside.write_text("secret\n", encoding="ascii")
            archive = source / "go-sdk" / BIND.go_archive_name("x64")
            _write_go_archive(
                archive,
                62,
                members=(
                    ("go/bin/go", b"", 0o777, tarfile.SYMTYPE, str(outside)),
                    ("escape", b"", 0o777, tarfile.SYMTYPE, "../../outside.txt"),
                ),
            )
            tmp = base / "tmp"
            tmp.mkdir()
            expected = "ab" * 32
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, "SHA-256 verification failed"
            ):
                BIND.bind_go_archive(
                    source, tmp, "x64", expected_archive_sha256=expected, require_elf=False
                )
            self.assertFalse((tmp / "go-sdk").exists())
            self.assertEqual(outside.read_text(encoding="ascii"), "secret\n")
            self.assertEqual(list(tmp.iterdir()), [])

    def test_hostile_matching_hash_link_archive_extracts_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            outside = base / "pwned.txt"
            outside.write_text("keep\n", encoding="ascii")
            archive = source / "go-sdk" / BIND.go_archive_name("x64")
            digest = _write_go_archive(
                archive,
                62,
                members=(
                    ("go/bin/go", b"", 0o777, tarfile.SYMTYPE, str(outside)),
                ),
            )
            tmp = base / "tmp"
            tmp.mkdir()
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, "unsafe|link target"
            ):
                BIND.bind_go_archive(
                    source, tmp, "x64", expected_archive_sha256=digest, require_elf=False
                )
            self.assertFalse((tmp / "go-sdk").exists())
            self.assertEqual(outside.read_text(encoding="ascii"), "keep\n")

    def test_hostile_xray_source_symlink_path_swap_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "x64")
            real = source / "xray-core"
            swapped = source / "xray-swapped"
            real.rename(swapped)
            real.symlink_to(swapped)
            tmp = base / "tmp"
            tmp.mkdir()
            with self.assertRaisesRegex(BIND.StoreEngineBindError, "symbolic link"):
                BIND.prepare(
                    source,
                    tmp,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )

    def test_hostile_xray_tree_swap_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "x64")
            (source / "xray-core" / "main.go").write_text("package swapped\n", encoding="ascii")
            tmp = base / "tmp"
            tmp.mkdir()
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, "Xray source tree does not match"
            ):
                BIND.prepare(
                    source,
                    tmp,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )

    def test_hostile_module_tree_corruption_and_extra_files_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "x64")
            extra = (
                source / "go-mod-cache" / "cache" / "download" / "evil.org" / "mod"
            )
            extra.mkdir(parents=True)
            (extra / "payload").write_text("corrupt\n", encoding="ascii")
            tmp = base / "tmp"
            tmp.mkdir()
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, "Go module closure tree does not match"
            ):
                BIND.prepare(
                    source,
                    tmp,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )
            shutil_tmp = base / "tmp-corrupt"
            shutil_tmp.mkdir()
            (extra / "payload").unlink()
            extra.rmdir()
            extra.parent.rmdir()
            mod = (
                source
                / "go-mod-cache"
                / "cache"
                / "download"
                / "example.org"
                / "mod"
                / "@v"
                / "v0.0.0.mod"
            )
            mod.write_text("module evil.org/mod\n", encoding="ascii")
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, "Go module closure tree does not match"
            ):
                BIND.prepare(
                    source,
                    shutil_tmp,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )

    def test_hostile_host_gocache_canary_is_unused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "x64")
            canary_dir = base / "host-gocache"
            canary_dir.mkdir()
            canary = canary_dir / "canary"
            canary.write_text("stolen-build-cache\n", encoding="ascii")
            tmp = base / "tmp"
            tmp.mkdir()
            previous = os.environ.get("GOCACHE")
            os.environ["GOCACHE"] = str(canary_dir)
            try:
                env = BIND.prepare(
                    source,
                    tmp,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )
            finally:
                if previous is None:
                    os.environ.pop("GOCACHE", None)
                else:
                    os.environ["GOCACHE"] = previous
            isolated = pathlib.Path(env["GOCACHE"])
            self.assertTrue(isolated.is_dir())
            self.assertNotEqual(isolated.resolve(), canary_dir.resolve())
            self.assertFalse((isolated / "canary").exists())
            self.assertEqual(canary.read_text(encoding="ascii"), "stolen-build-cache\n")
            self.assertEqual(env["WINS_STORE_GOCACHE"], env["GOCACHE"])

    def test_arm64_clang_or_is_reachable_without_prebuilt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "arm64")
            shutil.rmtree(source / "awg-prebuilt")
            tmp = base / "tmp"
            tmp.mkdir()
            env = BIND.prepare(
                source,
                tmp,
                "arm64",
                repo=ROOT,
                expected_go_archive_sha256=pins["go"],
                expected_module_tree_sha256=pins["module"],
                expected_xray_tree_sha256=pins["xray"],
                expected_xray_license_sha256=pins["license"],
                require_go_elf=False,
                toolchain_probe=lambda: "/usr/bin/clang",
            )
            self.assertEqual(
                env["AWG_ARM64_TOOLCHAIN"],
                "clang-14.0.6/binutils-2.40-2",
            )
            self.assertEqual(env["AWG_ARM64_CLANG"], "/usr/bin/clang")
            self.assertNotIn("AWG_ARM64_PREBUILT", env)

    def test_arm64_wrong_prebuilt_hash_is_refused_and_does_not_fall_through(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "arm64")
            tmp = base / "tmp"
            tmp.mkdir()
            kwargs = _prepare_kwargs(pins, "arm64")
            kwargs["expected_awg_sha256"] = "cd" * 32
            kwargs["toolchain_probe"] = lambda: "/usr/bin/clang"
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, "arm64 AWG prebuilt payload SHA-256"
            ):
                BIND.prepare(
                    source,
                    tmp,
                    "arm64",
                    repo=ROOT,
                    **kwargs,
                )

    def test_hostile_go_archive_path_swap_extracts_hashed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            archive = source / "go-sdk" / BIND.go_archive_name("x64")
            digest = _write_go_archive(archive, 62)
            original = archive.read_bytes()
            tmp = base / "tmp"
            tmp.mkdir()
            real_open = os.open
            opened = {"count": 0}

            def swapping_open(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                if os.path.abspath(path) == os.path.abspath(archive):
                    opened["count"] += 1
                    if opened["count"] == 1:
                        archive.unlink()
                        archive.write_bytes(b"EVIL-ARCHIVE-BYTES" * 64)
                return fd

            with mock.patch.object(BIND.os, "open", swapping_open):
                env = BIND.bind_go_archive(
                    source,
                    tmp,
                    "x64",
                    expected_archive_sha256=digest,
                    require_elf=False,
                )
            self.assertEqual(opened["count"], 1)
            self.assertEqual(env["WINS_RELEASE_GO_TREE_SHA256"], digest)
            go_bin = pathlib.Path(env["LINUX_REVIEWED_GO_BIN"])
            self.assertTrue(go_bin.is_file())
            self.assertEqual(go_bin.read_bytes()[:4], b"\x7fELF")
            self.assertEqual(archive.read_bytes(), b"EVIL-ARCHIVE-BYTES" * 64)
            self.assertNotEqual(original, archive.read_bytes())

    def test_hostile_same_inode_same_size_overwrite_does_not_change_go_extract(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            archive = source / "go-sdk" / BIND.go_archive_name("x64")
            digest = _write_go_archive(archive, 62)
            original = archive.read_bytes()
            original_elf = synthetic_elf64(62)
            evil_archive = base / "evil.tar.gz"
            _write_go_archive(
                evil_archive,
                62,
                members=(
                    (
                        "go/bin/go",
                        b"EVILGO-NOT-ELF",
                        0o755,
                        tarfile.REGTYPE,
                        "",
                    ),
                ),
            )
            evil = evil_archive.read_bytes()
            self.assertLess(len(evil), len(original))
            padded_evil = evil + (b"\x00" * (len(original) - len(evil)))
            self.assertEqual(len(padded_evil), len(original))
            tmp = base / "tmp"
            tmp.mkdir()
            real_open = os.open
            real_read = os.read
            real_lseek = os.lseek
            real_fdopen = os.fdopen
            real_close = os.close
            archive_fds: set[int] = set()
            read_from_archive = {"n": 0}
            overwritten = {"count": 0}
            opened = {"count": 0}

            def overwrite_same_inode() -> None:
                fd = real_open(str(archive), os.O_WRONLY)
                try:
                    written = os.write(fd, padded_evil)
                    if written != len(padded_evil):
                        raise AssertionError("same-inode overwrite truncated")
                finally:
                    real_close(fd)
                overwritten["count"] += 1

            def tracking_open(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                if os.path.abspath(path) == os.path.abspath(archive):
                    if flags & os.O_WRONLY:
                        return fd
                    archive_fds.add(fd)
                    opened["count"] += 1
                return fd

            def tracking_close(fd):
                archive_fds.discard(fd)
                return real_close(fd)

            def hostile_read(fd, n):
                block = real_read(fd, n)
                if fd in archive_fds:
                    read_from_archive["n"] += len(block)
                    if (
                        read_from_archive["n"] >= len(original)
                        and overwritten["count"] == 0
                    ):
                        overwrite_same_inode()
                return block

            def hostile_lseek(fd, pos, how):
                if fd in archive_fds:
                    overwrite_same_inode()
                return real_lseek(fd, pos, how)

            def hostile_fdopen(fd, *args, **kwargs):
                if fd in archive_fds:
                    overwrite_same_inode()
                return real_fdopen(fd, *args, **kwargs)

            with mock.patch.object(BIND.os, "open", tracking_open):
                with mock.patch.object(BIND.os, "read", hostile_read):
                    with mock.patch.object(BIND.os, "close", tracking_close):
                        with mock.patch.object(BIND.os, "lseek", hostile_lseek):
                            with mock.patch.object(BIND.os, "fdopen", hostile_fdopen):
                                env = BIND.bind_go_archive(
                                    source,
                                    tmp,
                                    "x64",
                                    expected_archive_sha256=digest,
                                    require_elf=False,
                                )
            self.assertEqual(opened["count"], 1)
            self.assertGreaterEqual(overwritten["count"], 1)
            self.assertEqual(env["WINS_RELEASE_GO_TREE_SHA256"], digest)
            go_bin = pathlib.Path(env["LINUX_REVIEWED_GO_BIN"])
            self.assertTrue(go_bin.is_file())
            self.assertEqual(go_bin.read_bytes(), original_elf)
            self.assertNotIn(b"EVILGO-NOT-ELF", go_bin.read_bytes())
            self.assertEqual(archive.read_bytes(), padded_evil)
            self.assertNotEqual(original, archive.read_bytes())

    def test_hostile_xray_identity_layout_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "x64")
            identity = source / "xray-core" / BIND.CONTRACT.XRAY_IDENTITY_RELATIVE
            identity.unlink()
            tmp = base / "tmp"
            tmp.mkdir()
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, BIND.XRAY_IDENTITY_MISSING
            ):
                BIND.prepare(
                    source,
                    tmp,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )
            identity.write_text("commit=deadbeef\ntag=evil\nbuild=evil\n", encoding="ascii")
            swapped = base / "tmp-wrong-identity"
            swapped.mkdir()
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, BIND.XRAY_IDENTITY_MISSING
            ):
                BIND.prepare(
                    source,
                    swapped,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )
            identity.unlink()
            identity.symlink_to(source / "xray-core" / "LICENSE")
            linked = base / "tmp-identity-link"
            linked.mkdir()
            with self.assertRaisesRegex(BIND.StoreEngineBindError, "symbolic link"):
                BIND.prepare(
                    source,
                    linked,
                    "x64",
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )
            identity.unlink()
            identity.write_text(
                BIND.CONTRACT.XRAY_IDENTITY_TEXT, encoding="ascii"
            )
            tar_only = BIND.hash_regular_tree(source / "xray-core", "with identity")
            identity.unlink()
            without_identity = BIND.hash_regular_tree(
                source / "xray-core", "tar-only layout"
            )
            identity.write_text(
                BIND.CONTRACT.XRAY_IDENTITY_TEXT, encoding="ascii"
            )
            self.assertNotEqual(tar_only, without_identity)
            self.assertEqual(tar_only, pins["xray"])
            kwargs = _prepare_kwargs(pins, "x64")
            kwargs["expected_xray_tree_sha256"] = without_identity
            tar_only_tmp = base / "tmp-tar-only-pin"
            tar_only_tmp.mkdir()
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, "Xray source tree does not match"
            ):
                BIND.prepare(
                    source,
                    tar_only_tmp,
                    "x64",
                    repo=ROOT,
                    **kwargs,
                )

    def test_hostile_destination_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "x64")
            dest = base / "stage"
            dest.mkdir()
            outside = base / "outside-xray"
            outside.write_bytes(synthetic_elf64(62))
            (dest / "xray").symlink_to(outside)
            payloads = _payloads(base / "payloads", 62)
            tmp = base / "tmp"
            tmp.mkdir()
            with self.assertRaisesRegex(BIND.StoreEngineBindError, "already exists|symbolic link"):
                BIND.stage_isolated_offline(
                    source,
                    dest,
                    "x64",
                    payloads,
                    tmp=tmp,
                    repo=ROOT,
                    **_prepare_kwargs(pins, "x64"),
                )
            self.assertEqual(outside.read_bytes()[:4], b"\x7fELF")
            self.assertTrue((dest / "xray").is_symlink())

    def test_path_clang_canary_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            canary_dir = base / "bin"
            canary_dir.mkdir()
            canary = canary_dir / "clang"
            canary.write_text(
                "#!/bin/sh\nprintf 'clang version 14.0.6\\n'\n",
                encoding="ascii",
            )
            canary.chmod(0o755)
            dpkg = canary_dir / "dpkg-query"
            dpkg.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            dpkg.chmod(0o755)

            def fake_which(name, path=None):
                if name == "clang":
                    return str(canary)
                if name == "dpkg-query":
                    return str(dpkg)
                return None

            def fake_run(argv, **kwargs):
                if argv[0] == str(canary):
                    return subprocess.CompletedProcess(
                        argv, 0, stdout="clang version 14.0.6\n", stderr=""
                    )
                if argv[0] == str(dpkg) and "clang" in argv:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout=BIND.CONTRACT.REVIEWED_CLANG_PACKAGE,
                        stderr="",
                    )
                if argv[0] == str(dpkg) and "binutils" in argv:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout=BIND.CONTRACT.REVIEWED_BINUTILS_PACKAGE,
                        stderr="",
                    )
                raise AssertionError(argv)

            with mock.patch.object(BIND.shutil, "which", fake_which):
                with mock.patch.object(BIND.subprocess, "run", fake_run):
                    bound = BIND._probe_awg_arm64_toolchain()
            self.assertIsNone(bound)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "arm64")
            shutil.rmtree(source / "awg-prebuilt")
            tmp = base / "tmp"
            tmp.mkdir()
            with mock.patch.object(BIND.shutil, "which", fake_which):
                with mock.patch.object(BIND.subprocess, "run", fake_run):
                    with self.assertRaisesRegex(
                        BIND.StoreEngineBindError, BIND.AWG_TOOLCHAIN_REFUSAL
                    ):
                        BIND.prepare(
                            source,
                            tmp,
                            "arm64",
                            repo=ROOT,
                            **_prepare_kwargs(pins, "arm64"),
                        )

    def test_path_clang_replacement_after_probe_exports_package_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            canary_dir = base / "bin"
            canary_dir.mkdir()
            canary = canary_dir / "clang"
            canary.write_text(
                "#!/bin/sh\nprintf 'clang version 14.0.6\\n'\n",
                encoding="ascii",
            )
            canary.chmod(0o755)
            dpkg = canary_dir / "dpkg-query"
            dpkg.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            dpkg.chmod(0o755)
            package_clang = pathlib.Path(BIND.PACKAGE_CLANG_PATH)
            invoked: list[str] = []

            def fake_which(name, path=None):
                if name == "clang":
                    return str(canary)
                if name == "dpkg-query":
                    return str(dpkg)
                return None

            def fake_identity(path, label, *, max_hops=8):
                if label == "PATH clang":
                    return (8, 88, pathlib.Path(canary))
                if label == "package clang":
                    canary.write_text(
                        "#!/bin/sh\nprintf 'clang version 14.0.6\\n'\n"
                        "printf 'REPLACED-AFTER-PROBE\\n'\n",
                        encoding="ascii",
                    )
                    return (8, 88, package_clang)
                raise AssertionError(label)

            def fake_run(argv, **kwargs):
                invoked.append(str(argv[0]))
                if argv[0] == str(canary):
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="clang version 14.0.6\nREPLACED-AFTER-PROBE\n",
                        stderr="",
                    )
                if argv[0] == str(package_clang):
                    return subprocess.CompletedProcess(
                        argv, 0, stdout="clang version 14.0.6\n", stderr=""
                    )
                if argv[0] == str(dpkg) and "clang" in argv:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout=BIND.CONTRACT.REVIEWED_CLANG_PACKAGE,
                        stderr="",
                    )
                if argv[0] == str(dpkg) and "binutils" in argv:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout=BIND.CONTRACT.REVIEWED_BINUTILS_PACKAGE,
                        stderr="",
                    )
                raise AssertionError(argv)

            with mock.patch.object(BIND.shutil, "which", fake_which):
                with mock.patch.object(
                    BIND, "_regular_file_identity", fake_identity
                ):
                    with mock.patch.object(BIND.subprocess, "run", fake_run):
                        bound = BIND._probe_awg_arm64_toolchain()
            self.assertEqual(bound, str(package_clang))
            self.assertNotEqual(bound, str(canary))
            self.assertIn(str(package_clang), invoked)
            self.assertNotIn(str(canary), invoked)
            self.assertIn("REPLACED-AFTER-PROBE", canary.read_text(encoding="ascii"))

            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "arm64")
            shutil.rmtree(source / "awg-prebuilt")
            tmp = base / "tmp"
            tmp.mkdir()
            with mock.patch.object(BIND.shutil, "which", fake_which):
                with mock.patch.object(
                    BIND, "_regular_file_identity", fake_identity
                ):
                    with mock.patch.object(BIND.subprocess, "run", fake_run):
                        env = BIND.prepare(
                            source,
                            tmp,
                            "arm64",
                            repo=ROOT,
                            expected_go_archive_sha256=pins["go"],
                            expected_module_tree_sha256=pins["module"],
                            expected_xray_tree_sha256=pins["xray"],
                            expected_xray_license_sha256=pins["license"],
                            require_go_elf=False,
                        )
            self.assertEqual(env["AWG_ARM64_CLANG"], str(package_clang))
            self.assertNotEqual(env["AWG_ARM64_CLANG"], str(canary))
            self.assertNotIn("AWG_ARM64_PREBUILT", env)

    def test_missing_gosum_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "engine-sources"
            source.mkdir()
            pins = _write_source_root(source, "x64")
            repo = base / "empty-repo"
            (repo / "winn_protocol_experimental").mkdir(parents=True)
            tmp = base / "tmp"
            tmp.mkdir()
            with self.assertRaisesRegex(
                BIND.StoreEngineBindError, BIND.WINN_GOSUM_MISSING
            ):
                BIND.prepare(
                    source,
                    tmp,
                    "x64",
                    repo=repo,
                    **_prepare_kwargs(pins, "x64"),
                )

    def test_stage_engines_wrapper_and_producer_refuse_bundle_and_symlink_dest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dest = (
                pathlib.Path(temporary)
                / "build"
                / "linux"
                / "arm64"
                / "release"
                / "bundle"
            )
            dest.mkdir(parents=True)
            wrapped = subprocess.run(
                ["bash", str(STAGE), str(dest), "arm64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(wrapped.returncode, 65, wrapped.stderr)
            self.assertIn(
                "refusing to stage store engines into a Flutter linux bundle",
                wrapped.stderr,
            )
            link = pathlib.Path(temporary) / "link-stage"
            real = pathlib.Path(temporary) / "real-stage"
            real.mkdir()
            link.symlink_to(real)
            linked = subprocess.run(
                ["bash", str(PRODUCER), "--stage-engines", str(link), "arm64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(linked.returncode, 0, linked.stdout)
            self.assertRegex(
                linked.stderr,
                r"refusing symlink engine destination|refusing architecture-mismatched",
            )


def _producer_functions(*names: str) -> str:
    """Return the exact top-level bash definitions of names from the producer."""
    source = PRODUCER.read_text(encoding="utf-8")
    chunks = []
    for name in names:
        start = source.index(f"\n{name}() {{\n") + 1
        end = source.index("\n}\n", start) + 3
        chunks.append(source[start:end])
    return "".join(chunks)


def _winn_section() -> str:
    source = PRODUCER.read_text(encoding="utf-8")
    start = source.index("  prepare_linux_reviewed_go_for_engines || return $?")
    end = source.index(
        'log "Winn Protocol v3 core/relay roles verified; relay remains scratch-only"',
        start,
    )
    return source[start:end]


WINN_RELEASE_STUB = r'''
import os
import sys

args = sys.argv[1:]
mode = os.environ.get("STUB_MODE", "ok")
if args[:1] != ["verify"] or "--release" not in args or "--print-manifest" not in args \
        or "--print-artifact" in args:
    sys.stderr.write("stub: unexpected argv %r\n" % (args,))
    raise SystemExit(2)
if "--allow-unsigned" in args or "--trust-public-key" in args:
    sys.stderr.write("stub: release staging passed a dev-only flag\n")
    raise SystemExit(2)
release = args[args.index("--release") + 1]
if mode == "toolchain":
    sys.stderr.write("TOOLCHAIN-MISSING: go archive\n")
    raise SystemExit(3)
if mode == "bad-signature":
    sys.stderr.write("signature does not verify\n")
    raise SystemExit(1)
if mode == "unsigned":
    sys.stderr.write("UNSIGNED: dev use only\n")
with open(os.path.join(release, "manifest.json"), "rb") as handle:
    payload = handle.read()
sys.stdout.flush()
sys.stdout.buffer.write(payload * (2 if mode == "two-lines" else 1))
'''


class LinuxWinnReleaseStagingTests(unittest.TestCase):
    """The Winn section of the producer under the sealed release contract."""

    HELPERS = (
        "winsvpn_sha256_bind_file",
        "assert_linux_winn_builder_receipt",
        "resolve_linux_winn_release_dir",
        "run_linux_winn_release_verify",
        "stage_linux_winn_release_artifact",
    )

    def _fake_root(self, base: pathlib.Path) -> pathlib.Path:
        root = base / "repo"
        (root / "tools").mkdir(parents=True)
        (root / "tools" / "winn_release.py").write_text(WINN_RELEASE_STUB, encoding="utf-8")
        return root

    def _release(
        self,
        base: pathlib.Path,
        target: str = "datapath-linux-amd64",
        payload: bytes = b"\x7fELF winn datapath bytes",
        **overrides,
    ) -> pathlib.Path:
        release = (base / "release").resolve()
        name = "winn3-gateway" if target.startswith("winn3-gateway-") else "winn-datapath"
        artifact = release / "artifacts" / target / name
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        entry = {
            "target": target,
            "path": f"artifacts/{target}/{name}",
            "sha256": digest,
            "size": len(payload),
            "header_path": None,
            "header_sha256": None,
            "build_a_sha256": digest,
            "build_b_sha256": digest,
        }
        entry.update(overrides)
        manifest = {
            "contract": "winsvpn-winn-release-manifest-v1",
            "artifacts": [entry],
            "source": {"commit": "a" * 40, "binding": "git-archive", "tree_sha256": "b" * 64},
            "toolchains": {
                "go": {
                    "version": "1.27.1",
                    "archive_sha256": "c" * 64,
                    "install_tree_sha256": "d" * 64,
                    "executable_sha256": "e" * 64,
                }
            },
        }
        (release / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        return release

    def _run(self, root: pathlib.Path, script: str, env_extra=None, args=()):
        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(root),
        }
        env.update(env_extra or {})
        prelude = (
            "set -Eeuo pipefail\n"
            f"ROOT={str(root)!r}\n"
            'python3() { /usr/bin/python3 -I "$@"; }\n'
            + _producer_functions(*self.HELPERS)
        )
        return subprocess.run(
            ["bash", "-c", prelude + script, "_", *args],
            cwd=root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _stage(self, base, root, release, target="datapath-linux-amd64", name="winn-datapath", mode="ok"):
        dest = base / "scratch" / name
        dest.parent.mkdir(exist_ok=True)
        fields = base / "scratch" / f"{name}.fields"
        completed = self._run(
            root,
            'stage_linux_winn_release_artifact "$1" "$2" "$3" "$4" "$5"\n',
            {"STUB_MODE": mode},
            (str(release), target, name, str(dest), str(fields)),
        )
        return completed, dest, fields

    def test_signed_release_bytes_are_copied_and_bound_to_the_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            root = self._fake_root(base)
            payload = b"\x7fELF signed relay bytes"
            release = self._release(base, "winn3-gateway-linux-arm64", payload)
            completed, dest, fields = self._stage(
                base, root, release, "winn3-gateway-linux-arm64", "winn3-gateway"
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(dest.read_bytes(), payload)
            self.assertFalse(dest.is_symlink())
            lines = fields.read_text(encoding="utf-8").splitlines()
            manifest_sha = hashlib.sha256((release / "manifest.json").read_bytes()).hexdigest()
            self.assertEqual(
                lines,
                [
                    hashlib.sha256(payload).hexdigest(),
                    manifest_sha,
                    "b" * 64,
                    "1.27.1",
                    "e" * 64,
                    "d" * 64,
                ],
            )

    def test_release_staging_refuses_every_unverified_input(self) -> None:
        cases = {
            "bad-signature": ({}, "bad-signature", "verification failed for datapath-linux-amd64 (exit 1)"),
            "toolchain": ({}, "toolchain", "needs a missing toolchain"),
            "unsigned": ({}, "unsigned", "reported an unsigned release"),
            "two manifests": ({}, "two-lines", "must print exactly one canonical manifest line"),
            "sha": ({"sha256": "0" * 64, "build_a_sha256": "0" * 64, "build_b_sha256": "0" * 64}, "ok", "do not match the manifest sha256"),
            "two builds differ": ({"build_b_sha256": "1" * 64}, "ok", "two identical builds"),
            "header": ({"header_path": "artifacts/x.h"}, "ok", "lists a header"),
            "size": ({"size": 1}, "ok", "size does not match"),
            "path": ({"path": "artifacts/other/winn-datapath"}, "ok", "is not artifacts/"),
        }
        for label, (overrides, mode, expected) in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as temporary:
                base = pathlib.Path(temporary).resolve()
                root = self._fake_root(base)
                release = self._release(base, **overrides)
                completed, dest, _ = self._stage(base, root, release, mode=mode)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn(expected, completed.stderr)

    def test_real_driver_signed_release_round_trip(self) -> None:
        # The real tools/winn_release.py, with a test authority key pinned in a
        # throwaway copy of tools/. Signed bytes stage; unsigned or tampered
        # releases are refused by the driver itself.
        import base64
        import secrets

        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            root = base / "repo"
            (root / "tools").mkdir(parents=True)
            shutil.copyfile(ROOT / "tools" / "winn_release.py", root / "tools" / "winn_release.py")
            spec = importlib.util.spec_from_file_location(
                "_winsvpn_test_winn_release", root / "tools" / "winn_release.py"
            )
            driver = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(driver)
            seed = secrets.token_bytes(32)
            key = base / "test-authority.pem"
            der = bytes.fromhex("302e020100300506032b657004220420") + seed
            key.write_text(
                "-----BEGIN PRIVATE KEY-----\n"
                + base64.b64encode(der).decode("ascii")
                + "\n-----END PRIVATE KEY-----\n",
                encoding="ascii",
            )
            key.chmod(0o600)
            (root / "tools" / "winn_release_authority.json").write_text(
                json.dumps(
                    {
                        "contract": "winsvpn-winn-release-authority-v1",
                        "algorithm": "ed25519",
                        "public_key": driver.ed25519_public(seed).hex(),
                    }
                ),
                encoding="utf-8",
            )

            def make_release(name: str) -> pathlib.Path:
                release = base / name
                payload = b"\x7fELF real-driver datapath " + name.encode()
                artifact = release / "artifacts" / "datapath-linux-amd64" / "winn-datapath"
                artifact.parent.mkdir(parents=True)
                artifact.write_bytes(payload)
                digest = hashlib.sha256(payload).hexdigest()
                manifest = {
                    "contract": "winsvpn-winn-release-manifest-v1",
                    "source": {
                        "commit": "a" * 40,
                        "binding": "git-archive",
                        "path": "winn_protocol_experimental",
                        "tree_sha256": "b" * 64,
                    },
                    "toolchains": {
                        "go": {
                            "version": "1.27.1",
                            "archive_sha256": "c" * 64,
                            "install_tree_sha256": "d" * 64,
                            "executable_sha256": "e" * 64,
                        },
                        "gomodcache_tree_sha256": "f" * 64,
                        "android_ndk": None,
                        "apple": None,
                    },
                    "skipped_targets": {},
                    "artifacts": [
                        {
                            "target": "datapath-linux-amd64",
                            "path": "artifacts/datapath-linux-amd64/winn-datapath",
                            "sha256": digest,
                            "size": len(payload),
                            "header_path": None,
                            "header_sha256": None,
                            "build_a_sha256": digest,
                            "build_b_sha256": digest,
                        }
                    ],
                }
                (release / "manifest.json").write_bytes(driver.canonical_json(manifest))
                return release

            signed = make_release("signed")
            signing = subprocess.run(
                ["/usr/bin/python3", "-I", str(root / "tools" / "winn_release.py"), "sign",
                 "--release", str(signed), "--key", str(key)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(signing.returncode, 0, signing.stderr)
            self.assertNotIn(seed.hex(), signing.stdout + signing.stderr)
            completed, dest, fields = self._stage(base, root, signed)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                dest.read_bytes(),
                (signed / "artifacts" / "datapath-linux-amd64" / "winn-datapath").read_bytes(),
            )
            self.assertEqual(fields.read_text(encoding="utf-8").splitlines()[2], "b" * 64)

            unsigned = make_release("unsigned")
            shutil.rmtree(base / "scratch")
            completed, _, _ = self._stage(base, root, unsigned)
            self.assertEqual(completed.returncode, 65, completed.stderr)
            self.assertIn("manifest.sig.json is missing", completed.stderr)

            tampered = signed / "artifacts" / "datapath-linux-amd64" / "winn-datapath"
            tampered.chmod(0o644)
            tampered.write_bytes(tampered.read_bytes() + b"x")
            shutil.rmtree(base / "scratch")
            completed, _, _ = self._stage(base, root, signed)
            self.assertEqual(completed.returncode, 65, completed.stderr)
            self.assertIn("does not match the manifest", completed.stderr)

    def test_staged_bytes_are_bound_to_the_verified_manifest_only(self) -> None:
        # The real driver verifies a genuinely signed release; before and after
        # that read the directory holds another engine and a manifest naming
        # it. A digest read from the directory after verification accepts it.
        sys.path.insert(0, str(ROOT / "tools"))
        import winn_release_testkit as testkit

        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            root = base / "repo"
            testkit.install_racing_driver(root / "tools")
            target = "datapath-linux-amd64"
            release, genuine, attacker = testkit.prepare_race(
                base,
                {target: ("winn-datapath", b"\x7fELF genuine signed datapath")},
                {target: ("winn-datapath", b"\x7fELF attacker datapath xxxxx")},
            )
            dest = base / "scratch" / "winn-datapath"
            dest.parent.mkdir()
            completed = self._run(
                root,
                'stage_linux_winn_release_artifact "$1" "$2" "$3" "$4" "$5"\n',
                testkit.race_environment(genuine, attacker),
                (str(release), target, "winn-datapath", str(dest), str(base / "scratch" / "fields")),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("do not match the manifest sha256", completed.stderr)

    def test_release_dir_must_be_absolute_canonical_and_not_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            root = self._fake_root(base)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real)
            for value, expected in (
                ("relative/rel", "must be an absolute path"),
                (str(link), "not a symlink"),
                (str(real) + "/../real", "must already be canonical"),
            ):
                with self.subTest(value):
                    completed = self._run(
                        root,
                        "resolve_linux_winn_release_dir\n",
                        {"WINS_WINN_RELEASE_DIR": value},
                    )
                    self.assertEqual(completed.returncode, 65, completed.stderr)
                    self.assertIn(expected, completed.stderr)
            accepted = self._run(
                root, "resolve_linux_winn_release_dir\n", {"WINS_WINN_RELEASE_DIR": str(real)}
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout.strip(), str(real))

    def test_builder_receipt_binds_target_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            root = self._fake_root(base)
            output = base / "winn-datapath"
            output.write_bytes(b"\x7fELF built")
            digest = hashlib.sha256(output.read_bytes()).hexdigest()
            receipt = "WINN_BUILD_RECEIPT " + json.dumps(
                {
                    "artifact": {"sha256": digest},
                    "contract": "winsvpn-winn-core-build-v4",
                    "target": {"id": "datapath-linux-amd64"},
                }
            )
            good = f"Built Winn Protocol datapath: {output} (datapath-linux-amd64, sha256 {digest})"
            cases = {
                "good": ([receipt, good], 0),
                "wrong digest": ([receipt, good.replace(digest, "0" * 64)], 1),
                "wrong target": ([receipt, good.replace("datapath-linux-amd64", "datapath-linux-arm64")], 1),
                "no receipt": ([good], 1),
                "old contract": ([receipt.replace("v4", "v3"), good], 1),
                "two results": ([receipt, good, good], 1),
                "receipt for another target": ([receipt.replace('"datapath-linux-amd64"', '"datapath-linux-arm64"'), good], 1),
                "receipt for other bytes": ([receipt.replace(digest, "1" * 64), good], 1),
                "duplicate receipt key": ([receipt.replace("{", '{"contract":"x",', 1), good], 1),
            }
            for label, (lines, expected) in cases.items():
                with self.subTest(label):
                    log = base / f"{label}.log"
                    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    completed = self._run(
                        root,
                        f'assert_linux_winn_builder_receipt {str(log)!r} datapath-linux-amd64 {str(output)!r}\n',
                    )
                    self.assertEqual(completed.returncode, expected, completed.stderr)

    def test_winn_section_uses_the_sealed_builder_contract(self) -> None:
        section = _winn_section()
        build = section[section.index("  else\n    mkdir -m 0700 -- \"${tmp_dir}/winn-source\"") :]
        for marker in (
            '"WINS_RELEASE_GO_ROOT=${WINS_RELEASE_GO_ROOT:?}"',
            '"WINS_STORE_GOMODCACHE=${winn_gomodcache}"',
            '"WINS_STORE_GOMODCACHE_TREE_SHA256=${WINS_STORE_GOMODCACHE_TREE_SHA256}"',
            '"WINS_WINN_SOURCE_ROOT=${WINS_WINN_SOURCE_ROOT}"',
            '"WINS_WINN_SOURCE_TREE_SHA256=${WINS_WINN_SOURCE_TREE_SHA256}"',
            'chmod -R a-w -- "${tmp_dir}/winn-source"',
            'chmod -R a-w -- "${tmp_dir}/winn-gomodcache"',
            "Winn builder module cache copy does not match WINS_STORE_GOMODCACHE_TREE_SHA256.",
            'if /usr/bin/env -i "${winn_builder_env[@]}" \\\n'
            '        PATH=/usr/bin:/bin:/usr/sbin:/sbin bash "$ROOT/tools/build_winn_protocol_engine.sh" "${winn_target}"',
            'PATH=/usr/bin:/bin:/usr/sbin:/sbin bash "$ROOT/tools/build_winn_protocol_engine.sh" "${relay_target}"',
            'assert_linux_winn_builder_receipt "$tmp_dir/winn/build.log" "${winn_target}"',
            'assert_linux_winn_builder_receipt "$tmp_dir/winn/relay-build.log" "${relay_target}"',
        ):
            self.assertIn(marker, build)
        # The Winn builder no longer receives the root-sealed Go function.
        self.assertNotIn("export -f wins_release_go_run", section)
        # The builder's exit status is authoritative: only the log echo may
        # swallow a failure.
        invocations = build[
            build.index("winn_builder_env=(") : build.index(
                "Winn Protocol source changed while the core/relay pair"
            )
        ]
        self.assertNotIn("|| true", invocations.replace("2>/dev/null || true", ""))
        # Both sources reach the same gates before install.
        gates = section.index("  # Same gates for built and signed-release bytes.")
        for gate in (
            "assert_release_elf_machine",
            "verify_linux_winn3_datapath_contract",
            "verify_linux_winn3_gateway_role",
            'winn_digest="$(winsvpn_sha256_bind_file "$tmp_dir/winn/winn-datapath")"',
            'relay_digest="$(winsvpn_sha256_bind_file "$tmp_dir/winn/winn3-gateway")"',
        ):
            self.assertGreater(section.index(gate, gates), gates)
        self.assertLess(
            gates,
            section.index('winsvpn_install_bound_engine "$tmp_dir/winn/winn-datapath"'),
        )

    def test_release_mode_requires_signature_and_matching_source(self) -> None:
        section = _winn_section()
        producer = PRODUCER.read_text(encoding="utf-8")
        verify = producer[
            producer.index("run_linux_winn_release_verify() {") : producer.index(
                "stage_linux_winn_release_artifact() {"
            )
        ]
        self.assertIn(
            'python3 -I "${ROOT}/tools/winn_release.py" verify --release "${release_dir}" \\\n'
            '    --print-manifest >"${stdout_path}"',
            verify,
        )
        stage = producer[
            producer.index("stage_linux_winn_release_artifact() {") : producer.index(
                "\n}\n", producer.index("stage_linux_winn_release_artifact() {")
            )
        ]
        # One verification per staged target, and the release manifest is
        # never read again after it.
        self.assertEqual(stage.count("run_linux_winn_release_verify"), 1)
        self.assertNotIn('"${release_dir}/manifest.json"', stage)
        self.assertNotIn('os.path.join(release, "manifest.json")', stage)
        code_lines = [
            line for line in producer.splitlines() if not line.lstrip().startswith("#")
        ]
        for line in code_lines:
            self.assertNotIn("--allow-unsigned", line)
            self.assertNotIn("--trust-public-key", line)
        release = section[
            section.index('if [[ -n "${WINS_WINN_RELEASE_DIR:-}" ]]; then') : section.index(
                "  else\n    mkdir -m 0700 -- \"${tmp_dir}/winn-source\""
            )
        ]
        for marker in (
            'stage_linux_winn_release_artifact "${winn_release_dir}" "${winn_target}" \\\n      "winn-datapath"',
            'stage_linux_winn_release_artifact "${winn_release_dir}" "${relay_target}" \\\n      "winn3-gateway"',
            '[[ "${winn_core_fields[2]}" == "${winn_source_tree_before}" ]]',
            '[[ "${winn_core_fields[3]#go}" == "${GO_VERSION}" ]]',
            "Winn Protocol v3 core and relay must come from one signed release manifest.",
        ):
            self.assertIn(marker, release)
        self.assertNotIn("build_winn_protocol_engine.sh", release)
        self.assertIn(
            '"${winn_digest}" == "${winn_core_fields[0]}" && "${relay_digest}" == "${winn_relay_fields[0]}"',
            section,
        )

    def test_sealed_builder_consumes_spec_inputs(self) -> None:
        # SPEC section 1 inputs the producer hands the builder. Owned by the
        # Arbiter's builder rewrite; red until that builder lands.
        winn = WINN.read_text(encoding="utf-8")
        for token in (
            "WINS_WINN_SOURCE_ROOT",
            "WINS_WINN_SOURCE_TREE_SHA256",
            "WINS_STORE_GOMODCACHE",
            "WINS_STORE_GOMODCACHE_TREE_SHA256",
            "WINS_RELEASE_GO_ROOT",
        ):
            self.assertIn(token, winn)


if __name__ == "__main__":
    unittest.main()
