#!/usr/bin/env python3
"""Regressions for tools/winn_release.py (sealed, reproducible, signed Winn releases)."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import winn_release as wr  # noqa: E402

# RFC 8032 section 7.1, tests 1 and 2 (also reproduced with Go's crypto/ed25519).
RFC_VECTORS = (
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
)
TEST_SEED = bytes(range(32))


def _write_key(path: pathlib.Path, seed: bytes, mode: int = 0o600) -> None:
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    path.write_text("-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PRIVATE KEY-----\n")
    path.chmod(mode)


def _fake_release(directory: pathlib.Path, *, binding: str = "git-archive", skipped: dict | None = None) -> pathlib.Path:
    release = directory / "release"
    (release / "artifacts" / "datapath-linux-arm64").mkdir(parents=True)
    (release / "artifacts" / "datapath-ios-arm64").mkdir(parents=True)
    exe = release / "artifacts" / "datapath-linux-arm64" / "winn-datapath"
    exe.write_bytes(b"\x7fELF fake engine")
    archive = release / "artifacts" / "datapath-ios-arm64" / "libwinn-datapath.a"
    archive.write_bytes(b"!<arch>\nfake")
    header = archive.with_suffix(".h")
    header.write_bytes(b"#ifndef X\n#define X\n#endif\n")
    artifacts = []
    for target, path, head in (("datapath-ios-arm64", archive, header), ("datapath-linux-arm64", exe, None)):
        digest = wr.sha256_file(path)
        artifacts.append({
            "target": target, "path": path.relative_to(release).as_posix(), "sha256": digest,
            "size": path.stat().st_size,
            "header_path": head.relative_to(release).as_posix() if head else None,
            "header_sha256": wr.sha256_file(head) if head else None,
            "build_a_sha256": digest, "build_b_sha256": digest,
        })
    manifest = {
        "contract": wr.MANIFEST_CONTRACT,
        "source": {"binding": binding, "commit": "260da56", "path": "winn_protocol_experimental", "tree_sha256": "0" * 64},
        "skipped_targets": skipped or {},
        "artifacts": artifacts,
    }
    (release / "manifest.json").write_bytes(wr.canonical_json(manifest))
    return release


def _sign_args(release: pathlib.Path, key: pathlib.Path, **flags: bool) -> argparse.Namespace:
    return argparse.Namespace(release=str(release), key=str(key),
                              allow_unpinned_key=flags.get("unpinned", True),
                              allow_export_source=flags.get("export", False),
                              allow_partial=flags.get("partial", False))


def _verify_args(release: pathlib.Path, **kw: object) -> argparse.Namespace:
    return argparse.Namespace(release=str(release), trust_public_key=kw.get("trust"),
                              allow_unsigned=bool(kw.get("unsigned", False)), print_artifact=kw.get("print_artifact"),
                              print_manifest=bool(kw.get("print_manifest", False)))


def _signed_fake_release(tmp: pathlib.Path) -> tuple[pathlib.Path, str]:
    release = _fake_release(tmp)
    key = tmp / "k.pem"
    _write_key(key, TEST_SEED)
    with contextlib.redirect_stdout(io.StringIO()):
        wr.sign_release(_sign_args(release, key))
    return release, wr.ed25519_public(TEST_SEED).hex()


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors(self) -> None:
        for seed, public, message, signature in RFC_VECTORS:
            seed_b, msg = bytes.fromhex(seed), bytes.fromhex(message)
            self.assertEqual(wr.ed25519_public(seed_b).hex(), public)
            self.assertEqual(wr.ed25519_sign(seed_b, msg).hex(), signature)
            self.assertTrue(wr.ed25519_verify(bytes.fromhex(public), msg, bytes.fromhex(signature)))

    def test_verify_rejects_tampering(self) -> None:
        public = wr.ed25519_public(TEST_SEED)
        signature = wr.ed25519_sign(TEST_SEED, b"manifest")
        self.assertTrue(wr.ed25519_verify(public, b"manifest", signature))
        self.assertFalse(wr.ed25519_verify(public, b"manifesT", signature))
        bad = bytearray(signature)
        bad[5] ^= 1
        self.assertFalse(wr.ed25519_verify(public, b"manifest", bytes(bad)))
        # S >= L must be rejected (signature malleability).
        s = int.from_bytes(signature[32:], "little") + wr._L
        self.assertFalse(wr.ed25519_verify(public, b"manifest", signature[:32] + s.to_bytes(32, "little")))

    def test_release_python_owner_verifier_agrees(self) -> None:
        # The ReleasePython v2 owner tooling verifies signatures by the same
        # authority key with its own independently reviewed Ed25519 code.
        import macos_release_python_owner_provision as owner  # type: ignore[import-not-found]
        public = wr.ed25519_public(TEST_SEED)
        message = wr.SIGNATURE_DOMAIN + b"cross-check"
        self.assertTrue(owner.verify_ed25519(public, message, wr.ed25519_sign(TEST_SEED, message)))
        self.assertFalse(owner.verify_ed25519(public, message + b"x", wr.ed25519_sign(TEST_SEED, message)))


class KeyHandlingTests(unittest.TestCase):
    def test_key_must_be_private_regular_pkcs8(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            key = tmp / "k.pem"
            _write_key(key, TEST_SEED, 0o644)
            with self.assertRaisesRegex(wr.ReleaseError, "chmod 600"):
                wr.load_private_seed(key)
            key.chmod(0o600)
            self.assertEqual(wr.load_private_seed(key), TEST_SEED)
            link = tmp / "link.pem"
            link.symlink_to(key)
            with self.assertRaisesRegex(wr.ReleaseError, "not a link"):
                wr.load_private_seed(link)
            other = tmp / "rsa.pem"
            other.write_text("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
            other.chmod(0o600)
            with self.assertRaisesRegex(wr.ReleaseError, "PKCS#8"):
                wr.load_private_seed(other)

    def test_pinned_authority_is_the_release_python_v2_key(self) -> None:
        self.assertEqual(wr.pinned_public_key().hex(),
                         "fac60c882c05f585377dfb16f21e7be71b67bcb2c1539ca9d1d780ed491dd669")


class SignVerifyTests(unittest.TestCase):
    def test_sign_then_verify_round_trip_never_prints_key(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            release = _fake_release(tmp)
            key = tmp / "k.pem"
            _write_key(key, TEST_SEED)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                self.assertEqual(wr.sign_release(_sign_args(release, key)), 0)
            text = out.getvalue()
            self.assertNotIn(TEST_SEED.hex(), text)
            self.assertNotIn(base64.b64encode(TEST_SEED).decode()[:20], text)
            public = wr.ed25519_public(TEST_SEED).hex()
            self.assertIn(public, text)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(wr.verify_release(_verify_args(release, trust=public)), 0)
                # The pinned authority is not the test key, so default trust refuses.
                with self.assertRaisesRegex(wr.ReleaseError, "not the trusted release authority"):
                    wr.verify_release(_verify_args(release))
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                wr.verify_release(_verify_args(release, trust=public, print_artifact="datapath-ios-arm64"))
            lines = out.getvalue().splitlines()
            self.assertEqual(lines, [str(release / "artifacts/datapath-ios-arm64/libwinn-datapath.a"),
                                     str(release / "artifacts/datapath-ios-arm64/libwinn-datapath.h")])
            with self.assertRaisesRegex(wr.ReleaseError, "already exists"):
                wr.sign_release(_sign_args(release, key))

    def test_tampered_artifact_or_manifest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            release = _fake_release(tmp)
            key = tmp / "k.pem"
            _write_key(key, TEST_SEED)
            with contextlib.redirect_stdout(io.StringIO()):
                wr.sign_release(_sign_args(release, key))
            public = wr.ed25519_public(TEST_SEED).hex()
            artifact = release / "artifacts/datapath-linux-arm64/winn-datapath"
            original = artifact.read_bytes()
            artifact.write_bytes(original + b"x")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(wr.ReleaseError, "does not match"):
                wr.verify_release(_verify_args(release, trust=public))
            artifact.write_bytes(original)
            header = release / "artifacts/datapath-ios-arm64/libwinn-datapath.h"
            header.write_bytes(b"#ifndef Y\n")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(wr.ReleaseError, "header"):
                wr.verify_release(_verify_args(release, trust=public))
            header.write_bytes(b"#ifndef X\n#define X\n#endif\n")
            manifest = json.loads((release / "manifest.json").read_text())
            manifest["source"]["commit"] = "deadbee"
            (release / "manifest.json").write_bytes(wr.canonical_json(manifest))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(wr.ReleaseError, "different manifest"):
                wr.verify_release(_verify_args(release, trust=public))

    def test_unsigned_release_needs_explicit_dev_flag(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            release = _fake_release(pathlib.Path(name))
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(wr.ReleaseError, "unsigned"):
                    wr.verify_release(_verify_args(release))
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(wr.verify_release(_verify_args(release, unsigned=True)), 0)
            self.assertIn("UNSIGNED: dev use only", err.getvalue())

    def test_unequal_independent_builds_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            release = _fake_release(pathlib.Path(name))
            manifest = json.loads((release / "manifest.json").read_text())
            manifest["artifacts"][1]["build_b_sha256"] = "f" * 64
            (release / "manifest.json").write_bytes(wr.canonical_json(manifest))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(wr.ReleaseError, "not recorded as identical"):
                wr.verify_release(_verify_args(release, unsigned=True))

    def test_sign_refuses_unpinned_key_export_source_and_partial_release(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            key = tmp / "k.pem"
            _write_key(key, TEST_SEED)
            release = _fake_release(tmp)
            with self.assertRaisesRegex(wr.ReleaseError, "not the pinned release authority"):
                wr.sign_release(_sign_args(release, key, unpinned=False))
            self.assertFalse((release / "manifest.sig.json").exists())
            shutil.rmtree(release)
            release = _fake_release(tmp, binding="export")
            with self.assertRaisesRegex(wr.ReleaseError, "unverified export"):
                wr.sign_release(_sign_args(release, key))
            shutil.rmtree(release)
            release = _fake_release(tmp, skipped={"datapath-android-arm64": "TOOLCHAIN-MISSING"})
            with self.assertRaisesRegex(wr.ReleaseError, "partial release"):
                wr.sign_release(_sign_args(release, key))

    def test_manifest_paths_cannot_escape_the_release(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            release = _fake_release(pathlib.Path(name))
            manifest = json.loads((release / "manifest.json").read_text())
            manifest["artifacts"][1]["path"] = "../outside"
            (release / "manifest.json").write_bytes(wr.canonical_json(manifest))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(wr.ReleaseError, "release-relative"):
                wr.verify_release(_verify_args(release, unsigned=True))


class TreeAndTargetTests(unittest.TestCase):
    def test_sealed_digest_refuses_writable_trees_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name) / "src"
            root.mkdir()
            (root / "go.mod").write_text("module x\n")
            with self.assertRaisesRegex(wr.ReleaseError, "writable"):
                wr.sealed_tree_digest(root)
            wr.seal_tree(root)
            digest = wr.sealed_tree_digest(root)
            line = f"file 9 {hashlib.sha256(b'module x' + bytes([10])).hexdigest()} go.mod\n"
            expected = hashlib.sha256(line.encode()).hexdigest()
            self.assertEqual(digest, expected)
            root.chmod(0o700)
            with self.assertRaisesRegex(wr.ReleaseError, "directory is writable"):
                wr.sealed_tree_digest(root)
            (root / "link").symlink_to("go.mod")
            root.chmod(0o500)
            with self.assertRaisesRegex(wr.ReleaseError, "non-regular"):
                wr.sealed_tree_digest(root)
            wr.remove_tree(root)

    def test_sets_cover_every_app_engine_and_all_thirty_two_targets(self) -> None:
        self.assertEqual(len(wr.SETS["all"]), 32)
        self.assertIn("winn3-relay-windows-arm64", wr.SETS["windows"])
        self.assertEqual(set(wr.SETS["app"]) - set(wr.TARGETS), set())
        self.assertEqual(wr.TARGETS["datapath-android-arm"], ("libwinnengine.so", "ndk"))
        self.assertEqual(wr.TARGETS["datapath-iossimulator-amd64"][1], "xcode")
        with self.assertRaises(wr.ReleaseError):
            wr.select_targets(None, "datapath-linux-arm64,datapath-linux-arm64")
        with self.assertRaises(wr.ReleaseError):
            wr.select_targets("android", "datapath-linux-arm64")
        with self.assertRaises(wr.ReleaseError):
            wr.select_targets(None, "no-such-target")

    def test_builder_has_no_retained_producer_gate(self) -> None:
        builder = (ROOT / "tools" / "build_winn_protocol_engine.sh").read_text()
        for gone in ("WINS_RETAINED_BUILDER", "ReleaseWinnProtocolAuthority", "consumption-ledger",
                     "authorization.json", "OWNER-BLOCKED"):
            self.assertNotIn(gone, builder)
        self.assertIn('exec /usr/bin/python3 -I "${RELEASE_DRIVER}" build-one', builder)

    def test_pins_cover_go_ndk_and_xcode(self) -> None:
        tools = wr.load_pins()
        with mock.patch.object(wr, "host_key", return_value="darwin_arm64"):
            self.assertEqual(wr.go_pins(tools)["version"], tools["go"]["version"])
            self.assertTrue(wr.HEX64.fullmatch(wr.ndk_pins(tools)["install_tree_sha256"]))
        self.assertEqual(set(wr.xcode_pins(tools)), {"version", "build"})
        with mock.patch.object(wr, "host_key", return_value="linux_riscv64"):
            with self.assertRaisesRegex(wr.ReleaseError, "unpinned"):
                wr.go_pins(tools)

    def test_go_executable_pin_is_selected_for_the_build_host(self) -> None:
        darwin, linux, explicit = "1" * 64, "2" * 64, "3" * 64

        def tools(by_platform: object = None) -> dict:
            go = {
                "version": "1.27.1",
                "executable_sha256": darwin,
                "archive_sha256": {"darwin_arm64": "4" * 64, "linux_amd64": "5" * 64},
                "install_tree_sha256": {"darwin_arm64": "6" * 64, "linux_amd64": "7" * 64},
            }
            if by_platform is not None:
                go["executable_sha256_by_platform"] = by_platform
            return {"go": go}

        def pins(host: str, value: dict) -> dict:
            with mock.patch.object(wr, "host_key", return_value=host):
                return wr.go_pins(value)

        # A Linux host uses its own bin/go pin even though the darwin pin exists.
        self.assertEqual(pins("linux_amd64", tools({"linux_amd64": linux}))["executable_sha256"], linux)
        # A Linux host without its own pin refuses; the darwin pin is never borrowed.
        for value in (tools(), tools({"darwin_arm64": explicit})):
            with self.assertRaisesRegex(wr.ReleaseError, "executable_sha256 is missing for linux_amd64"):
                pins("linux_amd64", value)
        # A malformed host entry or table refuses.
        for value, message in (
            (tools({"linux_amd64": "A" * 64}), "executable_sha256 is missing for linux_amd64"),
            (tools({"linux_amd64": None}), "executable_sha256 is missing for linux_amd64"),
            (tools({"darwin_arm64": "not-a-digest"}), "executable_sha256 is missing for darwin_arm64"),
            (tools(["linux_amd64", linux]), "executable_sha256_by_platform must be an object"),
        ):
            host = "darwin_arm64" if "darwin_arm64" in message else "linux_amd64"
            with self.subTest(value=value), self.assertRaisesRegex(wr.ReleaseError, message):
                pins(host, value)
        # darwin_arm64 without its own entry keeps the darwin pin; an explicit entry wins.
        self.assertEqual(pins("darwin_arm64", tools())["executable_sha256"], darwin)
        self.assertEqual(pins("darwin_arm64", tools({"linux_amd64": linux}))["executable_sha256"], darwin)
        self.assertEqual(pins("darwin_arm64", tools({"darwin_arm64": explicit}))["executable_sha256"], explicit)


class GitBindingTests(unittest.TestCase):
    """The commit binding, exercised against a stub git (no real git is run)."""

    def _stub(self, tmp: pathlib.Path, *, head: str, resolved: str, status: str) -> pathlib.Path:
        stub = tmp / "git"
        stub.write_text(
            "#!/bin/sh\n"
            "shift 2\n"
            'case "$1" in\n'
            f'  rev-parse) case "$3" in HEAD*) echo {head} ;; *) echo {resolved} ;; esac ;;\n'
            f"  status) printf '%s' '{status}' ;;\n"
            '  archive) cat "$FAKE_TAR" ;;\n'
            "  *) exit 9 ;;\n"
            "esac\n"
        )
        stub.chmod(0o755)
        return stub

    def test_dirty_or_non_head_commit_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            fake_root = tmp / "repo"
            (fake_root / ".git").mkdir(parents=True)
            head = "a" * 40
            with mock.patch.object(wr, "ROOT", fake_root):
                stub = self._stub(tmp, head=head, resolved=head, status=" M winn_protocol_experimental/go.mod\n")
                with mock.patch.dict(os.environ, {"WINS_WINN_RELEASE_GIT": str(stub)}):
                    with self.assertRaisesRegex(wr.ReleaseError, "dirty"):
                        wr.resolve_commit_and_require_clean(head)
                stub = self._stub(tmp, head=head, resolved="b" * 40, status="")
                with mock.patch.dict(os.environ, {"WINS_WINN_RELEASE_GIT": str(stub)}):
                    with self.assertRaisesRegex(wr.ReleaseError, "is not HEAD"):
                        wr.resolve_commit_and_require_clean("b" * 40)
                stub = self._stub(tmp, head=head, resolved=head, status="")
                with mock.patch.dict(os.environ, {"WINS_WINN_RELEASE_GIT": str(stub)}):
                    self.assertEqual(wr.resolve_commit_and_require_clean(head), head)
            with self.assertRaisesRegex(wr.ReleaseError, "hex commit"):
                wr.resolve_commit_and_require_clean("HEAD~1")

    def test_git_archive_snapshot_is_sealed_and_identical_in_both_copies(self) -> None:
        import tarfile
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            fake_root = tmp / "repo"
            (fake_root / ".git").mkdir(parents=True)
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode="w") as archive:
                for member, data in (("go.mod", b"module x\n"), ("go.sum", b""), ("cmd/main.go", b"package main\n")):
                    info = tarfile.TarInfo(f"winn_protocol_experimental/{member}")
                    info.size = len(data)
                    info.mode = 0o644
                    archive.addfile(info, io.BytesIO(data))
            tar_path = tmp / "src.tar"
            tar_path.write_bytes(payload.getvalue())
            head = "c" * 40
            stub = self._stub(tmp, head=head, resolved=head, status="")
            # git runs with a scrubbed environment, so the stub names the tar directly.
            stub.write_text(stub.read_text().replace('"$FAKE_TAR"', f"'{tar_path}'"))
            work = tmp / "work"
            work.mkdir()
            with mock.patch.object(wr, "ROOT", fake_root), mock.patch.dict(
                    os.environ, {"WINS_WINN_RELEASE_GIT": str(stub), "FAKE_TAR": str(tar_path)}):
                roots, identity = wr.snapshot_source(work, head, None)
            self.assertEqual(identity["binding"], "git-archive")
            self.assertEqual(identity["commit"], head)
            self.assertEqual(len(roots), 2)
            self.assertNotEqual(roots[0], roots[1])
            for root in roots:
                self.assertEqual(wr.sealed_tree_digest(root), identity["tree_sha256"])
                self.assertEqual(stat.S_IMODE((root / "go.mod").stat().st_mode) & 0o222, 0)
            wr.remove_tree(work)

    def test_clean_check_covers_source_and_release_tools(self) -> None:
        for path in ("winn_protocol_experimental", "tools/build_winn_protocol_engine.sh",
                     "tools/winn_release.py", "tools/toolchain-pins.json"):
            self.assertIn(path, wr.CLEAN_PATHS)

    def test_source_archive_members_are_regular_files_only(self) -> None:
        import tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            info = tarfile.TarInfo("winn_protocol_experimental/evil")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaisesRegex(wr.ReleaseError, "refusing source archive member"):
                wr._extract_tar_bytes(buffer.getvalue(), pathlib.Path(name))


class HeldManifestTests(unittest.TestCase):
    """verify takes every digest from the bytes it verified, and can print them."""

    def test_print_manifest_prints_the_verified_bytes_then_artifact_lines(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            release, public = _signed_fake_release(pathlib.Path(name))
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                wr.verify_release(_verify_args(release, trust=public, print_manifest=True,
                                               print_artifact="datapath-linux-arm64"))
            lines = out.getvalue().split("\n")
            self.assertEqual((lines[0] + "\n").encode("ascii"), (release / "manifest.json").read_bytes())
            self.assertEqual(lines[1], str(release / "artifacts/datapath-linux-arm64/winn-datapath"))
            self.assertEqual(lines[2:], [""])

    def test_a_manifest_replaced_after_the_signature_check_is_never_used(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            release, public = _signed_fake_release(tmp)
            genuine = (release / "manifest.json").read_bytes()
            forged = json.loads(genuine)
            forged["source"]["commit"] = "deadbee"
            original = wr.read_held_bytes

            def read_then_swap(path: pathlib.Path, limit: int) -> bytes:
                payload = original(path, limit)
                if path.name == "manifest.json":
                    (release / "manifest.json").write_bytes(wr.canonical_json(forged))
                return payload

            out = io.StringIO()
            with mock.patch.object(wr, "read_held_bytes", read_then_swap), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(wr.verify_release(_verify_args(release, trust=public, print_manifest=True)), 0)
            self.assertEqual(out.getvalue().encode("ascii"), genuine)

    def test_signature_document_is_checked_strictly(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            release, public = _signed_fake_release(pathlib.Path(name))
            payload = (release / "manifest.json").read_bytes()
            document = json.loads((release / "manifest.sig.json").read_bytes())
            trusted = bytes.fromhex(public)
            self.assertEqual(wr.verify_manifest_payload(payload, json.dumps(document).encode(), trusted)["contract"],
                             wr.MANIFEST_CONTRACT)
            for field, value, message in (
                ("signature", "zz" * 64, "signature is malformed"),
                ("signature", "00" * 64, "does not verify"),
                ("public_key", "11" * 32, "not the trusted release authority"),
                ("manifest_sha256", "22" * 32, "different manifest"),
            ):
                with self.subTest(field=field):
                    bad = dict(document, **{field: value})
                    with self.assertRaisesRegex(wr.ReleaseError, message):
                        wr.verify_manifest_payload(payload, json.dumps(bad).encode(), trusted)


class AndroidStampTests(unittest.TestCase):
    """verify-android-stamp authenticates the stamp under the pinned key only."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._dir.name)
        authority = self.tmp / "authority.json"
        authority.write_text(json.dumps({"contract": wr.AUTHORITY_CONTRACT, "algorithm": "ed25519",
                                         "public_key": wr.ed25519_public(TEST_SEED).hex()}))
        patcher = mock.patch.object(wr, "AUTHORITY", authority)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._dir.cleanup)
        self.engine = self.tmp / "libwinnengine.so"
        self.engine.write_bytes(b"\x7fELF android arm64 engine")

    def _stamp(self, seed: bytes = TEST_SEED, target: str = "datapath-android-arm64", **override: object) -> pathlib.Path:
        digest = wr.sha256_file(self.engine)
        manifest = {"contract": wr.MANIFEST_CONTRACT, "artifacts": [{
            "target": target, "path": f"artifacts/{target}/libwinnengine.so", "sha256": digest,
            "size": self.engine.stat().st_size, "header_path": None, "header_sha256": None,
            "build_a_sha256": digest, "build_b_sha256": digest}]}
        payload = wr.canonical_json(manifest)
        stamp = {
            "contract": wr.ANDROID_STAMP_CONTRACT, "signed": True,
            "manifest_b64": base64.b64encode(payload).decode(),
            "manifest_signature": wr.ed25519_sign(seed, wr.SIGNATURE_DOMAIN + payload).hex(),
        }
        stamp.update(override)
        path = self.tmp / f"stamp-{len(list(self.tmp.iterdir()))}.json"
        path.write_text(json.dumps(stamp))
        return path

    def _check(self, stamp: pathlib.Path, target: str = "datapath-android-arm64") -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return wr.verify_android_stamp(argparse.Namespace(stamp=str(stamp), artifact=str(self.engine), target=target))

    def test_genuine_stamp_passes(self) -> None:
        self.assertEqual(self._check(self._stamp()), 0)

    def test_fabricated_unsigned_stamp_is_refused(self) -> None:
        digest = wr.sha256_file(self.engine)
        fabricated = self.tmp / "fabricated.json"
        fabricated.write_text(json.dumps({
            "contract": wr.ANDROID_STAMP_CONTRACT, "signed": True,
            "release_manifest_sha256": "ab" * 32, "signature_public_key": wr.ed25519_public(TEST_SEED).hex(),
            "engines": {"arm64-v8a": {"sha256": digest, "size": self.engine.stat().st_size,
                                      "target": "datapath-android-arm64"}}}))
        with self.assertRaisesRegex(wr.ReleaseError, "lacks signed manifest bytes"):
            self._check(fabricated)

    def test_other_key_other_bytes_and_other_target_are_refused(self) -> None:
        with self.assertRaisesRegex(wr.ReleaseError, "signature does not verify"):
            self._check(self._stamp(seed=bytes(range(1, 33))))
        with self.assertRaisesRegex(wr.ReleaseError, "exactly one matching target"):
            self._check(self._stamp(target="datapath-android-amd64"))
        stamp = self._stamp()
        self.engine.write_bytes(b"\x7fELF other engine bytes!!")
        with self.assertRaisesRegex(wr.ReleaseError, "differs from the signed manifest"):
            self._check(stamp)


class TwoBuildSchedulingTests(unittest.TestCase):
    """Claude seat: one Go cache per variant, every A queued first, B after its A."""

    def _run(self, jobs: int, targets: list[str]) -> list[dict]:
        events: list[dict] = []
        lock = __import__("threading").Lock()
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)

        def fake_builder(target, output, env, log):
            start = __import__("time").monotonic()
            __import__("time").sleep(0.05)
            output.write_bytes(b"same bytes for " + target.encode())
            log.write_text("ok")
            end = __import__("time").monotonic()
            with lock:
                events.append({"target": target, "variant": "a" if "/builds/a/" in str(output) else "b",
                               "cache": env["WINS_WINN_VARIANT_GOCACHE"], "start": start, "end": end})
            digest = wr.sha256_file(output)
            return {"contract": wr.RECEIPT_CONTRACT, "target": {"id": target, "goos": "linux", "goarch": "arm64",
                                                                "cgo_enabled": False},
                    "artifact": {"sha256": digest, "output_path": str(output)}, "archive_mode": False,
                    "package": "./cmd/winn-datapath", "role": "datapath", "platform": {}}

        args = argparse.Namespace(out=str(tmp / "rel"), set=None, targets=",".join(targets),
                                  source_commit="260da56", source_export=None, go_archive=None, ndk=None,
                                  developer_dir=None, module_proxy="off", jobs=jobs, skip_unavailable=False,
                                  keep_work=True)
        with mock.patch.object(wr, "prepare_go", return_value=(tmp / "go", {"version": "1.27.1"})), \
                mock.patch.object(wr, "snapshot_source", return_value=([tmp / "sa", tmp / "sb"], {
                    "commit": "260da56", "binding": "export", "tree_sha256": "1" * 64, "relay_tree_sha256": None})), \
                mock.patch.object(wr, "seed_module_cache", return_value=(tmp / "cache", "2" * 64)), \
                mock.patch.object(wr, "recheck_go"), \
                mock.patch.object(wr, "sealed_tree_digest", side_effect=lambda path: "2" * 64 if path.name == "cache" else "1" * 64), \
                mock.patch.object(wr, "run_builder", side_effect=fake_builder), \
                mock.patch.object(wr, "B_SEPARATION_SECONDS", 0.3), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(wr.build_release(args), 0)
        return events

    def test_one_cache_per_variant_and_every_b_after_its_a(self) -> None:
        targets = ["datapath-linux-arm64", "datapath-linux-amd64", "linux-arm64"]
        events = self._run(2, targets)
        caches = {variant: {e["cache"] for e in events if e["variant"] == variant} for variant in "ab"}
        self.assertEqual(len(caches["a"]), 1)
        self.assertEqual(len(caches["b"]), 1)
        self.assertNotEqual(caches["a"], caches["b"])
        for target in targets:
            a = next(e for e in events if e["target"] == target and e["variant"] == "a")
            b = next(e for e in events if e["target"] == target and e["variant"] == "b")
            self.assertGreaterEqual(b["start"] - a["end"], 0.3 - 0.01, target)

    def test_b_waits_for_its_a_even_when_a_worker_is_free(self) -> None:
        # One target, two workers: B is taken while A is still compiling, and
        # must not start until A has finished and the separation has passed.
        events = self._run(2, ["datapath-linux-arm64"])
        a = next(e for e in events if e["variant"] == "a")
        b = next(e for e in events if e["variant"] == "b")
        self.assertGreaterEqual(b["start"] - a["end"], 0.3 - 0.01)

    def test_every_a_is_queued_before_any_b(self) -> None:
        targets = ["datapath-linux-arm64", "datapath-linux-amd64", "linux-arm64"]
        events = sorted(self._run(1, targets), key=lambda e: e["start"])
        self.assertEqual([e["variant"] for e in events], ["a", "a", "a", "b", "b", "b"])


class BuildOneContractTests(unittest.TestCase):
    """Astra Turn 1 finding 4: the direct builder keeps its output contract."""

    def test_build_one_installs_output_receipt_and_mode(self) -> None:
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "repo" / ".git").mkdir(parents=True)
        target = "datapath-linux-arm64"
        receipt = {"contract": wr.RECEIPT_CONTRACT, "target": {"id": target},
                   "artifact": {"sha256": "", "output_path": "/scratch/out"}}

        def fake_release(namespace):
            release = pathlib.Path(namespace.out)
            (release / "artifacts" / target).mkdir(parents=True)
            (release / "logs").mkdir()
            artifact = release / "artifacts" / target / "winn-datapath"
            artifact.write_bytes(b"\x7fELF built")
            artifact.chmod(0o555)
            digest = wr.sha256_file(artifact)
            receipt["artifact"]["sha256"] = digest
            (release / "logs" / f"{target}.a.log").write_text(
                "--- stdout\n" + wr.RECEIPT_PREFIX + json.dumps(receipt) + "\n")
            (release / "manifest.json").write_bytes(wr.canonical_json({"artifacts": [{
                "target": target, "path": f"artifacts/{target}/winn-datapath", "sha256": digest,
                "header_path": None, "role": "datapath"}]}))
            return 0

        output = tmp / "out" / "winn-datapath"
        out = io.StringIO()
        with mock.patch.object(wr, "ROOT", tmp / "repo"), \
                mock.patch.object(wr, "_git", return_value=b"a" * 40 + b"\n"), \
                mock.patch.object(wr, "build_release", side_effect=fake_release), \
                contextlib.redirect_stdout(out):
            self.assertEqual(wr.build_one(argparse.Namespace(target=target, output=str(output))), 0)
        self.assertTrue(os.access(output, os.X_OK), "the executable bit must survive installation")
        written = json.loads(pathlib.Path(str(output) + ".receipt.json").read_text())
        self.assertEqual(written["artifact"]["output_path"], str(output))
        lines = out.getvalue().splitlines()
        self.assertTrue(lines[0].startswith(wr.RECEIPT_PREFIX))
        self.assertEqual(json.loads(lines[0][len(wr.RECEIPT_PREFIX):]), written)
        self.assertTrue(lines[1].startswith("Built Winn Protocol datapath: "))
        with mock.patch.object(wr, "ROOT", tmp / "repo"):
            output.unlink()
            with self.assertRaisesRegex(wr.ReleaseError, "output must be fresh"):
                wr.build_one(argparse.Namespace(target=target, output=str(output)))


class PrepareGoTests(unittest.TestCase):
    def test_prepare_go_refuses_an_unpinned_archive_and_an_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            tmp = pathlib.Path(name)
            archive = tmp / "go.tar.gz"
            archive.write_bytes(b"not the pinned archive")
            with self.assertRaisesRegex(wr.ReleaseError, "is not the pinned"):
                wr.prepare_go_command(argparse.Namespace(out=str(tmp / "go"), go_archive=str(archive)))
            self.assertFalse((tmp / "go").exists(), "a refused archive must leave nothing behind")
            (tmp / "go").mkdir()
            with self.assertRaisesRegex(wr.ReleaseError, "already exists"):
                wr.prepare_go_command(argparse.Namespace(out=str(tmp / "go"), go_archive=str(archive)))


def _direct_release_builder(target: str, during=None):
    """A stand-in build_release for build-one: writes a minimal release for TARGET.

    DURING, if given, runs inside the build (after the freshness check and
    before publication), the way another writer could act while Go compiles.
    """
    name = wr.TARGETS[target][0]

    def fake_release(namespace):
        release = pathlib.Path(namespace.out)
        (release / "artifacts" / target).mkdir(parents=True)
        (release / "logs").mkdir()
        artifact = release / "artifacts" / target / name
        artifact.write_bytes(b"built bytes for " + target.encode())
        artifact.chmod(0o444 if name.endswith(".a") else 0o555)
        entry = {"target": target, "path": f"artifacts/{target}/{name}", "sha256": wr.sha256_file(artifact),
                 "header_path": None, "header_sha256": None, "role": "datapath"}
        if name.endswith(".a"):
            header = artifact.with_suffix(".h")
            header.write_bytes(b"/* generated */\n")
            header.chmod(0o444)
            entry["header_path"] = f"artifacts/{target}/{header.name}"
            entry["header_sha256"] = wr.sha256_file(header)
        receipt = {"contract": wr.RECEIPT_CONTRACT, "target": {"id": target},
                   "artifact": {"sha256": entry["sha256"], "output_path": "/scratch/out"}}
        (release / "logs" / f"{target}.a.log").write_text(
            "--- stdout\n" + wr.RECEIPT_PREFIX + json.dumps(receipt) + "\n")
        (release / "manifest.json").write_bytes(wr.canonical_json({"artifacts": [entry]}))
        if during is not None:
            during()
        return 0

    return fake_release


class ExclusivePublicationTests(unittest.TestCase):
    """Astra SEALED-T2: every published output is created exclusively.

    A destination that exists, or that another writer creates while the build
    runs, is refused: never overwritten, never written through a link, and no
    success line is printed.
    """

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "repo" / ".git").mkdir(parents=True)
        self.out_dir = self.tmp / "out"
        self.out_dir.mkdir()

    def _build_one(self, target: str, output: pathlib.Path, during=None) -> tuple[object, str]:
        out = io.StringIO()
        result: object = None
        with mock.patch.object(wr, "ROOT", self.tmp / "repo"), \
                mock.patch.object(wr, "_git", return_value=b"a" * 40 + b"\n"), \
                mock.patch.object(wr, "build_release", side_effect=_direct_release_builder(target, during)), \
                contextlib.redirect_stdout(out):
            try:
                result = wr.build_one(argparse.Namespace(target=target, output=str(output)))
            except (wr.ReleaseError, OSError) as exc:
                result = exc
        return result, out.getvalue()

    def test_build_one_refuses_a_destination_another_writer_created_during_the_build(self) -> None:
        output = self.out_dir / "winn-datapath"
        result, printed = self._build_one(
            "datapath-linux-arm64", output, lambda: output.write_bytes(b"another writer's output"))
        # The link refusal surfaces as FileExistsError, which main() reports as
        # a refusal with exit status 1.
        self.assertIsInstance(result, (wr.ReleaseError, OSError))
        self.assertEqual(output.read_bytes(), b"another writer's output")
        self.assertNotIn(wr.RECEIPT_PREFIX, printed)
        self.assertFalse(pathlib.Path(str(output) + ".receipt.json").exists())
        self.assertEqual([p.name for p in self.out_dir.iterdir()], ["winn-datapath"])
        output.unlink()
        err = io.StringIO()
        with mock.patch.object(wr, "ROOT", self.tmp / "repo"), \
                mock.patch.object(wr, "_git", return_value=b"a" * 40 + b"\n"), \
                mock.patch.object(wr, "build_release", side_effect=_direct_release_builder(
                    "datapath-linux-arm64", lambda: output.write_bytes(b"again"))), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(err):
            self.assertEqual(wr.main(["build-one", "datapath-linux-arm64", str(output)]), 1)
        self.assertIn("WINN RELEASE REFUSED", err.getvalue())
        self.assertNotIn(wr.RECEIPT_PREFIX, out.getvalue())
        self.assertEqual(output.read_bytes(), b"again")

    def test_build_one_never_writes_through_a_link_planted_during_the_build(self) -> None:
        output = self.out_dir / "winn-datapath"
        victim = self.tmp / "victim"
        victim.write_bytes(b"victim")
        result, printed = self._build_one("datapath-linux-arm64", output, lambda: output.symlink_to(victim))
        self.assertIsInstance(result, (wr.ReleaseError, OSError))
        self.assertEqual(victim.read_bytes(), b"victim")
        self.assertTrue(output.is_symlink())
        self.assertNotIn(wr.RECEIPT_PREFIX, printed)

    def test_build_one_receipt_collision_removes_only_its_own_links(self) -> None:
        output = self.out_dir / "winn-datapath"
        receipt = pathlib.Path(str(output) + ".receipt.json")
        result, printed = self._build_one(
            "datapath-linux-arm64", output, lambda: receipt.write_bytes(b"another receipt"))
        self.assertIsInstance(result, (wr.ReleaseError, OSError))
        self.assertEqual(receipt.read_bytes(), b"another receipt")
        self.assertFalse(output.exists(), "the output this call linked must be withdrawn")
        self.assertNotIn(wr.RECEIPT_PREFIX, printed)

    def test_build_one_refuses_an_archive_target_relabelled_as_a_shared_object(self) -> None:
        output = self.out_dir / "libwinn.so"
        built = []
        result, printed = self._build_one("datapath-ios-arm64", output, lambda: built.append(1))
        self.assertIsInstance(result, wr.ReleaseError)
        self.assertIn("requires an output path ending in .a", str(result))
        self.assertEqual(built, [], "the relabel must be refused before anything is built")
        self.assertEqual(list(self.out_dir.iterdir()), [])

    def test_build_one_publishes_an_archive_with_its_header_and_receipt(self) -> None:
        output = self.out_dir / "libwinn-datapath.a"
        result, printed = self._build_one("datapath-ios-arm64", output)
        self.assertEqual(result, 0)
        self.assertEqual(sorted(p.name for p in self.out_dir.iterdir()),
                         ["libwinn-datapath.a", "libwinn-datapath.a.receipt.json", "libwinn-datapath.h"])
        for path in self.out_dir.iterdir():
            self.assertEqual(path.stat().st_nlink, 1, path.name)
        self.assertTrue(printed.startswith(wr.RECEIPT_PREFIX))

    def _release_args(self, targets: list[str]) -> argparse.Namespace:
        return argparse.Namespace(out=str(self.tmp / "rel"), set=None, targets=",".join(targets),
                                  source_commit="260da56", source_export=None, go_archive=None, ndk=None,
                                  developer_dir=None, module_proxy="off", jobs=2, skip_unavailable=False,
                                  keep_work=True)

    def _build_release(self, target: str, during_build=None, after_mkdir=None) -> object:
        tmp = self.tmp

        def fake_builder(target_name, output, env, log):
            output.write_bytes(b"same bytes")
            log.write_text("ok")
            if during_build is not None and "/builds/b/" in str(output):
                during_build()
            digest = wr.sha256_file(output)
            return {"contract": wr.RECEIPT_CONTRACT, "target": {"id": target_name, "goos": "linux",
                                                                "goarch": "arm64", "cgo_enabled": False},
                    "artifact": {"sha256": digest, "output_path": str(output)}, "archive_mode": False,
                    "package": "./cmd/winn-datapath", "role": "datapath", "platform": {}}

        original_mkdir = pathlib.Path.mkdir
        acted: list = []

        def spy_mkdir(path, *args, **kwargs):
            original_mkdir(path, *args, **kwargs)
            # pathlib's parents=True recursion re-enters this spy; act once.
            if after_mkdir is not None and path.parent.name == "artifacts" and not acted:
                acted.append(path)
                after_mkdir(path)

        with mock.patch.object(wr, "prepare_go", return_value=(tmp / "go", {"version": "1.27.1"})), \
                mock.patch.object(wr, "snapshot_source", return_value=([tmp / "sa", tmp / "sb"], {
                    "commit": "260da56", "binding": "export", "tree_sha256": "1" * 64, "relay_tree_sha256": None})), \
                mock.patch.object(wr, "seed_module_cache", return_value=(tmp / "cache", "2" * 64)), \
                mock.patch.object(wr, "recheck_go"), \
                mock.patch.object(wr, "sealed_tree_digest", side_effect=lambda path: "2" * 64 if path.name == "cache" else "1" * 64), \
                mock.patch.object(wr, "run_builder", side_effect=fake_builder), \
                mock.patch.object(wr, "B_SEPARATION_SECONDS", 0.0), \
                mock.patch.object(pathlib.Path, "mkdir", spy_mkdir), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                return wr.build_release(self._release_args([target]))
            except (wr.ReleaseError, OSError) as exc:
                return exc

    def test_build_release_never_writes_through_a_link_planted_at_an_artifact(self) -> None:
        victim = self.tmp / "victim"
        victim.write_bytes(b"victim")
        victim.chmod(0o644)
        result = self._build_release(
            "datapath-linux-arm64", after_mkdir=lambda d: (d / "winn-datapath").symlink_to(victim))
        self.assertIsInstance(result, (wr.ReleaseError, OSError))
        self.assertIn("refusing to overwrite", str(result))
        self.assertEqual(victim.read_bytes(), b"victim")
        self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o644)
        self.assertFalse((self.tmp / "rel" / "manifest.json").exists())

    def test_build_release_refuses_a_manifest_another_writer_created(self) -> None:
        victim = self.tmp / "victim"
        victim.write_bytes(b"victim")
        manifest = self.tmp / "rel" / "manifest.json"
        result = self._build_release("datapath-linux-arm64", during_build=lambda: manifest.symlink_to(victim))
        self.assertIsInstance(result, (wr.ReleaseError, OSError))
        self.assertEqual(victim.read_bytes(), b"victim")
        self.assertTrue(manifest.is_symlink())

    def test_build_release_publishes_fresh_read_only_files(self) -> None:
        self.assertEqual(self._build_release("datapath-linux-arm64"), 0)
        artifact = self.tmp / "rel" / "artifacts" / "datapath-linux-arm64" / "winn-datapath"
        self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((self.tmp / "rel" / "manifest.json").stat().st_mode), 0o444)

    def test_sign_refuses_a_signature_that_appeared_while_signing(self) -> None:
        release = _fake_release(self.tmp)
        key = self.tmp / "k.pem"
        _write_key(key, TEST_SEED)
        signature = release / "manifest.sig.json"
        real_sign = wr.ed25519_sign

        def racing_sign(seed, message):
            signature.write_bytes(b"another signer's record")
            return real_sign(seed, message)

        with mock.patch.object(wr, "ed25519_sign", side_effect=racing_sign), \
                contextlib.redirect_stdout(io.StringIO()) as printed:
            with self.assertRaisesRegex(wr.ReleaseError, "appeared while signing"):
                wr.sign_release(_sign_args(release, key))
        self.assertEqual(signature.read_bytes(), b"another signer's record")
        self.assertNotIn("SIGNED", printed.getvalue())
        self.assertEqual(sorted(p.name for p in release.iterdir()),
                         ["artifacts", "manifest.json", "manifest.sig.json"])

    def test_exclusive_helpers_refuse_existing_and_linked_paths(self) -> None:
        source = self.tmp / "source"
        source.write_bytes(b"payload")
        victim = self.tmp / "victim"
        victim.write_bytes(b"victim")
        existing = self.tmp / "existing"
        existing.write_bytes(b"existing")
        link = self.tmp / "link"
        link.symlink_to(victim)
        dangling = self.tmp / "dangling"
        dangling.symlink_to(self.tmp / "nowhere")
        for destination in (existing, link, dangling):
            with self.assertRaisesRegex(wr.ReleaseError, "refusing to overwrite"):
                wr.copy_exclusive(source, destination, 0o444)
            with self.assertRaisesRegex(wr.ReleaseError, "refusing to overwrite"):
                wr.write_exclusive(destination, b"x", 0o444)
        self.assertEqual(victim.read_bytes(), b"victim")
        self.assertEqual(existing.read_bytes(), b"existing")
        self.assertFalse((self.tmp / "nowhere").exists())
        fresh = self.tmp / "fresh"
        self.assertEqual(wr.copy_exclusive(source, fresh, 0o555), hashlib.sha256(b"payload").hexdigest())
        self.assertEqual(stat.S_IMODE(fresh.stat().st_mode), 0o555)
        with self.assertRaises(OSError):
            wr.copy_exclusive(link, self.tmp / "fresh2", 0o444)


class SealedDigestEncodingTests(unittest.TestCase):
    """Claude seat: one descriptor per file, identical digest and refusals."""

    @staticmethod
    def _reference(root: pathlib.Path) -> str:
        members = []
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                path = pathlib.Path(dirpath) / name
                data = path.read_bytes()
                relative = path.relative_to(root).as_posix()
                members.append(f"file {len(data)} {hashlib.sha256(data).hexdigest()} {relative}\n")
        return hashlib.sha256("".join(sorted(members)).encode("utf-8")).hexdigest()

    def test_digest_equals_the_reference_member_encoding(self) -> None:
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: wr.remove_tree(tmp))
        root = tmp / "tree"
        (root / "a" / "b").mkdir(parents=True)
        (root / "top.go").write_bytes(b"package top\n")
        (root / "a" / "empty").write_bytes(b"")
        (root / "a" / "b" / "big.bin").write_bytes(os.urandom(3 * 1024 * 1024 + 17))
        (root / "a" / "b" / "z.txt").write_bytes(b"z")
        wr.seal_tree(root)
        self.assertEqual(wr.sealed_tree_digest(root), self._reference(root))
        self.assertEqual(wr.sealed_tree_digest(pathlib.Path(str(root) + os.sep)), self._reference(root))

    def test_hard_linked_symlinked_and_writable_members_are_refused(self) -> None:
        for case in ("hardlink", "file-symlink", "writable-file"):
            with self.subTest(case=case):
                tmp = pathlib.Path(tempfile.mkdtemp())
                self.addCleanup(lambda tmp=tmp: wr.remove_tree(tmp))
                root = tmp / "tree"
                root.mkdir()
                member = root / "member.go"
                member.write_bytes(b"package member\n")
                if case == "hardlink":
                    os.link(member, tmp / "outside-link")
                elif case == "file-symlink":
                    (root / "alias.go").symlink_to(member)
                wr.seal_tree(root)
                if case == "writable-file":
                    member.chmod(0o644)
                with self.assertRaisesRegex(wr.ReleaseError, "hard-linked|non-regular|writable"):
                    wr.sealed_tree_digest(root)

    def test_a_fifo_is_refused_without_blocking(self) -> None:
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: wr.remove_tree(tmp))
        root = tmp / "tree"
        root.mkdir()
        os.mkfifo(root / "pipe", 0o444)
        wr.seal_tree(root)
        with self.assertRaisesRegex(wr.ReleaseError, "non-regular"):
            wr.sealed_tree_digest(root)


class WindowsBinaryHashTests(unittest.TestCase):
    def test_sha256_file_opens_in_binary_mode(self) -> None:
        import inspect

        source = inspect.getsource(wr.sha256_file)
        self.assertIn('getattr(os, "O_BINARY", 0)', source)
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "bin.exe"
            payload = b"MZ\r\n\x1a\x00tail"
            path.write_bytes(payload)
            self.assertEqual(wr.sha256_file(path), hashlib.sha256(payload).hexdigest())

    def test_every_raw_descriptor_opens_in_binary_mode(self) -> None:
        # POSIX has no text mode, so the proof is on the flags: a stand-in
        # O_BINARY bit must reach every os.open this module makes, including
        # read_held_bytes, which `verify` runs on the Windows build host.
        import importlib.util

        stand_in = 1 << 30
        real_open = os.open
        seen: list[tuple[str, bool]] = []

        def recording_open(path, flags, *args, **kwargs):
            seen.append((os.path.basename(os.fspath(path)), bool(flags & stand_in)))
            return real_open(path, flags & ~stand_in, *args, **kwargs)

        spec = importlib.util.spec_from_file_location(
            "_winn_release_binary_mode_probe", ROOT / "tools" / "winn_release.py"
        )
        assert spec is not None and spec.loader is not None
        probe = importlib.util.module_from_spec(spec)
        with mock.patch.object(os, "O_BINARY", stand_in, create=True):
            spec.loader.exec_module(probe)
        self.assertTrue(probe._EXCLUSIVE_WRITE & stand_in, "write_exclusive and copy_exclusive destinations")

        payload = b"MZ\r\n\x1a\x00tail\n"
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root / "src.bin").write_bytes(payload)
            sealed = root / "sealed"
            sealed.mkdir()
            (sealed / "member.bin").write_bytes(payload)
            (sealed / "member.bin").chmod(0o444)
            sealed.chmod(0o555)
            try:
                with mock.patch.object(os, "O_BINARY", stand_in, create=True), \
                        mock.patch.object(os, "open", recording_open):
                    self.assertEqual(wr.read_held_bytes(root / "src.bin", 1024), payload)
                    digest = wr.copy_exclusive(root / "src.bin", root / "dst.bin", 0o444)
                    wr.sealed_tree_digest(sealed)
            finally:
                sealed.chmod(0o755)
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertEqual((root / "dst.bin").read_bytes(), payload)
        reads = [entry for entry in seen if entry[0] in {"src.bin", "member.bin"}]
        self.assertEqual(
            reads,
            [("src.bin", True), ("src.bin", True), ("member.bin", True)],
            "read_held_bytes, copy_exclusive's source and sealed_tree_digest",
        )

if __name__ == "__main__":
    unittest.main()
