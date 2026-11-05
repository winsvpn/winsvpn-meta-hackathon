#!/usr/bin/env python3
"""Regression tests for the pinned three-ABI Android Xray producer."""

from __future__ import annotations

import pathlib
import struct
import tempfile
import unittest

try:
    from tools.verify_android_elf_alignment import verify_android_elf_alignment
    from tools.verify_android_xray_binary import verify_android_xray_binary
except ModuleNotFoundError:
    from verify_android_elf_alignment import verify_android_elf_alignment
    from verify_android_xray_binary import verify_android_xray_binary


ROOT = pathlib.Path(__file__).resolve().parents[1]
CANONICAL = {
    "arm64-v8a": (
        "arm64",
        "30772382fcee4fe18b6c31a3daf9a53878b5bfa775e05ea3f3c8cb0b0ec73b2b",
    ),
    "armeabi-v7a": (
        "arm",
        "35e5256bce15bc30bd3dbf7ba82c7ac6b138782eae811e0ae4ab535fbedec1b9",
    ),
    "x86_64": (
        "amd64",
        "82885af5bc2c89eb10201af08049d865c398025fe89f2b8cd02178fc275876b4",
    ),
}


def synthetic_arm_elf(*, alignment: int = 16_384, machine: int = 40) -> bytes:
    data = bytearray(1_001_000)
    ident = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<16sHHIIIIIHHHHHH",
        data,
        0,
        ident,
        3,
        machine,
        1,
        0x4000,
        52,
        0,
        0,
        52,
        32,
        3,
        0,
        0,
        0,
    )
    interpreter = b"/system/bin/linker\x00"
    struct.pack_into(
        "<IIIIIIII", data, 52, 3, 0x100, 0x100, 0, len(interpreter), len(interpreter), 4, 1
    )
    struct.pack_into(
        "<IIIIIIII", data, 84, 1, 0, 0, 0, 0x1000, 0x1000, 4, alignment
    )
    struct.pack_into(
        "<IIIIIIII",
        data,
        116,
        1,
        0x4000,
        0x4000,
        0,
        0x1000,
        0x1000,
        5,
        alignment,
    )
    data[0x100 : 0x100 + len(interpreter)] = interpreter
    marker = (
        b"github.com/xtls/xray-core/main\x00"
        b"github.com/xtls/xray-core/core\x00"
        b"go1.27.1\x00v1.260327.0\x00"
    )
    data[0x200 : 0x200 + len(marker)] = marker
    return bytes(data)


class AndroidXrayProducerTest(unittest.TestCase):
    def test_canonical_three_abi_outputs(self) -> None:
        for abi, (goarch, digest) in CANONICAL.items():
            with self.subTest(abi=abi):
                result = verify_android_xray_binary(
                    ROOT
                    / "android"
                    / "app"
                    / "src"
                    / "main"
                    / "jniLibs"
                    / abi
                    / "libxray.so",
                    goarch=goarch,
                    go_version="1.27.1",
                    build_marker="v1.260327.0",
                    expected_sha256=digest,
                )
                self.assertEqual(result["page_size"], 16_384)

    def test_producer_pins_and_stages_armv7_atomically(self) -> None:
        build = (ROOT / "tools" / "build_xray_engine.sh").read_text()
        for literal in (
            'XRAY_TAG="v26.9.30"',
            'XRAY_COMMIT="b26a91de4f3294e26a0ad0a970b81a386a41f789"',
            'REVIEWED_GO_VERSION="1.27.1"',
            'REVIEWED_NDK_VERSION="30.0.16248370"',
            "android-arm) goos=android; goarch=arm",
            "export GOARM=7",
            "max-page-size=${ANDROID_ELF_PAGE_SIZE}",
            "common-page-size=${ANDROID_ELF_PAGE_SIZE}",
            "verify_android_xray_binary.py",
            'export GOFLAGS=-mod=readonly',
            'export GOMODCACHE="${WORK_ROOT}/go-mod-cache"',
        ):
            self.assertIn(literal, build)

        prepare = (ROOT / "tools" / "prepare_android_xray_assets.sh").read_text()
        for target in ("android-arm64", "android-arm", "android-amd64"):
            self.assertIn(target, prepare)
        first_install = prepare.index('mv "${JNI_DIR}/${abi}/libxray.so.pending_xray_build"')
        self.assertLess(prepare.index("android-amd64"), first_install)

    def test_verifier_rejects_four_kib_alignment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "libxray.so"
            path.write_bytes(synthetic_arm_elf(alignment=4096))
            with self.assertRaisesRegex(ValueError, "4096.*not 16384-byte compatible"):
                verify_android_xray_binary(
                    path,
                    goarch="arm",
                    go_version="1.27.1",
                    build_marker="v1.260327.0",
                )

    def test_verifier_rejects_wrong_machine_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "libxray.so"
            path.write_bytes(synthetic_arm_elf(machine=183))
            with self.assertRaisesRegex(ValueError, "e_machine 183"):
                verify_android_xray_binary(
                    path,
                    goarch="arm",
                    go_version="1.27.1",
                    build_marker="v1.260327.0",
                )
            path.write_bytes(synthetic_arm_elf())
            with self.assertRaisesRegex(ValueError, "SHA-256 drift"):
                verify_android_xray_binary(
                    path,
                    goarch="arm",
                    go_version="1.27.1",
                    build_marker="v1.260327.0",
                    expected_sha256="0" * 64,
                )

    def test_all_shipping_xray_overlays_are_the_pinned_build(self) -> None:
        for source_set in ("main", "debug", "profile", "release"):
            for abi, (goarch, digest) in CANONICAL.items():
                with self.subTest(source_set=source_set, abi=abi):
                    verify_android_xray_binary(
                        ROOT
                        / "android"
                        / "app"
                        / "src"
                        / source_set
                        / "jniLibs"
                        / abi
                        / "libxray.so",
                        goarch=goarch,
                        go_version="1.27.1",
                        build_marker="v1.260327.0",
                        expected_sha256=digest,
                    )

    def test_shipping_64_bit_winn_engines_are_16_kib_compatible(self) -> None:
        for source_set in ("debug", "profile", "release"):
            for abi in ("arm64-v8a", "x86_64"):
                with self.subTest(source_set=source_set, abi=abi):
                    result = verify_android_elf_alignment(
                        ROOT
                        / "android"
                        / "app"
                        / "src"
                        / source_set
                        / "jniLibs"
                        / abi
                        / "libwinnengine.so",
                        abi=abi,
                    )
                    self.assertEqual(result["page_size"], 16_384)

    def test_generic_alignment_verifier_rejects_four_kib_elf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "libwinnengine.so"
            path.write_bytes(synthetic_arm_elf(alignment=4096))
            with self.assertRaisesRegex(ValueError, "4096.*not 16384-byte compatible"):
                verify_android_elf_alignment(path, abi="armeabi-v7a")


if __name__ == "__main__":
    unittest.main()
