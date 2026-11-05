#!/usr/bin/env python3
"""Adversarial fixture tests for standalone Inno Setup 7.1.0 custody."""

from __future__ import annotations

import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from concurrent import futures
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "release_inno_toolchain_custody.py"
POWERSHELL = ROOT / "tools" / "release_inno_toolchain_custody.ps1"
PIN = ROOT / "tools" / "inno-toolchain-pins.json"
LIVE_X64 = Path("/private/tmp/inno-custody-proof/innosetup-7.1.0-x64.exe")
LIVE_X64_ISSIG = Path("/private/tmp/inno-custody-proof/innosetup-7.1.0-x64.exe.issig")

SPEC = importlib.util.spec_from_file_location("release_inno_toolchain_custody", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Inno toolchain custody module")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o444)


def load_official() -> dict:
    return json.loads(PIN.read_text(encoding="utf-8"))


# Official ISCC.exe 7.1.0 identity measured on the x64 and ARM64 build VMs
# (2026-10-15); both hosts produced identical values.
MEASURED_ISCC = {
    "sha256": "d06ebd38f38e3cee60a3c50cc45bd449d77e0bc6a5cabc607ea9886808e4de1a",
    "size": 2135968,
    "install_tree_sha256": "7eb0389c70763b407650ef7b2ce9e8010988bbd217d86068b915b96afa91bfca",
    "product_version_string": "0.0.0.0",
}


def load_unmeasured() -> dict:
    """The official pin as it was before the compilers were measured."""
    document = load_official()
    for name in ("windows_x64", "windows_arm64"):
        record = document["compilers"][name]
        record["status"] = "unmeasured"
        for field in ("sha256", "size", "install_tree_sha256", "product_version_string"):
            record[field] = None
    document["status"] = "unmeasured"
    return document


def write_unmeasured_pin(directory: Path) -> Path:
    pin = directory / "inno-toolchain-pins.json"
    write_json(pin, load_unmeasured())
    return pin


def run_powershell(*args: str) -> subprocess.CompletedProcess[str]:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        raise unittest.SkipTest("PowerShell is unavailable")
    return subprocess.run(
        [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(POWERSHELL), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _churn_tmp_siblings(tag: str) -> None:
    roots = {Path(tempfile.gettempdir()).resolve(), Path("/private/tmp"), Path("/tmp")}
    for root in roots:
        try:
            if not root.exists():
                continue
        except OSError:
            continue
        sibling = root / f"wins-inno-churn-{os.getpid()}-{tag}-{time.time_ns()}"
        try:
            sibling.mkdir()
            (sibling / "nlink").mkdir()
            try:
                os.utime(root, None)
            except OSError:
                pass
        except OSError:
            continue
        finally:
            shutil.rmtree(sibling, ignore_errors=True)


def _churn_bound_ancestors(path: Path, index: int) -> None:
    _churn_tmp_siblings(f"{path.name}-{index}")
    parent = path.parent
    local = parent / f"wins-local-churn-{index}-{time.time_ns()}"
    try:
        local.mkdir()
        (local / "nlink").mkdir()
        try:
            os.utime(parent, None)
        except OSError:
            pass
    except OSError:
        return
    finally:
        shutil.rmtree(local, ignore_errors=True)


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_len(len(content)) + content


def encode_oid(s: str) -> bytes:
    parts = [int(item) for item in s.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        stack = [part & 0x7F]
        part >>= 7
        while part:
            stack.append(0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(reversed(stack))
    return tlv(0x06, body)


def encode_int(n: int) -> bytes:
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return tlv(0x02, raw)


def align4(n: int) -> int:
    return (n + 3) & ~3


def u16(n: int) -> bytes:
    return struct.pack("<H", n)


def u32(n: int) -> bytes:
    return struct.pack("<I", n)


def make_cert(*, cn: str, org: str, key: rsa.RSAPrivateKey, serial: int) -> x509.Certificate:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Noord-Holland"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


def encode_pkcs7(certs: list[x509.Certificate], signer: x509.Certificate) -> bytes:
    cert_der = b"".join(cert.public_bytes(Encoding.DER) for cert in certs)
    issuer_der = signer.issuer.public_bytes(Encoding.DER)
    issuer_serial = tlv(0x30, issuer_der + encode_int(signer.serial_number))
    sha256_oid = encode_oid("2.16.840.1.101.3.4.2.1")
    rsa_oid = encode_oid("1.2.840.113549.1.1.1")
    signer_info = tlv(
        0x30,
        encode_int(1)
        + issuer_serial
        + tlv(0x30, sha256_oid)
        + tlv(0x30, rsa_oid + tlv(0x05, b""))
        + tlv(0x04, b"\x00" * 16),
    )
    signed = tlv(
        0x30,
        encode_int(1)
        + tlv(0x31, tlv(0x30, sha256_oid))
        + tlv(0x30, encode_oid("1.2.840.113549.1.7.1"))
        + tlv(0xA0, cert_der)
        + tlv(0x31, signer_info),
    )
    return tlv(0x30, encode_oid("1.2.840.113549.1.7.2") + tlv(0xA0, signed))


def encode_string(key: str, value: str) -> bytes:
    encoded_key = (key + "\x00").encode("utf-16le")
    encoded_value = (value + "\x00").encode("utf-16le")
    after_key = 6 + len(encoded_key)
    pad_key = align4(after_key) - after_key
    after_val = after_key + pad_key + len(encoded_value)
    pad_val = align4(after_val) - after_val
    return (
        u16(after_val + pad_val)
        + u16(len(value) + 1)
        + u16(1)
        + encoded_key
        + (b"\x00" * pad_key)
        + encoded_value
        + (b"\x00" * pad_val)
    )


def encode_block(key: str, wtype: int, value: bytes, children: bytes) -> bytes:
    encoded_key = (key + "\x00").encode("utf-16le")
    after_key = 6 + len(encoded_key)
    pad_key = align4(after_key) - after_key
    value_length = len(value) if wtype == 0 else len(value) // 2
    after_val = after_key + pad_key + len(value)
    pad_val = align4(after_val) - after_val
    body = (
        u16(value_length)
        + u16(wtype)
        + encoded_key
        + (b"\x00" * pad_key)
        + value
        + (b"\x00" * pad_val)
        + children
    )
    return u16(2 + len(body)) + body


def encode_version(strings: dict[str, str]) -> bytes:
    children = b"".join(encode_string(key, value) for key, value in strings.items())
    string_table = encode_block("040904B0", 1, b"", children)
    string_file_info = encode_block("StringFileInfo", 1, b"", string_table)
    fixed = struct.pack("<I", 0xFEEF04BD) + (b"\x00" * 48)
    return encode_block("VS_VERSION_INFO", 0, fixed, string_file_info)


def wrap_win_certificate(pkcs7: bytes) -> bytes:
    record = struct.pack("<IHH", 8 + len(pkcs7), 0x0200, 0x0002) + pkcs7
    if len(record) % 8:
        record += b"\x00" * (8 - len(record) % 8)
    return record


def build_pe(
    *,
    machine: int = 0x8664,
    magic: int = 0x20B,
    authenticode: bool = False,
    pkcs7: bytes | None = None,
    version: dict[str, str] | None = None,
    overlay: bytes = b"",
) -> bytes:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 64)
    coff = bytearray(24)
    coff[0:4] = b"PE\0\0"
    struct.pack_into("<H", coff, 4, machine)
    optional_size = 240 if magic == 0x20B else 224
    struct.pack_into("<H", coff, 20, optional_size)
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, magic)
    number_offset = 108 if magic == 0x20B else 92
    directory_base = 112 if magic == 0x20B else 96
    struct.pack_into("<I", optional, number_offset, 16)
    if version is None:
        image = bytes(dos) + bytes(coff) + bytes(optional) + overlay + b"INNO-FIXTURE"
        if not authenticode and pkcs7 is None:
            return bytes(image)
        cert = wrap_win_certificate(pkcs7 or (b"\x30\x03\x02\x01\x00" + (b"\x00" * 11)))
        cert_offset = len(image)
        mutable = bytearray(image)
        struct.pack_into("<I", mutable, 64 + 24 + directory_base + 32, cert_offset)
        struct.pack_into("<I", mutable, 64 + 24 + directory_base + 36, len(cert))
        return bytes(mutable) + cert

    version_bytes = encode_version(version)
    root_size = 24
    type_size = 24
    lang_size = 24
    data_size = 16
    off_type = root_size
    off_lang = off_type + type_size
    off_data = off_lang + lang_size
    off_ver = off_data + data_size
    rsrc = bytearray()
    rsrc += u32(0) + u32(0) + u16(0) + u16(0) + u16(0) + u16(1)
    rsrc += u32(16) + u32(off_type | 0x80000000)
    rsrc += u32(0) + u32(0) + u16(0) + u16(0) + u16(0) + u16(1)
    rsrc += u32(1) + u32(off_lang | 0x80000000)
    rsrc += u32(0) + u32(0) + u16(0) + u16(0) + u16(0) + u16(1)
    rsrc += u32(0x409) + u32(off_data)
    rsrc += u32(0) + u32(len(version_bytes)) + u32(0) + u32(0)
    rsrc += version_bytes
    struct.pack_into("<H", coff, 6, 1)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x400)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 112 + 16, 0x1000)
    struct.pack_into("<I", optional, 112 + 20, len(rsrc))
    section = bytearray(40)
    section[0:5] = b".rsrc"
    raw_size = (len(rsrc) + 0x1FF) & ~0x1FF
    struct.pack_into("<I", section, 8, len(rsrc))
    struct.pack_into("<I", section, 12, 0x1000)
    struct.pack_into("<I", section, 16, raw_size)
    struct.pack_into("<I", section, 20, 0x400)
    headers = bytes(dos) + bytes(coff) + bytes(optional) + bytes(section)
    headers += b"\x00" * (0x400 - len(headers))
    struct.pack_into("<I", rsrc, off_data, 0x1000 + off_ver)
    rsrc_padded = bytes(rsrc) + b"\x00" * (raw_size - len(rsrc))
    image = bytearray(headers + rsrc_padded + overlay)
    cert = wrap_win_certificate(pkcs7 or (b"\x30\x03\x02\x01\x00" + (b"\x00" * 11)))
    cert_offset = len(image)
    struct.pack_into("<I", image, 64 + 24 + directory_base + 32, cert_offset)
    struct.pack_into("<I", image, 64 + 24 + directory_base + 36, len(cert))
    return bytes(image) + cert


# VERSIONINFO of the official 7.1.0 ISCC.exe as measured on Windows 11
# (2026-10-15): ProductVersion is "0.0.0.0", not "7.1.0".
COMPILER_VERSIONINFO = {
    "CompanyName": "Jordan Russell",
    "FileDescription": "Inno Setup Command-Line Compiler",
    "ProductName": "Inno Setup",
    "ProductVersion": "0.0.0.0",
    "OriginalFileName": "ISCC.exe",
}


def compiler_pe(**kwargs: object) -> bytes:
    version = dict(COMPILER_VERSIONINFO)
    extra = kwargs.pop("version", None)
    if isinstance(extra, dict):
        version.update(extra)
    kwargs.setdefault("authenticode", True)
    return build_pe(version=version, **kwargs)


def pin_compilers(
    document: dict,
    *,
    sha256: str,
    size: int,
    tree: str,
    product_version: str = "0.0.0.0",
) -> dict:
    for name in ("windows_x64", "windows_arm64"):
        record = document["compilers"][name]
        record["status"] = "pinned"
        record["sha256"] = sha256
        record["size"] = size
        record["install_tree_sha256"] = tree
        record["product_version_string"] = product_version
    document["status"] = "pinned"
    return document


class ReleaseInnoToolchainCustodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pin = MODULE.load_pin(PIN)
        cls.base = Path(tempfile.mkdtemp(prefix="wins-inno-custody-", dir="/private/tmp"))
        cls.base.chmod(0o700)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.base, ignore_errors=True)

    def scratch(self, name: str) -> Path:
        directory = self.base / name
        directory.mkdir(parents=True)
        return directory

    def test_official_pin_is_well_formed_and_ecdsa_verified(self) -> None:
        result = MODULE.verify_pins(PIN)
        self.assertEqual(result["contract"], MODULE.CONTRACT)
        self.assertEqual(result["version"], "7.1.0")
        self.assertEqual(result["status"], "pinned")
        self.assertTrue(result["installers_pinned"])
        self.assertTrue(result["compilers_pinned"])
        x64 = self.pin["installers"]["windows_x64"]
        self.assertEqual(
            x64["sha256"],
            "0362a383ed217d4c4239b5933866dd96d3eb2102737da92f80f6057a4b40df2f",
        )
        self.assertEqual(x64["size"], 14304168)
        self.assertEqual(self.pin["publisher"]["authenticode_publisher_name"], "Pyrsys B.V.")
        for name in ("windows_x64", "windows_arm64"):
            for field, value in MEASURED_ISCC.items():
                self.assertEqual(self.pin["compilers"][name][field], value)
        self.assertEqual(self.pin["compilers"]["windows_arm64"]["pe_machine"], "x64")
        self.assertEqual(self.pin["compilers"]["windows_arm64"]["native_arm64_compiler"], "not_published")
        self.assertEqual(MODULE.OFFICIAL_ISSIG_KEYS["def02"]["key_id"], self.pin["keys"]["def02"]["key_id"])
        self.assertNotIn("owner_blockers", result)
        self.assertNotIn("owner_blockers", load_official())
        self.assertEqual(self.pin["status"], "pinned")
        unmeasured = MODULE.verify_pins(write_unmeasured_pin(self.scratch("official-unmeasured")))
        self.assertEqual(unmeasured["status"], "unmeasured")
        self.assertFalse(unmeasured["compilers_pinned"])

    def test_cli_verify_pins_succeeds(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(TOOL), "verify-pins", "--pin", str(PIN)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("status|pinned", completed.stdout)
        self.assertIn("compilers_pinned|True", completed.stdout)
        self.assertNotIn("owner_blockers", completed.stdout)

    def test_duplicate_json_keys_fail(self) -> None:
        directory = self.scratch("dup")
        pin = directory / "inno-toolchain-pins.json"
        text = PIN.read_text(encoding="utf-8").replace(
            '"version": "7.1.0"',
            '"version": "7.1.0", "version": "7.1.0"',
            1,
        )
        pin.write_text(text, encoding="utf-8")
        pin.chmod(0o444)
        with self.assertRaisesRegex(MODULE.Refused, "duplicate JSON key"):
            MODULE.load_pin(pin)

    def test_extra_json_field_fails(self) -> None:
        official = load_official()
        official["extra"] = 1
        pin = self.scratch("extra") / "inno-toolchain-pins.json"
        write_json(pin, official)
        with self.assertRaisesRegex(MODULE.Refused, "unexpected pin field"):
            MODULE.load_pin(pin)

    def test_type_coercion_of_hash_version_and_flags_fails(self) -> None:
        cases = [
            ("installers", "windows_x64", "sha256", True, "type coercion refused"),
            ("installers", "windows_x64", "sha256", "0362A383ED217D4C4239B5933866DD96D3EB2102737DA92F80F6057A4B40DF2F", "exact lowercase"),
            ("version", None, None, 7.1, "type coercion refused"),
            ("verification_tool", None, "execute", True, "refusing to execute"),
            ("verification_methods", "issig_ecdsa_p256", "execute_issigtool", True, "refusing to execute"),
            ("schema_version", None, None, True, "type coercion refused"),
            ("installers", "windows_x64", "size", "14304168", "type coercion refused"),
            ("compilers", "windows_x64", "sha256", "0" * 64, "unmeasured or unpublished field must be JSON null"),
        ]
        official = load_unmeasured()
        for index, (section, name, field, value, pattern) in enumerate(cases):
            with self.subTest(section=section, field=field, value=value):
                document = copy.deepcopy(official)
                if section == "version":
                    document["version"] = value
                elif section == "schema_version":
                    document["schema_version"] = value
                elif name is None:
                    document[section][field] = value
                else:
                    document[section][name][field] = value
                pin = self.scratch(f"coerce-{index}") / "inno-toolchain-pins.json"
                write_json(pin, document)
                with self.assertRaisesRegex(MODULE.Refused, pattern):
                    MODULE.load_pin(pin)

    def test_zero_hash_and_fabricated_compiler_pin_fail(self) -> None:
        official = load_official()
        official["installers"]["windows_x64"]["sha256"] = "0" * 64
        pin = self.scratch("zero") / "inno-toolchain-pins.json"
        write_json(pin, official)
        with self.assertRaisesRegex(MODULE.Refused, "non-zero digest"):
            MODULE.load_pin(pin)

        official = load_unmeasured()
        official["status"] = "pinned"
        official["compilers"]["windows_x64"]["status"] = "pinned"
        official["compilers"]["windows_x64"]["sha256"] = "a" * 64
        pin = self.scratch("fabricated-status") / "inno-toolchain-pins.json"
        write_json(pin, official)
        with self.assertRaisesRegex(MODULE.Refused, "type coercion refused: size"):
            MODULE.load_pin(pin)

        official = load_unmeasured()
        official["status"] = "pinned"
        pin = self.scratch("fabricated-top-status") / "inno-toolchain-pins.json"
        write_json(pin, official)
        with self.assertRaisesRegex(MODULE.Refused, "pin status must be pinned when both compilers"):
            MODULE.load_pin(pin)

        official = load_official()
        official["compilers"]["windows_arm64"]["install_tree_sha256"] = "0" * 64
        pin = self.scratch("zero-pinned-tree") / "inno-toolchain-pins.json"
        write_json(pin, official)
        with self.assertRaisesRegex(MODULE.Refused, "non-zero digest"):
            MODULE.load_pin(pin)

    def test_issig_mutation_fails_ecdsa(self) -> None:
        official = load_official()
        official["installers"]["windows_x64"]["issig_sig_s"] = "1" * 64
        pin = self.scratch("issig-mut") / "inno-toolchain-pins.json"
        write_json(pin, official)
        with self.assertRaisesRegex(MODULE.Refused, "ECDSA-P256"):
            MODULE.load_pin(pin)

    def test_attacker_key_replacement_cannot_self_sign(self) -> None:
        attacker = ec.generate_private_key(ec.SECP256R1())
        numbers = attacker.public_key().public_numbers()
        public_x = f"{numbers.x:064x}"
        public_y = f"{numbers.y:064x}"
        key_id = hashlib.sha256(bytes.fromhex(public_x + public_y)).hexdigest()
        official = load_official()
        official["issig_keys"]["def02"]["public_x"] = public_x
        official["issig_keys"]["def02"]["public_y"] = public_y
        official["issig_keys"]["def02"]["key_id"] = key_id
        pin = self.scratch("attacker-key") / "inno-toolchain-pins.json"
        write_json(pin, official)
        with self.assertRaisesRegex(MODULE.Refused, "immutable code anchor"):
            MODULE.load_pin(pin)

        digest = MODULE.issig_hash_to_sign(
            official["installers"]["windows_x64"]["filename"],
            official["installers"]["windows_x64"]["size"],
            official["installers"]["windows_x64"]["sha256"],
            official["installers"]["windows_x64"]["issig_file_tag"],
        )
        signature = attacker.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        sig_r, sig_s = decode_dss_signature(signature)
        official["installers"]["windows_x64"]["issig_sig_r"] = f"{sig_r:064x}"
        official["installers"]["windows_x64"]["issig_sig_s"] = f"{sig_s:064x}"
        pin = self.scratch("attacker-key-signed") / "inno-toolchain-pins.json"
        write_json(pin, official)
        with self.assertRaisesRegex(MODULE.Refused, "immutable code anchor"):
            MODULE.load_pin(pin)

    def test_path_substitution_symlink_hardlink_and_directory_fail(self) -> None:
        directory = self.scratch("fs")
        real = directory / "innosetup-7.1.0-x64.exe"
        real.write_bytes(b"not-the-official-installer")
        real.chmod(0o444)
        with self.assertRaisesRegex(MODULE.Refused, "PATH substitution refused"):
            MODULE.verify_installer_identity(Path("innosetup-7.1.0-x64.exe"), "x64", PIN)

        named_link = directory / "named"
        named_link.mkdir()
        target = named_link / "innosetup-7.1.0-x64.exe"
        os.symlink(real, target)
        with self.assertRaisesRegex(MODULE.Refused, "symbolic path component rejected"):
            MODULE.verify_installer_identity(target, "x64", PIN)

        hard_dir = directory / "hard"
        hard_dir.mkdir()
        original = hard_dir / "original.bin"
        original.write_bytes(b"hardlink-bytes")
        hard = hard_dir / "innosetup-7.1.0-x64.exe"
        os.link(original, hard)
        with self.assertRaisesRegex(MODULE.Refused, "hardlink refused"):
            MODULE.verify_installer_identity(hard, "x64", PIN)

        as_dir = directory / "as-dir" / "innosetup-7.1.0-x64.exe"
        as_dir.mkdir(parents=True)
        with self.assertRaisesRegex(MODULE.Refused, "regular non-reparse file"):
            MODULE.verify_installer_identity(as_dir, "x64", PIN)

    def test_hash_mismatch_wrong_architecture_and_mutation_fail(self) -> None:
        directory = self.scratch("mismatch")
        candidate = directory / "innosetup-7.1.0-x64.exe"
        candidate.write_bytes(build_pe(machine=0x014C, magic=0x10B))
        candidate.chmod(0o444)
        with self.assertRaisesRegex(MODULE.Refused, "SHA-256 mismatch"):
            MODULE.verify_installer_identity(candidate, "x64", PIN)

        with self.assertRaisesRegex(MODULE.Refused, "architecture mismatch"):
            MODULE.assert_pe_machine(build_pe(machine=0x014C, magic=0x10B, authenticode=True), "x64")
        with self.assertRaisesRegex(MODULE.Refused, "architecture mismatch"):
            MODULE.assert_pe_machine(build_pe(machine=0xAA64, authenticode=True), "x64")
        with self.assertRaisesRegex(MODULE.Refused, "embedded Authenticode"):
            MODULE.parse_pe(build_pe(authenticode=False))

        swapped = directory / "swap" / "innosetup-7.1.0-x64.exe"
        swapped.parent.mkdir()
        real = swapped.parent / "real.exe"
        real.write_bytes(b"stable-bytes")
        os.symlink(real, swapped)
        with self.assertRaisesRegex(MODULE.Refused, "symbolic path component rejected"):
            MODULE.digest_file(swapped, "installer", maximum=MODULE.MAX_INSTALLER)

    def test_compiler_path_untrusted_root_and_owner_block(self) -> None:
        directory = self.scratch("compiler")
        with self.assertRaisesRegex(MODULE.Refused, "PATH substitution refused"):
            MODULE.verify_compiler(Path("ISCC.exe"), "x64", PIN)

        evil = directory / "evil" / "ISCC.exe"
        evil.parent.mkdir()
        evil.write_bytes(build_pe())
        evil.chmod(0o444)
        with self.assertRaisesRegex(MODULE.Refused, "untrusted installation root"):
            MODULE.verify_compiler(evil, "x64", PIN)

        trusted_shape = directory / "Inno Setup 7" / "ISCC.exe"
        trusted_shape.parent.mkdir()
        trusted_shape.write_bytes(build_pe())
        trusted_shape.chmod(0o444)
        unmeasured = write_unmeasured_pin(self.scratch("compiler-unmeasured"))
        with self.assertRaisesRegex(MODULE.Refused, "ISCC x64 pin not measured"):
            MODULE.verify_compiler(trusted_shape, "x64", unmeasured)
        with self.assertRaisesRegex(MODULE.Refused, "ISCC arm64 pin not measured"):
            MODULE.verify_compiler(trusted_shape, "arm64", unmeasured)
        with self.assertRaisesRegex(MODULE.Refused, "compiler SHA-256 mismatch"):
            MODULE.verify_compiler(trusted_shape, "x64", PIN)
        with self.assertRaisesRegex(MODULE.Refused, "compiler architecture is unsupported"):
            MODULE.verify_compiler(trusted_shape, "x86", PIN)

    def test_cli_refuses_upload_and_setup_execution_tokens(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(TOOL), "verify-pins", "upload"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("refusing to execute a setup candidate or upload artifact", completed.stderr)

        completed = subprocess.run(
            [sys.executable, str(TOOL), "verify-installer", "--arch", "x64", "--path", "C:\\setup.exe", "/SILENT"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("refusing to execute a setup candidate or upload artifact", completed.stderr)

    def test_full_verify_installer_requires_windows_trust(self) -> None:
        directory = self.scratch("chain")
        candidate = directory / "innosetup-7.1.0-x64.exe"
        candidate.write_bytes(b"placeholder")
        candidate.chmod(0o444)
        if os.name == "nt":
            with self.assertRaises(MODULE.Refused):
                MODULE.verify_installer(candidate, "x64", PIN)
        else:
            with self.assertRaisesRegex(MODULE.Refused, "Authenticode chain verification requires Windows|SHA-256 mismatch"):
                MODULE.verify_installer(candidate, "x64", PIN)

    def test_python_and_powershell_never_execute_or_upload(self) -> None:
        python = TOOL.read_text(encoding="utf-8")
        powershell = POWERSHELL.read_text(encoding="utf-8")
        self.assertNotIn("Start-Process", python)
        self.assertNotIn("Invoke-WebRequest", python)
        self.assertNotIn("Get-Command", python)
        self.assertNotIn("INNO_SETUP_ISCC", python)
        self.assertNotIn("Start-Process", powershell)
        self.assertNotIn("Invoke-WebRequest", powershell)
        self.assertNotIn("Get-Command", powershell)
        self.assertNotIn("INNO_SETUP_ISCC", powershell)
        self.assertNotIn("$env:PATH", powershell)
        self.assertNotIn("subprocess", python)
        self.assertNotIn("urllib.request", python)
        self.assertIn("winget install", python)
        self.assertIn("WinVerifyTrust", python)
        self.assertIn("WinVerifyTrust", powershell)
        self.assertIn("NumberOfLinks", powershell)
        self.assertIn("GetFileInformationByHandle", powershell)
        self.assertIn("PATH substitution refused", powershell)
        self.assertIn("untrusted installation root", powershell)
        self.assertIn("hardlink refused", powershell)
        self.assertIn("reparse point rejected", powershell)
        self.assertNotIn("$env:PATH", powershell)
        self.assertIn("OFFICIAL_ISSIG_KEYS", python)
        self.assertIn("immutable_code_constants", python)
        self.assertIn("pkcs7_signerinfo_issuer_serial", python)
        self.assertIn("PathnameIdentityEqual", powershell)
        self.assertIn("_pathname_identity", python)
        self.assertIn("_POST_PARENT_BIND_HOOK", python)
        self.assertIn("descriptor-relative", python.lower() + powershell.lower())

    def test_retrieved_utc_must_be_exact_iso_utc(self) -> None:
        official = load_official()
        cases = [
            "2026-08-24T22:11:15+00:00",
            "2026-08-24T22:11:15.000Z",
            "2026-08-24 22:11:15Z",
            "2026-08-24T22:11:15z",
            "2026-07-31T23:59:59Z",
            "2099-01-01T00:00:00Z",
        ]
        for index, value in enumerate(cases):
            with self.subTest(value=value):
                document = copy.deepcopy(official)
                document["retrieved_utc"] = value
                pin = self.scratch(f"utc-{index}") / "inno-toolchain-pins.json"
                write_json(pin, document)
                with self.assertRaisesRegex(
                    MODULE.Refused,
                    "exact ISO UTC|reviewed issuance bound|reviewed freshness",
                ):
                    MODULE.load_pin(pin)

        document = copy.deepcopy(official)
        document["official_sources"]["downloads"]["retrieved_utc"] = "2026-08-22T22:11:15Z"
        pin = self.scratch("utc-fresh") / "inno-toolchain-pins.json"
        write_json(pin, document)
        with self.assertRaisesRegex(MODULE.Refused, "reviewed freshness bound"):
            MODULE.load_pin(pin)

    def test_renamed_pyrsys_installer_is_not_iscc(self) -> None:
        directory = self.scratch("renamed-installer")
        compiler = directory / "Inno Setup 7" / "ISCC.exe"
        compiler.parent.mkdir()
        if LIVE_X64.is_file():
            shutil.copyfile(LIVE_X64, compiler)
        else:
            compiler.write_bytes(
                build_pe(
                    authenticode=True,
                    version={
                        "CompanyName": "jrsoftware.org",
                        "FileDescription": "Inno Setup Setup",
                        "ProductName": "Inno Setup",
                        "ProductVersion": "7.1.0",
                    },
                )
            )
        compiler.chmod(0o444)
        with self.assertRaisesRegex(
            MODULE.Refused, "compiler identity must be ISCC.exe, not the Pyrsys installer"
        ):
            MODULE.verify_compiler(compiler, "x64", PIN)

    def test_suffix_filename_is_not_the_pinned_installer(self) -> None:
        directory = self.scratch("suffix-name")
        candidate = directory / "evil-innosetup-7.1.0-x64.exe"
        candidate.write_bytes(b"not-official")
        candidate.chmod(0o444)
        with self.assertRaisesRegex(MODULE.Refused, "installer filename mismatch"):
            MODULE.verify_installer_identity(candidate, "x64", PIN)
        completed = run_powershell(
            "-VerifyInstaller",
            "-Architecture",
            "x64",
            "-Path",
            str(candidate),
            "-PinPath",
            str(PIN),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, "installer filename mismatch")
        self.assertNotRegex(POWERSHELL.read_text(encoding="utf-8"), r"EndsWith\(")

    def test_mixed_old_new_install_tree_fails(self) -> None:
        root = self.scratch("mixed-tree") / "Inno Setup 7"
        root.mkdir()
        compiler = root / "ISCC.exe"
        helper = root / "helper.dll"
        compiler.write_bytes(b"compiler-bytes")
        helper.write_bytes(b"helper-a")
        compiler.chmod(0o444)
        helper.chmod(0o644)
        tree = MODULE.snapshot_install_tree(root)
        try:
            helper.write_bytes(b"helper-b")
            helper.chmod(0o644)
            with self.assertRaisesRegex(
                MODULE.Refused,
                "mutated while it was inspected|pathname identity changed|mixed old/new",
            ):
                tree.assert_unchanged("ISCC install tree")
        finally:
            tree.close()

        first = MODULE.install_tree_digest(root)
        extra = root / "extra.dll"
        extra.write_bytes(b"extra")
        extra.chmod(0o644)
        second = MODULE.install_tree_digest(root)
        self.assertNotEqual(first, second)

    def test_live_official_x64_cms_reaches_windows_trust(self) -> None:
        if not (
            LIVE_X64.is_file()
            and hashlib.sha256(LIVE_X64.read_bytes()).hexdigest()
            == "0362a383ed217d4c4239b5933866dd96d3eb2102737da92f80f6057a4b40df2f"
        ):
            self.skipTest("independently retrieved official 7.1.0 x64 installer is not present")
        leaf = MODULE.authenticode_leaf(LIVE_X64.read_bytes())
        self.assertEqual(leaf["publisher_name"], "Pyrsys B.V.")
        self.assertEqual(leaf["serial"], "b208315c09c02ef1550e0c8d127cf499")
        self.assertEqual(
            leaf["sha256"],
            "4efd84e6f1091b19321231743b9aa86482effd6d0bea9f7a44db6211154616f3",
        )
        completed = run_powershell(
            "-VerifyInstaller",
            "-Architecture",
            "x64",
            "-Path",
            str(LIVE_X64),
            "-PinPath",
            str(PIN),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, "Authenticode chain verification requires Windows")
        self.assertNotRegex(completed.stderr, "SignerInfo does not resolve")

    def test_powershell_pin_bind_uses_one_held_handle(self) -> None:
        powershell = POWERSHELL.read_text(encoding="utf-8")
        self.assertIn("BindRegularFile($full, 'Inno toolchain pin'", powershell)
        self.assertNotIn("[IO.File]::ReadAllBytes", powershell)
        self.assertIn("AssertUnchanged($loaded.Bound, 'Inno toolchain pin')", powershell)
        completed = run_powershell("-VerifyPins", "-PinPath", str(PIN))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("status|pinned", completed.stdout)

    def test_powershell_syntax_when_available(self) -> None:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        command = (
            "$t=$null;$e=$null;"
            "[void][Management.Automation.Language.Parser]::ParseFile("
            f"'{POWERSHELL.as_posix()}',[ref]$t,[ref]$e);"
            "if($e.Count){$e|% Message;exit 1}"
        )
        completed = subprocess.run(
            [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_powershell_duplicate_and_extra_json_fail(self) -> None:
        directory = self.scratch("ps-dup")
        pin = directory / "inno-toolchain-pins.json"
        text = PIN.read_text(encoding="utf-8").replace(
            '"version": "7.1.0"',
            '"version": "7.1.0", "version": "7.1.0"',
            1,
        )
        pin.write_text(text, encoding="utf-8")
        pin.chmod(0o444)
        completed = run_powershell("-VerifyPins", "-PinPath", str(pin))
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, "duplicate JSON key")

        official = load_official()
        official["extra"] = True
        extra = self.scratch("ps-extra") / "inno-toolchain-pins.json"
        write_json(extra, official)
        completed = run_powershell("-VerifyPins", "-PinPath", str(extra))
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, "unexpected pin field")

        official = load_official()
        official["schema_version"] = True
        coerced = self.scratch("ps-bool") / "inno-toolchain-pins.json"
        write_json(coerced, official)
        completed = run_powershell("-VerifyPins", "-PinPath", str(coerced))
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, "type coercion refused")

        official = load_official()
        completed = run_powershell("-VerifyPins", "-PinPath", str(PIN))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("installers_pinned|True", completed.stdout)

        official["installers"]["windows_x64"]["issig_sig_s"] = "1" * 64
        mutated = self.scratch("ps-ecdsa") / "inno-toolchain-pins.json"
        write_json(mutated, official)
        completed = run_powershell("-VerifyPins", "-PinPath", str(mutated))
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, "ECDSA-P256")

    def test_parent_swap_is_detected(self) -> None:
        directory = self.scratch("parent-swap")
        parent = directory / "hold"
        parent.mkdir()
        candidate = parent / "innosetup-7.1.0-x64.exe"
        candidate.write_bytes(b"snapshot-bytes")
        candidate.chmod(0o444)
        snapshot = MODULE.bind_regular_snapshot(candidate, "installer", maximum=MODULE.MAX_INSTALLER)
        try:
            snapshot.assert_unchanged("installer")
            os.rename(parent, directory / "hold.old")
            parent.mkdir()
            replacement = parent / "innosetup-7.1.0-x64.exe"
            replacement.write_bytes(b"replacement-bytes")
            replacement.chmod(0o444)
            with self.assertRaisesRegex(MODULE.Refused, "parent path component mutated|mutated while it was inspected"):
                snapshot.assert_unchanged("installer")
        finally:
            snapshot.close()

    def test_exact_parent_swap_restore_and_symlink_are_detected(self) -> None:
        directory = self.scratch("parent-swap-restore")
        parent = directory / "hold"
        parent.mkdir()
        candidate = parent / "innosetup-7.1.0-x64.exe"
        candidate.write_bytes(b"snapshot-bytes")
        candidate.chmod(0o444)
        attacker = directory / "attacker"
        attacker.mkdir()
        (attacker / candidate.name).write_bytes(b"attacker-bytes")
        decoy = directory / "decoy"
        decoy.mkdir()
        (decoy / candidate.name).write_bytes(b"decoy-bytes")
        snapshot = MODULE.bind_regular_snapshot(candidate, "installer", maximum=MODULE.MAX_INSTALLER)
        try:
            os.rename(parent, directory / "hold.old")
            os.rename(attacker, parent)
            os.rename(parent, directory / "hold.attacker")
            os.rename(decoy, parent)
            with self.assertRaisesRegex(
                MODULE.Refused, "parent path component mutated|mutated while it was inspected"
            ):
                snapshot.assert_unchanged("installer")
        finally:
            snapshot.close()

        nested = self.scratch("parent-symlink") / "hold"
        nested.mkdir()
        linked = nested / "innosetup-7.1.0-x64.exe"
        linked.write_bytes(b"link-target-bytes")
        linked.chmod(0o444)
        file_index = len(linked.parts) - 2

        def replace_with_symlink(_path: Path, index: int) -> None:
            if index != file_index:
                return
            os.rename(nested, nested.parent / "hold.old")
            os.symlink(nested.parent / "hold.old", nested)

        MODULE._POST_PARENT_BIND_HOOK = replace_with_symlink
        try:
            with self.assertRaisesRegex(
                MODULE.Refused,
                "symbolic path component rejected|parent path component mutated|mutated while it was inspected",
            ):
                MODULE.bind_regular_snapshot(linked, "installer", maximum=MODULE.MAX_INSTALLER)
        finally:
            MODULE._POST_PARENT_BIND_HOOK = None

        swapped = self.scratch("parent-bind-swap") / "hold"
        swapped.mkdir()
        target = swapped / "innosetup-7.1.0-x64.exe"
        target.write_bytes(b"bind-swap-bytes")
        target.chmod(0o444)
        other = swapped.parent / "other"
        other.mkdir()
        (other / target.name).write_bytes(b"other-bytes")
        bind_index = len(target.parts) - 2

        def swap_parent(_path: Path, index: int) -> None:
            if index != bind_index:
                return
            os.rename(swapped, swapped.parent / "hold.old")
            os.rename(other, swapped)

        MODULE._POST_PARENT_BIND_HOOK = swap_parent
        try:
            with self.assertRaisesRegex(
                MODULE.Refused, "parent path component mutated|mutated while it was inspected"
            ):
                MODULE.bind_regular_snapshot(target, "installer", maximum=MODULE.MAX_INSTALLER)
        finally:
            MODULE._POST_PARENT_BIND_HOOK = None

    def test_cleanup_race_is_detected(self) -> None:
        directory = self.scratch("cleanup-race")
        parent = directory / "hold"
        parent.mkdir()
        candidate = parent / "innosetup-7.1.0-x64.exe"
        candidate.write_bytes(b"cleanup-bytes")
        candidate.chmod(0o444)
        snapshot = MODULE.bind_regular_snapshot(candidate, "installer", maximum=MODULE.MAX_INSTALLER)
        try:
            os.rename(parent, directory / "hold.old")
            with self.assertRaisesRegex(
                MODULE.Refused,
                "parent path component mutated|mutated while it was inspected|unreadable",
            ):
                snapshot.assert_unchanged("installer")
        finally:
            snapshot.close()

    def test_pathname_identity_ignores_directory_mtime_size_and_nlink(self) -> None:
        directory = self.scratch("ident-stable")
        child = directory / "child.bin"
        child.write_bytes(b"ident-bytes")
        child.chmod(0o444)
        before = MODULE._pathname_identity(os.lstat(directory))
        (directory / "sibling").mkdir()
        os.utime(directory, None)
        after = MODULE._pathname_identity(os.lstat(directory))
        self.assertEqual(before, after)
        self.assertEqual(len(before), 5)
        file_before = MODULE._identity(os.lstat(child))
        os.utime(child, None)
        file_after = MODULE._identity(os.lstat(child))
        self.assertNotEqual(file_before, file_after)

    def test_windows_identity_matches_fstat_and_lstat_of_one_unchanged_exe(self) -> None:
        # Values measured on Windows 11 26300 with python.org CPython 3.14.7
        # for one unchanged C:\Windows\System32\curl.exe: lstat() adds execute
        # bits from the .exe extension and reports st_ctime as the creation
        # time; fstat() on the open handle reports neither.
        common = {
            "st_dev": 599548479228222678,
            "st_ino": 1970324837179871,
            "st_nlink": 1,
            "st_uid": 0,
            "st_gid": 0,
            "st_size": 4096,
            "st_mtime_ns": 1789323820700347800,
            "st_birthtime_ns": 1789323820667887800,
            "st_file_attributes": 32,
        }
        held = types.SimpleNamespace(
            st_mode=0o100666, st_ctime_ns=1792095587157626400, **common
        )
        by_name = types.SimpleNamespace(
            st_mode=0o100777, st_ctime_ns=1789323820667887800, **common
        )
        with mock.patch.object(MODULE.os, "name", "nt"):
            self.assertEqual(MODULE._identity(held), MODULE._identity(by_name))
            for field, value in (
                ("st_size", 4097),
                ("st_mtime_ns", 1789323820700347801),
                ("st_birthtime_ns", 1789323820667887801),
                ("st_ino", 1970324837179872),
                ("st_file_attributes", 33),
                ("st_mode", 0o100444),
            ):
                changed = types.SimpleNamespace(**{**vars(by_name), field: value})
                self.assertNotEqual(
                    MODULE._identity(held), MODULE._identity(changed), field
                )
        if os.name != "nt":
            self.assertNotEqual(MODULE._identity(held), MODULE._identity(by_name))

    def test_sibling_churn_does_not_false_positive_python(self) -> None:
        directory = self.scratch("py-churn")
        candidate = directory / "innosetup-7.1.0-x64.exe"
        candidate.write_bytes(b"churn-stable-bytes")
        candidate.chmod(0o444)
        stop = threading.Event()
        errors: list[BaseException] = []
        cycles = {"n": 0}

        def worker() -> None:
            try:
                while not stop.is_set():
                    _churn_tmp_siblings(f"thr-{cycles['n']}")
                    cycles["n"] += 1
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        MODULE._POST_PARENT_BIND_HOOK = _churn_bound_ancestors
        try:
            for _ in range(8):
                snapshot = MODULE.bind_regular_snapshot(
                    candidate, "installer", maximum=MODULE.MAX_INSTALLER
                )
                try:
                    snapshot.assert_unchanged("installer")
                    MODULE.load_pin(PIN)
                finally:
                    snapshot.close()
            if LIVE_X64.is_file():
                live = MODULE.bind_regular_snapshot(
                    LIVE_X64, "installer", maximum=MODULE.MAX_INSTALLER
                )
                try:
                    live.assert_unchanged("installer")
                finally:
                    live.close()
        finally:
            MODULE._POST_PARENT_BIND_HOOK = None
            stop.set()
            thread.join(timeout=5)
        self.assertFalse(errors)
        self.assertGreater(cycles["n"], 0)

    def test_sibling_churn_does_not_false_positive_powershell(self) -> None:
        directory = self.scratch("ps-churn")
        pin = directory / "inno-toolchain-pins.json"
        shutil.copyfile(PIN, pin)
        pin.chmod(0o444)
        candidate = directory / "probe.bin"
        candidate.write_bytes(b"powershell-churn-bytes")
        candidate.chmod(0o444)
        stop = threading.Event()
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                for index in range(40):
                    _churn_tmp_siblings(f"ps-{index}")
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            completed = run_powershell("-VerifyPins", "-PinPath", str(pin))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("status|pinned", completed.stdout)
            probe = run_powershell(
                "-CustodySelfTest",
                "-CustodySelfTestKind",
                "sibling-churn",
                "-Path",
                str(candidate),
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertIn("CUSTODY_SELFTEST|sibling-churn|ok", probe.stdout)
            if LIVE_X64.is_file():
                live = run_powershell(
                    "-VerifyInstaller",
                    "-Architecture",
                    "x64",
                    "-Path",
                    str(LIVE_X64),
                    "-PinPath",
                    str(PIN),
                )
                self.assertNotEqual(live.returncode, 0)
                self.assertRegex(live.stderr, "Authenticode chain verification requires Windows")
                self.assertNotRegex(live.stderr, "parent path component mutated")
        finally:
            stop.set()
            thread.join(timeout=5)
        self.assertFalse(errors)

    def test_powershell_parent_swap_and_restore_are_detected(self) -> None:
        directory = self.scratch("ps-parent-swap")
        parent = directory / "hold"
        parent.mkdir()
        candidate = parent / "innosetup-7.1.0-x64.exe"
        candidate.write_bytes(b"ps-snapshot-bytes")
        candidate.chmod(0o444)
        swapped = run_powershell(
            "-CustodySelfTest",
            "-CustodySelfTestKind",
            "parent-swap",
            "-Path",
            str(candidate),
        )
        self.assertEqual(swapped.returncode, 0, swapped.stderr)
        self.assertIn("CUSTODY_SELFTEST|parent-swap|ok", swapped.stdout)
        restored = run_powershell(
            "-CustodySelfTest",
            "-CustodySelfTestKind",
            "parent-swap-restore",
            "-Path",
            str(candidate),
        )
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertIn("CUSTODY_SELFTEST|parent-swap-restore|ok", restored.stdout)

    def test_thirty_concurrent_binds_survive_tempfile_churn(self) -> None:
        stop = threading.Event()
        errors: list[BaseException] = []
        cycles = {"n": 0}

        def churner() -> None:
            try:
                while not stop.is_set():
                    _churn_tmp_siblings(f"conc-{cycles['n']}")
                    cycles["n"] += 1
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=churner, daemon=True)
        thread.start()

        def worker(index: int) -> None:
            directory = self.scratch(f"conc-{index}")
            candidate = directory / "innosetup-7.1.0-x64.exe"
            candidate.write_bytes(f"concurrent-bytes-{index}".encode("ascii"))
            candidate.chmod(0o444)
            snapshot = MODULE.bind_regular_snapshot(
                candidate, "installer", maximum=MODULE.MAX_INSTALLER
            )
            try:
                for _ in range(4):
                    snapshot.assert_unchanged("installer")
                    _churn_tmp_siblings(f"w{index}")
            finally:
                snapshot.close()
            MODULE.load_pin(PIN)

        try:
            with futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(worker, range(30)))
            pins = run_powershell("-VerifyPins", "-PinPath", str(PIN))
            self.assertEqual(pins.returncode, 0, pins.stderr)
            self.assertIn("compilers_pinned|True", pins.stdout)
            self.assertIn("status|pinned", pins.stdout)
        finally:
            stop.set()
            thread.join(timeout=5)
        self.assertFalse(errors)
        self.assertGreater(cycles["n"], 0)


    def test_verify_to_trust_swap_is_detected(self) -> None:
        directory = self.scratch("verify-trust-swap")
        candidate = directory / "innosetup-7.1.0-x64.exe"
        candidate.write_bytes(b"original-identity-bytes")
        candidate.chmod(0o444)
        snapshot = MODULE.bind_regular_snapshot(candidate, "installer", maximum=MODULE.MAX_INSTALLER)
        try:
            os.unlink(candidate)
            candidate.write_bytes(b"swapped-before-trust")
            candidate.chmod(0o444)
            with self.assertRaisesRegex(MODULE.Refused, "mutated while it was inspected"):
                snapshot.assert_unchanged("installer")
        finally:
            snapshot.close()

    def test_missing_sidecar_fails(self) -> None:
        directory = self.scratch("missing-sidecar")
        candidate = directory / "innosetup-7.1.0-x64.exe"
        candidate.write_bytes(b"sidecar-missing")
        candidate.chmod(0o444)
        snapshot = MODULE.bind_regular_snapshot(candidate, "installer", maximum=MODULE.MAX_INSTALLER)
        try:
            with self.assertRaisesRegex(MODULE.Refused, "issig sidecar is required"):
                MODULE._verify_issig_sidecar(
                    candidate,
                    snapshot,
                    self.pin["installers"]["windows_x64"],
                    self.pin["keys"],
                )
        finally:
            snapshot.close()

    def test_install_tree_substitution_changes_digest(self) -> None:
        root = self.scratch("tree") / "Inno Setup 7"
        root.mkdir()
        compiler = root / "ISCC.exe"
        compiler.write_bytes(b"compiler-bytes")
        helper = root / "helper.dll"
        helper.write_bytes(b"helper-a")
        compiler.chmod(0o444)
        helper.chmod(0o644)
        first = MODULE.install_tree_digest(root)
        helper.write_bytes(b"helper-b")
        helper.chmod(0o644)
        second = MODULE.install_tree_digest(root)
        self.assertNotEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, compiler.stat().st_size and hashlib.sha256(compiler.read_bytes()).hexdigest())

    def test_fake_vs_version_info_overlay_is_ignored(self) -> None:
        fake = "VS_VERSION_INFO".encode("utf-16le")
        overlay = b"\x00\x01" + fake + "ProductVersion\x009.9.9\x00".encode("utf-16le")
        with self.assertRaisesRegex(MODULE.Refused, "VERSIONINFO resource"):
            MODULE.version_strings(build_pe(authenticode=True, overlay=overlay))
        real = build_pe(
            authenticode=True,
            version={
                "CompanyName": "jrsoftware.org",
                "FileDescription": "Inno Setup Setup",
                "ProductName": "Inno Setup",
                "ProductVersion": "7.1.0",
            },
            overlay=overlay,
        )
        versions = MODULE.version_strings(real)
        self.assertEqual(versions["ProductVersion"], "7.1.0")
        self.assertNotEqual(versions["ProductVersion"], "9.9.9")

    def test_signer_confusion_pkcs7_uses_signerinfo_not_bag(self) -> None:
        pyrsys_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        bag_pyrsys = make_cert(cn="Pyrsys B.V.", org="Pyrsys B.V.", key=pyrsys_key, serial=0x1111)
        attacker = make_cert(cn="Attacker", org="Evil Corp", key=attacker_key, serial=0x2222)
        pkcs7 = encode_pkcs7([bag_pyrsys, attacker], attacker)
        parsed = MODULE.parse_pkcs7_signer(pkcs7)
        self.assertEqual(parsed["serial"], 0x2222)
        pe = build_pe(pkcs7=pkcs7)
        with self.assertRaisesRegex(MODULE.Refused, "Pyrsys B.V. leaf"):
            MODULE.authenticode_leaf(pe)

    def test_certificate_bomb_is_bounded(self) -> None:
        tiny = tlv(0x30, encode_int(1))
        cert_set = tiny * 9
        signed = tlv(
            0x30,
            encode_int(1)
            + tlv(0x31, b"")
            + tlv(0x30, encode_oid("1.2.840.113549.1.7.1"))
            + tlv(0xA0, cert_set)
            + tlv(0x31, tlv(0x30, encode_int(1))),
        )
        bomb = tlv(0x30, encode_oid("1.2.840.113549.1.7.2") + tlv(0xA0, signed))
        with self.assertRaisesRegex(MODULE.Refused, "certificate count bound exceeded"):
            MODULE.parse_pkcs7_signer(bomb)

        huge = tlv(
            0x30,
            encode_oid("1.2.840.113549.1.7.2")
            + tlv(0xA0, tlv(0x30, encode_int(1) + tlv(0x31, b"") + tlv(0x30, b"") + bytes([0xA0, 0x84, 0x1F, 0xFF, 0xFF, 0xFF]) + b"\x00" * 8)),
        )
        with self.assertRaisesRegex(MODULE.Refused, "DER length is malformed|size bound exceeded|truncated"):
            MODULE.parse_pkcs7_signer(huge)

    @unittest.skipUnless(
        LIVE_X64.is_file()
        and hashlib.sha256(LIVE_X64.read_bytes()).hexdigest()
        == "0362a383ed217d4c4239b5933866dd96d3eb2102737da92f80f6057a4b40df2f",
        "independently retrieved official 7.1.0 x64 installer is not present",
    )
    def test_live_official_x64_installer_identity(self) -> None:
        result = MODULE.verify_installer_identity(LIVE_X64, "x64", PIN)
        self.assertEqual(result["publisher"], "Pyrsys B.V.")
        self.assertEqual(
            result["sha256"],
            "0362a383ed217d4c4239b5933866dd96d3eb2102737da92f80f6057a4b40df2f",
        )
        if LIVE_X64_ISSIG.is_file():
            self.assertEqual(
                hashlib.sha256(LIVE_X64_ISSIG.read_bytes()).hexdigest(),
                self.pin["installers"]["windows_x64"]["issig_sha256"],
            )
        if os.name != "nt":
            with self.assertRaisesRegex(MODULE.Refused, "Authenticode chain verification requires Windows"):
                MODULE.verify_installer(LIVE_X64, "x64", PIN)


class InnoCompilerExactCustodyMutationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = Path(tempfile.mkdtemp(prefix="wins-inno-compiler-", dir="/private/tmp"))
        cls.base.chmod(0o700)
        unmeasured_dir = cls.base / "unmeasured-official"
        unmeasured_dir.mkdir()
        cls.unmeasured_pin = write_unmeasured_pin(unmeasured_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.base, ignore_errors=True)

    def scratch(self, name: str) -> Path:
        directory = self.base / name
        directory.mkdir(parents=True)
        return directory

    def write_compiler(self, name: str, payload: bytes) -> tuple[Path, str, int, str]:
        root = self.scratch(name) / "Inno Setup 7"
        root.mkdir()
        compiler = root / "ISCC.exe"
        compiler.write_bytes(payload)
        compiler.chmod(0o444)
        digest = hashlib.sha256(payload).hexdigest()
        tree = MODULE.install_tree_digest(root)
        self.assertNotEqual(digest, tree)
        return compiler, digest, len(payload), tree

    def write_pinned_pin(
        self,
        name: str,
        *,
        sha256: str,
        size: int,
        tree: str,
        product_version: str = "0.0.0.0",
    ) -> Path:
        document = pin_compilers(
            load_official(),
            sha256=sha256,
            size=size,
            tree=tree,
            product_version=product_version,
        )
        pin = self.scratch(name) / "inno-toolchain-pins.json"
        write_json(pin, document)
        return pin

    def test_schema_and_example_are_ascii_and_example_compilers_are_pinned(self) -> None:
        schema = ROOT / "tools" / "inno-toolchain-pins.schema.json"
        example = ROOT / "tools" / "inno-toolchain-pins.example.json"
        schema_text = schema.read_text(encoding="ascii")
        example_text = example.read_text(encoding="ascii")
        self.assertIn("winsvpn-inno-toolchain-custody-v1", schema_text)
        self.assertIn("winsvpn-inno-compiler-receipt-v1", schema_text)
        self.assertIn("install_tree_sha256", schema_text)
        example_document = json.loads(example_text)
        # The example carries both compilers pinned, so the loader requires
        # top-level status "pinned" and no owner_blockers field.
        normalized = copy.deepcopy(example_document)
        normalized["status"] = "pinned"
        normalized.pop("owner_blockers", None)
        normalized_pin = self.scratch("example-normalized") / "inno-toolchain-pins.json"
        write_json(normalized_pin, normalized)
        loaded = MODULE.load_pin(normalized_pin)
        self.assertTrue(loaded["compilers_pinned"])
        self.assertEqual(loaded["status"], "pinned")
        self.assertEqual(example_document["compilers"]["windows_x64"]["status"], "pinned")
        self.assertEqual(
            example_document["compilers"]["windows_x64"]["sha256"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        self.assertNotEqual(
            example_document["compilers"]["windows_x64"]["sha256"],
            example_document["compilers"]["windows_x64"]["install_tree_sha256"],
        )
        official = MODULE.load_pin(PIN)
        self.assertTrue(official["compilers_pinned"])
        self.assertEqual(official["compilers"]["windows_x64"]["sha256"], MEASURED_ISCC["sha256"])

    def test_unmeasured_compiler_pin_still_fails_closed(self) -> None:
        compiler, _digest, _size, _tree = self.write_compiler("owner-absent", compiler_pe())
        with self.assertRaisesRegex(
            MODULE.Refused,
            r"\AISCC x64 pin not measured; run verify-compiler --measure on a Windows host and "
            r"record the printed values in tools/inno-toolchain-pins\.json\Z",
        ):
            MODULE.verify_compiler(compiler, "x64", self.unmeasured_pin)
        with self.assertRaisesRegex(MODULE.Refused, "compiler SHA-256 mismatch"):
            MODULE.verify_compiler(compiler, "x64", PIN)

    def write_status_pin(self, name: str, document: dict) -> Path:
        pin = self.scratch(name) / "inno-toolchain-pins.json"
        write_json(pin, document)
        return pin

    def test_pin_status_is_pinned_only_when_both_compilers_carry_complete_pins(self) -> None:
        both = pin_compilers(load_official(), sha256="aa" * 32, size=4096, tree="bb" * 32)
        both["status"] = "pinned"
        pinned_pin = self.write_status_pin("status-pinned", both)
        result = MODULE.verify_pins(pinned_pin)
        self.assertEqual(result["status"], "pinned")
        self.assertTrue(result["compilers_pinned"])
        self.assertNotIn("owner_blockers", result)
        completed = subprocess.run(
            [sys.executable, str(TOOL), "verify-pins", "--pin", str(pinned_pin)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("status|pinned", completed.stdout)
        self.assertIn("compilers_pinned|True", completed.stdout)

        mixed = load_unmeasured()
        record = mixed["compilers"]["windows_x64"]
        record.update(
            status="pinned",
            sha256="aa" * 32,
            size=4096,
            install_tree_sha256="bb" * 32,
            product_version_string="0.0.0.0",
        )
        mixed_pin = self.write_status_pin("status-mixed", mixed)
        loaded = MODULE.load_pin(mixed_pin)
        self.assertEqual(loaded["status"], "unmeasured")
        self.assertFalse(loaded["compilers_pinned"])
        compiler, _digest, _size, _tree = self.write_compiler("status-mixed-iscc", compiler_pe())
        with self.assertRaisesRegex(MODULE.Refused, "ISCC arm64 pin not measured"):
            MODULE.verify_compiler(compiler, "arm64", mixed_pin)

        refused = [
            ("pinned-with-unmeasured", load_unmeasured(), "pinned", "expected unmeasured"),
            ("unmeasured-with-pinned", copy.deepcopy(both), "unmeasured", "expected pinned"),
            ("pinned-with-mixed", copy.deepcopy(mixed), "pinned", "expected unmeasured"),
            ("legacy-owner-status", load_unmeasured(), "owner_inputs_required", "expected unmeasured"),
        ]
        for name, document, status, expected in refused:
            with self.subTest(case=name):
                document["status"] = status
                with self.assertRaisesRegex(
                    MODULE.Refused,
                    "pin status must be pinned when both compilers carry complete pins, "
                    f"otherwise unmeasured: {expected}",
                ):
                    MODULE.load_pin(self.write_status_pin(f"status-{name}", document))

        legacy = load_official()
        legacy["owner_blockers"] = []
        with self.assertRaisesRegex(MODULE.Refused, "unexpected pin field rejected: pin.owner_blockers"):
            MODULE.load_pin(self.write_status_pin("status-legacy-blockers", legacy))
        legacy_record = load_official()
        legacy_record["compilers"]["windows_x64"]["status"] = "owner_inputs_required"
        with self.assertRaisesRegex(MODULE.Refused, "compiler status is unsupported: windows_x64"):
            MODULE.load_pin(self.write_status_pin("status-legacy-record", legacy_record))

        if shutil.which("pwsh") or shutil.which("powershell"):
            ps_pinned = run_powershell("-VerifyPins", "-PinPath", str(pinned_pin))
            self.assertEqual(ps_pinned.returncode, 0, ps_pinned.stderr)
            self.assertIn("status|pinned", ps_pinned.stdout)
            ps_mismatch = run_powershell(
                "-VerifyPins",
                "-PinPath",
                str(self.write_status_pin("ps-status-mismatch", dict(load_unmeasured(), status="pinned"))),
            )
            self.assertNotEqual(ps_mismatch.returncode, 0)
            self.assertRegex(ps_mismatch.stderr, "pin status must be pinned when both compilers")
            ps_unmeasured = run_powershell(
                "-VerifyCompiler", "-Architecture", "x64", "-Path", str(compiler), "-PinPath",
                str(self.unmeasured_pin),
            )
            self.assertNotEqual(ps_unmeasured.returncode, 0)
            self.assertRegex(ps_unmeasured.stderr, "ISCC x64 pin not measured")
            self.assertNotRegex(ps_unmeasured.stderr, "OWNER INPUT REQUIRED")

    def _trusted_windows_signer(self):
        leaf = {
            "publisher_name": MODULE.OFFICIAL_PUBLISHER["authenticode_publisher_name"],
            "subject": MODULE.OFFICIAL_PUBLISHER["authenticode_subject_rfc4514"],
            "issuer": MODULE.OFFICIAL_PUBLISHER["authenticode_issuer_rfc4514"],
            "serial": MODULE.OFFICIAL_PUBLISHER["authenticode_leaf_serial_hex"],
            "sha256": MODULE.OFFICIAL_PUBLISHER["authenticode_leaf_sha256"],
            "raw": b"",
        }
        trust_calls: list[str] = []

        def trusted_chain(snapshot: object) -> None:
            trust_calls.append(str(getattr(snapshot, "path")))

        return (
            mock.patch.object(MODULE, "authenticode_leaf", lambda _data: dict(leaf)),
            mock.patch.object(MODULE, "verify_authenticode_chain_bound", trusted_chain),
            trust_calls,
        )

    def test_measure_reports_the_values_verify_then_accepts(self) -> None:
        compiler, digest, size, tree = self.write_compiler("measure-roundtrip", compiler_pe())
        helper = compiler.parent / "Default.isl"
        helper.write_bytes(b"helper-language-file")
        helper.chmod(0o444)
        tree = MODULE.install_tree_digest(compiler.parent)
        pin_before = PIN.read_bytes()
        pin_stat_before = os.lstat(PIN)
        leaf_patch, chain_patch, trust_calls = self._trusted_windows_signer()
        with leaf_patch, chain_patch:
            with self.assertRaisesRegex(MODULE.Refused, "ISCC x64 pin not measured"):
                MODULE.verify_compiler(compiler, "x64", self.unmeasured_pin)
            measured = MODULE.verify_compiler(compiler, "x64", PIN, measure=True)
            self.assertEqual(
                measured,
                {
                    "mode": "measure",
                    "pin_record": "compilers.windows_x64",
                    "architecture": "x64",
                    "sha256": digest,
                    "size": size,
                    "install_tree_sha256": tree,
                    "product_version_string": "0.0.0.0",
                },
            )
            self.assertEqual(trust_calls, [str(compiler)])
            arm = MODULE.verify_compiler(compiler, "arm64", PIN, measure=True)
            self.assertEqual(arm["pin_record"], "compilers.windows_arm64")
            self.assertEqual(arm["sha256"], digest)
            pinned = pin_compilers(
                load_official(),
                sha256=measured["sha256"],
                size=measured["size"],
                tree=measured["install_tree_sha256"],
                product_version=measured["product_version_string"],
            )
            pinned["status"] = "pinned"
            pinned_pin = self.write_status_pin("measure-roundtrip-pin", pinned)
            verified = MODULE.verify_compiler(compiler, "x64", pinned_pin)
            self.assertEqual(verified["sha256"], digest)
            self.assertEqual(verified["install_tree_sha256"], tree)
            self.assertEqual(verified["size"], size)
            self.assertEqual(verified["product_version_string"], "0.0.0.0")
            self.assertEqual(verified["version"], "7.1.0")
            MODULE.compiler_identity_record(verified, pin_sha256=MODULE.pin_file_digest(pinned_pin))
        self.assertEqual(PIN.read_bytes(), pin_before)
        self.assertEqual(MODULE._identity(os.lstat(PIN)), MODULE._identity(pin_stat_before))

    def test_measure_keeps_every_identity_refusal(self) -> None:
        leaf_patch, chain_patch, _calls = self._trusted_windows_signer()
        renamed, *_ = self.write_compiler(
            "measure-renamed-installer",
            build_pe(
                authenticode=True,
                version={
                    "CompanyName": "jrsoftware.org",
                    "FileDescription": "Inno Setup Setup",
                    "ProductName": "Inno Setup",
                    "ProductVersion": "7.1.0",
                },
            ),
        )
        not_compiler, *_ = self.write_compiler(
            "measure-version", compiler_pe(version={"FileDescription": "Inno Setup Compiler"})
        )
        native_arm, *_ = self.write_compiler("measure-arm64", compiler_pe(machine=0xAA64))
        untrusted = self.scratch("measure-root") / "Inno Setup 6" / "ISCC.exe"
        untrusted.parent.mkdir()
        untrusted.write_bytes(compiler_pe())
        untrusted.chmod(0o444)
        hardlinked, *_ = self.write_compiler("measure-hardlink", compiler_pe())
        (hardlinked.parent / "helper.dll").write_bytes(b"helper")
        os.link(hardlinked.parent / "helper.dll", hardlinked.parent / "linked.dll")
        symlinked, *_ = self.write_compiler("measure-symlink", compiler_pe())
        os.symlink(symlinked, symlinked.parent / "alias.dll")
        cases = [
            (renamed, "compiler identity must be ISCC.exe, not the Pyrsys installer"),
            (not_compiler, "compiler identity must be the Inno Setup command-line compiler"),
            (native_arm, "architecture mismatch"),
            (untrusted, "untrusted installation root"),
            (hardlinked, "hardlink refused"),
            (symlinked, "symbolic path component rejected"),
        ]
        with leaf_patch, chain_patch:
            for candidate, pattern in cases:
                with self.subTest(candidate=str(candidate)):
                    with self.assertRaisesRegex(MODULE.Refused, pattern):
                        MODULE.verify_compiler(candidate, "x64", PIN, measure=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = make_cert(cn="Pyrsys B.V.", org="Pyrsys B.V.", key=key, serial=1)
        forged, *_ = self.write_compiler("measure-forged", compiler_pe(pkcs7=encode_pkcs7([cert], cert)))
        with self.assertRaisesRegex(MODULE.Refused, "Authenticode (chain )?publisher mismatch"):
            MODULE.verify_compiler(forged, "x64", PIN, measure=True)
        with mock.patch.object(
            MODULE,
            "authenticode_leaf",
            lambda _data: {
                "publisher_name": "Pyrsys B.V.",
                "subject": MODULE.OFFICIAL_PUBLISHER["authenticode_subject_rfc4514"],
                "issuer": MODULE.OFFICIAL_PUBLISHER["authenticode_issuer_rfc4514"],
                "serial": MODULE.OFFICIAL_PUBLISHER["authenticode_leaf_serial_hex"],
                "sha256": MODULE.OFFICIAL_PUBLISHER["authenticode_leaf_sha256"],
                "raw": b"",
            },
        ):
            if os.name != "nt":
                with self.assertRaisesRegex(MODULE.Refused, "Authenticode chain verification requires Windows"):
                    MODULE.verify_compiler(forged, "x64", PIN, measure=True)

    def test_cli_measure_prints_values_and_never_writes_the_pin(self) -> None:
        compiler, digest, size, tree = self.write_compiler("measure-cli", compiler_pe())
        pin = self.scratch("measure-cli-pin") / "inno-toolchain-pins.json"
        shutil.copyfile(self.unmeasured_pin, pin)
        pin.chmod(0o644)
        before = pin.read_bytes()
        stat_before = MODULE._identity(os.lstat(pin))
        script = (
            "import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('inno_custody_cli', {str(TOOL)!r})\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "leaf = {'publisher_name': 'Pyrsys B.V.', 'raw': b''}\n"
            "leaf['subject'] = module.OFFICIAL_PUBLISHER['authenticode_subject_rfc4514']\n"
            "leaf['issuer'] = module.OFFICIAL_PUBLISHER['authenticode_issuer_rfc4514']\n"
            "leaf['serial'] = module.OFFICIAL_PUBLISHER['authenticode_leaf_serial_hex']\n"
            "leaf['sha256'] = module.OFFICIAL_PUBLISHER['authenticode_leaf_sha256']\n"
            "module.authenticode_leaf = lambda data: dict(leaf)\n"
            "module.verify_authenticode_chain_bound = lambda snapshot: None\n"
            "sys.exit(module.main(sys.argv[1:]))\n"
        )
        base = [sys.executable, "-c", script, "verify-compiler", "--arch", "x64", "--path", str(compiler), "--pin", str(pin)]
        refused = subprocess.run(base, check=False, capture_output=True, text=True)
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertIn("ISCC x64 pin not measured; run verify-compiler --measure", refused.stderr)
        measured = subprocess.run(base + ["--measure"], check=False, capture_output=True, text=True)
        self.assertEqual(measured.returncode, 0, measured.stderr)
        lines = dict(line.split("|", 1) for line in measured.stdout.splitlines())
        self.assertEqual(lines["mode"], "measure")
        self.assertEqual(lines["sha256"], digest)
        self.assertEqual(lines["size"], str(size))
        self.assertEqual(lines["install_tree_sha256"], tree)
        self.assertEqual(lines["product_version_string"], "0.0.0.0")
        self.assertNotIn("authenticode_leaf_sha256", lines)
        self.assertEqual(pin.read_bytes(), before)
        self.assertEqual(MODULE._identity(os.lstat(pin)), stat_before)

    def test_install_tree_digest_ignores_only_the_root_uninstall_log(self) -> None:
        root = self.scratch("per-install") / "Inno Setup 7"
        (root / "Languages").mkdir(parents=True)
        (root / "ISCC.exe").write_bytes(b"compiler-bytes")
        (root / "Languages" / "German.isl").write_bytes(b"german")
        before = MODULE.install_tree_digest(root)
        (root / "unins000.dat").write_bytes(b"install-one")
        first = MODULE.install_tree_digest(root)
        (root / "unins000.dat").write_bytes(b"install-two, longer")
        second = MODULE.install_tree_digest(root)
        self.assertEqual(before, first)
        self.assertEqual(first, second)
        (root / "unins000.exe").write_bytes(b"uninstaller")
        self.assertNotEqual(MODULE.install_tree_digest(root), second)
        (root / "unins000.exe").unlink()
        (root / "Languages" / "unins000.dat").write_bytes(b"nested")
        self.assertNotEqual(MODULE.install_tree_digest(root), second)
        (root / "Languages" / "unins000.dat").unlink()
        (root / "unins0000.dat").write_bytes(b"not the uninstall log name")
        self.assertNotEqual(MODULE.install_tree_digest(root), second)

    def test_windows_tree_mode_matches_the_powershell_verifier(self) -> None:
        exe = types.SimpleNamespace(st_mode=0o100777)
        read_only_exe = types.SimpleNamespace(st_mode=0o100555)
        directory = types.SimpleNamespace(st_mode=0o040777)
        with mock.patch.object(MODULE.os, "name", "nt"):
            self.assertEqual(MODULE._tree_mode(exe), 0o666)
            self.assertEqual(MODULE._tree_mode(read_only_exe), 0o444)
            self.assertEqual(MODULE._tree_mode(directory), 0o777)
        if os.name != "nt":
            self.assertEqual(MODULE._tree_mode(exe), 0o777)
        powershell = POWERSHELL.read_text(encoding="utf-8")
        self.assertIn('return readOnly ? Convert.ToInt32("444", 8) : Convert.ToInt32("666", 8);', powershell)
        self.assertIn("IsPerInstallFile(relative)", powershell)

    def test_windows_stat_based_install_tree_walk(self) -> None:
        root = self.scratch("windows-walk") / "Inno Setup 7"
        (root / "Languages").mkdir(parents=True)
        (root / "ISCC.exe").write_bytes(b"compiler-bytes")
        (root / "Languages" / "German.isl").write_bytes(b"german")
        (root / "ISCC.exe").chmod(0o444)
        (root / "Languages" / "German.isl").chmod(0o444)
        posix_digest = MODULE.install_tree_digest(root)
        real_open = os.open
        real_scandir = os.scandir
        refused_dirs: list[str] = []

        def windows_open(path, flags, *args, **kwargs):
            if kwargs.get("dir_fd") is None and os.path.isdir(path):
                refused_dirs.append(os.fspath(path))
                raise PermissionError(13, "Permission denied", os.fspath(path))
            return real_open(path, flags, *args, **kwargs)

        class WindowsEntry:
            def __init__(self, entry: os.DirEntry) -> None:
                self.name = entry.name
                self.path = entry.path
                self._entry = entry

            def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
                values = list(self._entry.stat(follow_symlinks=follow_symlinks))
                values[1] = values[2] = values[3] = 0
                return os.stat_result(values)

        class WindowsScandir:
            def __init__(self, path) -> None:
                self._scan = real_scandir(path)

            def __enter__(self) -> list[WindowsEntry]:
                return [WindowsEntry(entry) for entry in self._scan]

            def __exit__(self, *_exc: object) -> None:
                self._scan.close()

        with mock.patch.object(MODULE, "_supports_dir_fd", lambda: False), mock.patch.object(
            MODULE.os, "open", windows_open
        ), mock.patch.object(MODULE.os, "scandir", WindowsScandir):
            with self.assertRaises(PermissionError):
                os.open(root, os.O_RDONLY)
            tree = MODULE.snapshot_install_tree(root)
            try:
                self.assertEqual(tree.digest, posix_digest)
                self.assertTrue(all(handle == -1 for _path, _identity, handle in tree.directories))
                tree.assert_unchanged("ISCC install tree")
                os.rename(root / "Languages", root / "Languages.old")
                (root / "Languages").mkdir()
                (root / "Languages" / "German.isl").write_bytes(b"german")
                with self.assertRaisesRegex(
                    MODULE.Refused, "mutated|unreadable|mixed old/new|pathname identity changed"
                ):
                    tree.assert_unchanged("ISCC install tree")
            finally:
                tree.close()
            os.unlink(root / "Languages" / "German.isl")
            os.rmdir(root / "Languages")
            os.rename(root / "Languages.old", root / "Languages")
            self.assertEqual(MODULE.install_tree_digest(root), posix_digest)
            os.link(root / "ISCC.exe", root / "Languages" / "linked.dll")
            with self.assertRaisesRegex(MODULE.Refused, "hardlink refused"):
                MODULE.snapshot_install_tree(root)
            os.unlink(root / "Languages" / "linked.dll")
            os.symlink(root / "ISCC.exe", root / "Languages" / "alias.dll")
            with self.assertRaisesRegex(MODULE.Refused, "symbolic path component rejected"):
                MODULE.snapshot_install_tree(root)
            os.unlink(root / "Languages" / "alias.dll")
            self.assertEqual(MODULE.install_tree_digest(root), posix_digest)
        self.assertTrue(refused_dirs)

    def test_compiler_hash_mismatch_fails_closed(self) -> None:
        compiler, _digest, size, tree = self.write_compiler("hash-mismatch", compiler_pe())
        pin = self.write_pinned_pin(
            "hash-pin",
            sha256="aa" * 32,
            size=size,
            tree=tree,
        )
        with self.assertRaisesRegex(MODULE.Refused, "compiler SHA-256 mismatch"):
            MODULE.verify_compiler(compiler, "x64", pin)
        completed = run_powershell(
            "-VerifyCompiler",
            "-Architecture",
            "x64",
            "-Path",
            str(compiler),
            "-PinPath",
            str(pin),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, "compiler SHA-256 mismatch")

    def test_compiler_version_mismatch_fails_closed(self) -> None:
        compiler, digest, size, tree = self.write_compiler("version-mismatch", compiler_pe())
        pin = self.write_pinned_pin(
            "version-pin",
            sha256=digest,
            size=size,
            tree=tree,
            product_version="7.0.0",
        )
        with self.assertRaisesRegex(MODULE.Refused, "version mismatch"):
            MODULE.verify_compiler(compiler, "x64", pin)

    def test_compiler_install_tree_mismatch_fails_closed(self) -> None:
        compiler, digest, size, _tree = self.write_compiler("tree-mismatch", compiler_pe())
        pin = self.write_pinned_pin(
            "tree-pin",
            sha256=digest,
            size=size,
            tree="bb" * 32,
        )
        with self.assertRaisesRegex(MODULE.Refused, "compiler install-tree SHA-256 mismatch"):
            MODULE.verify_compiler(compiler, "x64", pin)

    def test_compiler_signer_mismatch_fails_closed(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = make_cert(cn="Pyrsys B.V.", org="Pyrsys B.V.", key=key, serial=1)
        payload = compiler_pe(pkcs7=encode_pkcs7([cert], cert))
        compiler, digest, size, tree = self.write_compiler("signer-mismatch", payload)
        pin = self.write_pinned_pin(
            "signer-pin",
            sha256=digest,
            size=size,
            tree=tree,
        )
        with self.assertRaisesRegex(MODULE.Refused, "Authenticode (chain )?publisher mismatch"):
            MODULE.verify_compiler(compiler, "x64", pin)

    def test_compiler_receipt_must_not_reuse_installer_digest(self) -> None:
        compiler, _digest, size, tree = self.write_compiler("reuse-installer", compiler_pe())
        installer_sha = load_official()["installers"]["windows_x64"]["sha256"]
        pin = self.write_pinned_pin(
            "reuse-pin",
            sha256=installer_sha,
            size=size,
            tree=tree,
        )
        with self.assertRaisesRegex(
            MODULE.Refused, "compiler receipt must not reuse the Pyrsys installer digest"
        ):
            MODULE.verify_compiler(compiler, "x64", pin)

    def test_file_and_tree_hashes_must_differ_in_pin(self) -> None:
        digest = "cc" * 32
        document = pin_compilers(
            load_official(),
            sha256=digest,
            size=4096,
            tree=digest,
        )
        pin = self.scratch("same-hash") / "inno-toolchain-pins.json"
        write_json(pin, document)
        with self.assertRaisesRegex(
            MODULE.Refused, "compiler file and install-tree hashes must be independently derived"
        ):
            MODULE.load_pin(pin)

    def test_compiler_identity_record_binds_hash_version_signer_and_tree(self) -> None:
        verified = {
            "architecture": "x64",
            "filename": "ISCC.exe",
            "sha256": "aa" * 32,
            "size": 4096,
            "pe_machine": "x64",
            "output_architectures": ["x64"],
            "version": "7.1.0",
            "product_version_string": "0.0.0.0",
            "publisher_name": "Pyrsys B.V.",
            "authenticode_leaf_sha256": MODULE.OFFICIAL_PUBLISHER["authenticode_leaf_sha256"],
            "authenticode_leaf_serial_hex": MODULE.OFFICIAL_PUBLISHER["authenticode_leaf_serial_hex"],
            "install_tree_sha256": "bb" * 32,
            "trusted_root_leaf": "Inno Setup 7",
        }
        record = MODULE.compiler_identity_record(verified, pin_sha256="dd" * 32)
        self.assertEqual(tuple(record), MODULE.COMPILER_RECEIPT_KEYS)
        self.assertEqual(record["contract"], MODULE.COMPILER_RECEIPT_CONTRACT)
        self.assertEqual(record["sha256"], "aa" * 32)
        self.assertEqual(record["install_tree_sha256"], "bb" * 32)
        self.assertEqual(record["product_version_string"], "0.0.0.0")
        self.assertEqual(record["version"], "7.1.0")
        self.assertEqual(record["publisher_name"], "Pyrsys B.V.")
        self.assertEqual(record["pin_path"], "tools/inno-toolchain-pins.json")
        with self.assertRaisesRegex(MODULE.Refused, "pin SHA-256 is not an exact lowercase"):
            MODULE.compiler_identity_record(verified, pin_sha256="0" * 64)
        wrong_version = dict(verified)
        wrong_version["version"] = "7.0.0"
        with self.assertRaisesRegex(MODULE.Refused, "version mismatch"):
            MODULE.compiler_identity_record(wrong_version, pin_sha256="dd" * 32)
        wrong_signer = dict(verified)
        wrong_signer["authenticode_leaf_sha256"] = "ee" * 32
        with self.assertRaisesRegex(MODULE.Refused, "Authenticode publisher mismatch"):
            MODULE.compiler_identity_record(wrong_signer, pin_sha256="dd" * 32)
        same_tree = dict(verified)
        same_tree["install_tree_sha256"] = verified["sha256"]
        with self.assertRaisesRegex(
            MODULE.Refused, "compiler file and install-tree hashes must be independently derived"
        ):
            MODULE.compiler_identity_record(same_tree, pin_sha256="dd" * 32)

    def test_verify_compiler_cli_emits_identity_fields_on_hash_mismatch(self) -> None:
        python = (ROOT / "tools" / "release_inno_toolchain_custody.py").read_text(encoding="utf-8")
        powershell = (ROOT / "tools" / "release_inno_toolchain_custody.ps1").read_text(
            encoding="utf-8"
        )
        for source in (python, powershell):
            self.assertIn("authenticode_leaf_sha256", source)
            self.assertIn("install_tree_sha256", source)
            self.assertIn("product_version_string", source)
            self.assertNotIn("INNO_SETUP_ISCC", source)
            self.assertNotIn("Get-Command ISCC", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
