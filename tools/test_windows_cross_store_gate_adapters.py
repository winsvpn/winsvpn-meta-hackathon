#!/usr/bin/env python3

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import cross_store_upload_readiness as readiness
import release_obfuscation_contract as obfuscation
import windows_cross_store_artifact_gate as gate


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_len(len(content)) + content


def encode_oid(value: str) -> bytes:
    parts = [int(item) for item in value.split(".")]
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


def _name(cn: str, org: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def make_cert(
    *,
    cn: str,
    org: str,
    key: rsa.RSAPrivateKey,
    serial: int,
    issuer: x509.Certificate | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
) -> x509.Certificate:
    subject = _name(cn, org)
    issuer_name = issuer.subject if issuer is not None else subject
    signer = issuer_key if issuer_key is not None else key
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(signer, hashes.SHA256())
    )


def encode_pkcs7(
    certs: list[x509.Certificate],
    signer: x509.Certificate,
    *,
    timestamp: bool = False,
    digest_oid: str = "2.16.840.1.101.3.4.2.1",
) -> bytes:
    cert_der = b"".join(cert.public_bytes(Encoding.DER) for cert in certs)
    issuer_der = signer.issuer.public_bytes(Encoding.DER)
    issuer_serial = tlv(0x30, issuer_der + encode_int(signer.serial_number))
    digest = encode_oid(digest_oid)
    rsa_oid = encode_oid("1.2.840.113549.1.1.1")
    unauth = b""
    if timestamp:
        token = tlv(0x04, b"winsvpn-fixture-rfc3161")
        attr = tlv(
            0x30,
            encode_oid(gate.OID_SPC_RFC3161) + tlv(0x31, token),
        )
        unauth = tlv(0xA1, attr)
    signer_info = tlv(
        0x30,
        encode_int(1)
        + issuer_serial
        + tlv(0x30, digest)
        + tlv(0x30, rsa_oid + tlv(0x05, b""))
        + tlv(0x04, b"\x00" * 16)
        + unauth,
    )
    signed = tlv(
        0x30,
        encode_int(1)
        + tlv(0x31, tlv(0x30, digest))
        + tlv(0x30, encode_oid("1.2.840.113549.1.7.1"))
        + tlv(0xA0, cert_der)
        + tlv(0x31, signer_info),
    )
    return tlv(0x30, encode_oid("1.2.840.113549.1.7.2") + tlv(0xA0, signed))


def wrap_win_certificate(pkcs7: bytes) -> bytes:
    record = struct.pack("<IHH", 8 + len(pkcs7), 0x0200, 0x0002) + pkcs7
    if len(record) % 8:
        record += b"\x00" * (8 - len(record) % 8)
    return record


_REVIEWED_PKCS7: bytes | None = None
_REVIEWED_SIGNER: tuple[x509.Certificate, x509.Certificate, rsa.RSAPrivateKey] | None = None
_MICROSOFT_SIGNER: tuple[x509.Certificate, x509.Certificate, rsa.RSAPrivateKey] | None = None
_RECEIPT_KEY: tuple[ed25519.Ed25519PrivateKey, bytes] | None = None

PRODUCER_VC_REDIST_BASENAME = {
    "x64": "VC_redist.x64.exe",
    "arm64": "VC_redist.arm64.exe",
}
PRODUCER_VC_REDIST_PRODUCT_NAME = {
    "x64": "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211",
    "arm64": "Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.44.35211",
}
PRODUCER_AMNEZIAWG_MSI_BASENAME = {
    "x64": "amneziawg-amd64.msi",
    "arm64": "amneziawg-arm64.msi",
}


def reviewed_signer() -> tuple[x509.Certificate, x509.Certificate, rsa.RSAPrivateKey]:
    global _REVIEWED_SIGNER
    if _REVIEWED_SIGNER is None:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = make_cert(cn="WinsVPN Test CA", org="WinsVPN Test CA", key=ca_key, serial=1)
        leaf = make_cert(
            cn=gate.AUTHENTICODE_LEAF_CN,
            org=gate.AUTHENTICODE_LEAF_O,
            key=leaf_key,
            serial=2,
            issuer=ca,
            issuer_key=ca_key,
        )
        _REVIEWED_SIGNER = (ca, leaf, leaf_key)
    return _REVIEWED_SIGNER


def microsoft_signer() -> tuple[x509.Certificate, x509.Certificate, rsa.RSAPrivateKey]:
    global _MICROSOFT_SIGNER
    if _MICROSOFT_SIGNER is None:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = make_cert(
            cn="Microsoft Code Signing PCA",
            org="Microsoft Corporation",
            key=ca_key,
            serial=21,
        )
        leaf = make_cert(
            cn=gate.VC_REDIST_PUBLISHER_CN,
            org="Microsoft Corporation",
            key=leaf_key,
            serial=22,
            issuer=ca,
            issuer_key=ca_key,
        )
        _MICROSOFT_SIGNER = (ca, leaf, leaf_key)
    return _MICROSOFT_SIGNER


def reviewed_pkcs7() -> bytes:
    global _REVIEWED_PKCS7
    if _REVIEWED_PKCS7 is None:
        ca, leaf, _leaf_key = reviewed_signer()
        _REVIEWED_PKCS7 = encode_pkcs7([ca, leaf], leaf)
    return _REVIEWED_PKCS7


def untrusted_signer() -> tuple[x509.Certificate, x509.Certificate, rsa.RSAPrivateKey]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = make_cert(cn="Other CA", org="Other CA", key=ca_key, serial=7)
    leaf = make_cert(
        cn="Other Corp",
        org="Other Corp",
        key=leaf_key,
        serial=8,
        issuer=ca,
        issuer_key=ca_key,
    )
    return ca, leaf, leaf_key


def lookalike_untrusted_signer() -> tuple[
    x509.Certificate, x509.Certificate, rsa.RSAPrivateKey
]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = make_cert(
        cn="WIN'S VPN INC. Lookalike CA",
        org=gate.AUTHENTICODE_LEAF_O,
        key=ca_key,
        serial=11,
    )
    leaf = make_cert(
        cn=gate.AUTHENTICODE_LEAF_CN,
        org=gate.AUTHENTICODE_LEAF_O,
        key=leaf_key,
        serial=12,
        issuer=ca,
        issuer_key=ca_key,
    )
    return ca, leaf, leaf_key


def reviewed_custody_policy() -> gate.AuthenticodeCustodyPolicy:
    pe = installer_pe("windows-x64-installer")
    leaf = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", pe)
    return gate.authenticode_custody_policy("WinsVPN-Setup.exe", pe, leaf)


def sign_pkcs7_over_digest(
    digest: bytes,
    *,
    leaf: x509.Certificate | None = None,
    key: rsa.RSAPrivateKey | None = None,
    ca: x509.Certificate | None = None,
) -> bytes:
    if leaf is None or key is None:
        ca, leaf, key = reviewed_signer()
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(digest)
        .add_signer(leaf, key, hashes.SHA256())
    )
    if ca is not None:
        builder = builder.add_certificate(ca)
    return builder.sign(Encoding.DER, [pkcs7.PKCS7Options.Binary])


_TSA_SIGNER: tuple[x509.Certificate, x509.Certificate, rsa.RSAPrivateKey] | None = None


def tsa_signer() -> tuple[x509.Certificate, x509.Certificate, rsa.RSAPrivateKey]:
    global _TSA_SIGNER
    if _TSA_SIGNER is None:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = make_cert(cn="WinsVPN Test TSA CA", org="WinsVPN Test TSA", key=ca_key, serial=31)
        leaf = make_cert(
            cn="WinsVPN Test TSA",
            org="WinsVPN Test TSA",
            key=leaf_key,
            serial=32,
            issuer=ca,
            issuer_key=ca_key,
        )
        _TSA_SIGNER = (ca, leaf, leaf_key)
    return _TSA_SIGNER


def encode_tstinfo(imprint: bytes) -> bytes:
    hash_alg = tlv(0x30, encode_oid(gate.OID_SHA256) + tlv(0x05, b""))
    message_imprint = tlv(0x30, hash_alg + tlv(0x04, imprint))
    stamped = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%SZ")
    return tlv(
        0x30,
        encode_int(1)
        + encode_oid("1.3.6.1.4.1.4146.2")
        + message_imprint
        + encode_int(1)
        + tlv(0x18, stamped.encode("ascii")),
    )


def sign_rfc3161_token(imprint: bytes) -> bytes:
    ca, leaf, key = tsa_signer()
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(encode_tstinfo(imprint))
        .add_signer(leaf, key, hashes.SHA256())
        .add_certificate(ca)
    )
    return builder.sign(Encoding.DER, [pkcs7.PKCS7Options.Binary])


def rebuild_pkcs7_with_unauthenticated(pkcs7_der: bytes, unauth_content: bytes) -> bytes:
    parsed = gate._parse_pkcs7_signer(pkcs7_der)
    auth = parsed["authenticated_attributes"]
    content = parsed["content"]
    signature = parsed["signature"]
    certificates = parsed["certificates"]
    if (
        type(auth) is not bytes
        or type(content) is not bytes
        or type(signature) is not bytes
        or type(certificates) is not list
        or not auth
        or not content
        or not signature
        or not certificates
    ):
        raise AssertionError("fixture PKCS#7 is missing signed Authenticode fields")
    issuer_serial = tlv(0x30, parsed["issuer_der"] + encode_int(int(parsed["serial"])))
    digest_alg = tlv(0x30, encode_oid(str(parsed["digest_oid"])) + tlv(0x05, b""))
    content_info = tlv(
        0x30,
        encode_oid(str(parsed["content_oid"])) + tlv(0xA0, tlv(0x04, content)),
    )
    signer_info = tlv(
        0x30,
        encode_int(1)
        + issuer_serial
        + digest_alg
        + tlv(0xA0, auth)
        + tlv(0x30, encode_oid(str(parsed["encryption_oid"])) + tlv(0x05, b""))
        + tlv(0x04, signature)
        + tlv(0xA1, unauth_content),
    )
    signed = tlv(
        0x30,
        encode_int(1)
        + tlv(0x31, digest_alg)
        + content_info
        + tlv(0xA0, b"".join(certificates))
        + tlv(0x31, signer_info),
    )
    return tlv(0x30, encode_oid(gate.SIGNED_DATA_OID) + tlv(0xA0, signed))


def attach_rfc3161(pkcs7_der: bytes, *, token: bytes | None = None) -> bytes:
    parsed = gate._parse_pkcs7_signer(pkcs7_der)
    signature = parsed["signature"]
    if type(signature) is not bytes or not signature:
        raise AssertionError("fixture PKCS#7 is missing a signature")
    if token is None:
        token = sign_rfc3161_token(hashlib.sha256(signature).digest())
    unauth = tlv(0x30, encode_oid(gate.OID_SPC_RFC3161) + tlv(0x31, token))
    return rebuild_pkcs7_with_unauthenticated(pkcs7_der, unauth)


def receipt_issuer_key() -> tuple[ed25519.Ed25519PrivateKey, bytes]:
    global _RECEIPT_KEY
    if _RECEIPT_KEY is None:
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            Encoding.Raw, serialization.PublicFormat.Raw
        )
        _RECEIPT_KEY = (private, public)
    return _RECEIPT_KEY


def patch_receipt_issuer():
    _private, public = receipt_issuer_key()
    del _private
    return mock.patch.object(
        gate, "_execution_receipt_public_key_bytes", return_value=public
    )


def signed_execution_receipt(
    snapshot: gate.AuthenticatedSnapshot,
    leaf: dict[str, str],
    target_id: str,
    inner_payloads: dict[str, bytes],
    **overrides: object,
) -> dict[str, object]:
    private, _public = receipt_issuer_key()
    digests = {
        name: hashlib.sha256(blob).hexdigest() for name, blob in inner_payloads.items()
    }
    issued = gate._execution_receipt_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    record: dict[str, object] = {
        "schema": gate.EXECUTION_RECEIPT_SCHEMA,
        "authenticated": True,
        "issuer": gate.EXECUTION_RECEIPT_ISSUER,
        "run_id": secrets.token_hex(32),
        "nonce": secrets.token_hex(32),
        "issued_at": issued,
        "target_id": target_id,
        "target_architecture": gate.TARGET_ARCHITECTURES[target_id],
        "installer_sha256": snapshot.digest,
        "installer_size": snapshot.size,
        "authenticode_leaf_sha256": leaf["sha256"],
        "build_transaction": gate.compute_windows_installer_source_closure(),
        "inner_payload_digests": dict(digests),
        "signature": "",
        "inner_payloads": inner_payloads,
    }
    record.update(overrides)
    inner_for_canonical = record.get("inner_payload_digests")
    if type(inner_for_canonical) is not dict:
        inner_for_canonical = digests
    canonical_digests = {
        str(name): str(value) for name, value in inner_for_canonical.items()
    }
    if "signature" not in overrides or record.get("signature") == "":
        canonical = gate._execution_receipt_canonical_bytes(record, canonical_digests)
        record["signature"] = private.sign(canonical).hex()
    return record


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


def split_version(text: str) -> tuple[int, int]:
    parts = [int(item) for item in text.split(".")]
    while len(parts) < 4:
        parts.append(0)
    return (parts[0] << 16) | parts[1], (parts[2] << 16) | parts[3]


def encode_version(strings: dict[str, str], *, file_version: str, product_version: str) -> bytes:
    children = b"".join(encode_string(key, value) for key, value in strings.items())
    string_table = encode_block("040904B0", 1, b"", children)
    string_file_info = encode_block("StringFileInfo", 1, b"", string_table)
    file_ms, file_ls = split_version(file_version)
    product_ms, product_ls = split_version(product_version)
    fixed = struct.pack(
        "<IIIIII",
        0xFEEF04BD,
        0x00010000,
        file_ms,
        file_ls,
        product_ms,
        product_ls,
    ) + (b"\x00" * 28)
    return encode_block("VS_VERSION_INFO", 0, fixed, string_file_info)


def signed_pe(
    machine: int,
    *,
    version: dict[str, str] | None = None,
    file_version: str = "1.0.17.34",
    product_version: str = "1.0.17",
    pkcs7: bytes | None = None,
    authenticode: bool = True,
    signer: tuple[x509.Certificate, x509.Certificate, rsa.RSAPrivateKey] | None = None,
    codeview: bool = False,
    timestamp: bool | str = True,
) -> bytes:
    is_pe32_plus = machine in {gate.PE_MACHINE_X64, gate.PE_MACHINE_ARM64}
    magic = 0x20B if is_pe32_plus else 0x10B
    optional_size = 240 if is_pe32_plus else 224
    directory_base = 112 if is_pe32_plus else 96
    number_offset = 108 if is_pe32_plus else 92
    if version is None and pkcs7 is None and authenticode is False:
        pe = 0x80
        optional = pe + 24
        data = bytearray(544)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, pe)
        data[pe : pe + 4] = b"PE\0\0"
        struct.pack_into("<H", data, pe + 4, machine)
        struct.pack_into("<H", data, pe + 6, 1)
        struct.pack_into("<H", data, pe + 20, optional_size)
        struct.pack_into("<H", data, optional, magic)
        struct.pack_into("<I", data, number_offset + optional, 16)
        struct.pack_into("<II", data, directory_base + optional + 32, 512, 16)
        struct.pack_into("<IHH", data, 512, 16, 0x0200, 0x0002)
        data[520:528] = b"PKCS7FIX"
        return bytes(data)

    dos = bytearray(64)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 64)
    coff = bytearray(24)
    coff[:4] = b"PE\0\0"
    struct.pack_into("<H", coff, 4, machine)
    struct.pack_into("<H", coff, 20, optional_size)
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, magic)
    struct.pack_into("<I", optional, number_offset, 16)
    if version is None and pkcs7 is None and authenticode:
        version = {
            "CompanyName": gate.AUTHENTICODE_LEAF_O,
            "FileDescription": "Win's VPN",
            "ProductName": "Win's VPN",
            "ProductVersion": product_version,
        }
    if version is None:
        cert_blob = wrap_win_certificate(
            pkcs7 or (b"\x30\x03\x02\x01\x00" + (b"\x00" * 11))
        )
        image = bytes(dos) + bytes(coff) + bytes(optional) + b"INNO-FIXTURE"
        mutable = bytearray(image)
        struct.pack_into("<I", mutable, 64 + 24 + directory_base + 32, len(mutable))
        struct.pack_into("<I", mutable, 64 + 24 + directory_base + 36, len(cert_blob))
        return bytes(mutable) + cert_blob
    version_bytes = encode_version(
        version, file_version=file_version, product_version=product_version
    )
    off_type = 24
    off_lang = off_type + 24
    off_data = off_lang + 24
    off_ver = off_data + 16
    rsrc = bytearray()
    rsrc += u32(0) + u32(0) + u16(0) + u16(0) + u16(0) + u16(1)
    rsrc += u32(16) + u32(off_type | 0x80000000)
    rsrc += u32(0) + u32(0) + u16(0) + u16(0) + u16(0) + u16(1)
    rsrc += u32(1) + u32(off_lang | 0x80000000)
    rsrc += u32(0) + u32(0) + u16(0) + u16(0) + u16(0) + u16(1)
    rsrc += u32(0x409) + u32(off_data)
    rsrc += u32(0) + u32(len(version_bytes)) + u32(0) + u32(0)
    rsrc += version_bytes
    struct.pack_into("<H", coff, 6, 2 if codeview else 1)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x3000 if codeview else 0x2000)
    struct.pack_into("<I", optional, 60, 0x400)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, directory_base + 16, 0x1000)
    struct.pack_into("<I", optional, directory_base + 20, len(rsrc))
    section = bytearray(40)
    section[0:5] = b".rsrc"
    raw_size = (len(rsrc) + 0x1FF) & ~0x1FF
    struct.pack_into("<I", section, 8, len(rsrc))
    struct.pack_into("<I", section, 12, 0x1000)
    struct.pack_into("<I", section, 16, raw_size)
    struct.pack_into("<I", section, 20, 0x400)
    debug_section = b""
    debug_raw = b""
    if codeview:
        debug_payload = b"RSDS" + (b"p" * 16) + b"\x01\x00\x00\x00" + b"vendor.pdb\x00"
        debug_raw_ptr = 0x400 + raw_size
        debug_rva = 0x2000
        debug_dir = bytearray(28)
        struct.pack_into("<I", debug_dir, 12, 2)
        struct.pack_into("<I", debug_dir, 16, len(debug_payload))
        struct.pack_into("<I", debug_dir, 20, debug_rva + 28)
        struct.pack_into("<I", debug_dir, 24, debug_raw_ptr + 28)
        debug_raw = bytes(debug_dir) + debug_payload
        debug_raw_size = (len(debug_raw) + 0x1FF) & ~0x1FF
        debug_section = bytearray(40)
        debug_section[0:6] = b".rdata"
        struct.pack_into("<I", debug_section, 8, len(debug_raw))
        struct.pack_into("<I", debug_section, 12, debug_rva)
        struct.pack_into("<I", debug_section, 16, debug_raw_size)
        struct.pack_into("<I", debug_section, 20, debug_raw_ptr)
        struct.pack_into("<II", optional, directory_base + 48, debug_rva, 28)
        debug_raw = debug_raw + (b"\x00" * (debug_raw_size - len(debug_raw)))
    headers = bytes(dos) + bytes(coff) + bytes(optional) + bytes(section) + bytes(debug_section)
    headers += b"\x00" * (0x400 - len(headers))
    struct.pack_into("<I", rsrc, off_data, 0x1000 + off_ver)
    rsrc_padded = bytes(rsrc) + b"\x00" * (raw_size - len(rsrc))
    image = bytearray(headers + rsrc_padded + debug_raw)
    cert_dir = 64 + 24 + directory_base + 32
    struct.pack_into("<I", image, cert_dir, len(image))
    struct.pack_into("<I", image, cert_dir + 4, 0)
    if pkcs7 is None and authenticode:
        digest = gate.authenticode_image_digest(
            "fixture.exe", bytes(image), require_certificate=False
        )
        if signer is None:
            ca, leaf, key = reviewed_signer()
        else:
            ca, leaf, key = signer
        pkcs7 = sign_pkcs7_over_digest(digest, leaf=leaf, key=key, ca=ca)
        if timestamp is True:
            pkcs7 = attach_rfc3161(pkcs7)
        elif timestamp == "garbage":
            pkcs7 = attach_rfc3161(
                pkcs7, token=tlv(0x04, b"winsvpn-fixture-rfc3161")
            )
        elif timestamp is not False:
            raise AssertionError("signed_pe timestamp must be True, False, or 'garbage'.")
    cert_blob = wrap_win_certificate(
        pkcs7 or (b"\x30\x03\x02\x01\x00" + (b"\x00" * 11))
    )
    struct.pack_into("<I", image, cert_dir + 4, len(cert_blob))
    return bytes(image) + cert_blob


def installer_pe(target: str, **overrides: object) -> bytes:
    version = {
        "CompanyName": gate.AUTHENTICODE_LEAF_O,
        "FileDescription": str(
            overrides.get("FileDescription", gate.TARGET_FILE_DESCRIPTIONS[target])
        ),
        "OriginalFilename": str(
            overrides.get("OriginalFilename", gate.TARGET_FILENAMES[target])
        ),
        "ProductName": "Win's VPN",
        "ProductVersion": str(overrides.get("ProductVersion", "1.0.17")),
    }
    pkcs7_override = overrides.get("pkcs7", None)
    authenticode = bool(overrides.get("authenticode", True))
    if "pkcs7" not in overrides:
        pkcs7 = None
    elif pkcs7_override is True:
        pkcs7 = reviewed_pkcs7()
    elif pkcs7_override is False or pkcs7_override is None:
        pkcs7 = None
        authenticode = False if pkcs7_override is False else authenticode
    elif type(pkcs7_override) is bytes and pkcs7_override:
        pkcs7 = pkcs7_override
    else:
        raise AssertionError("installer_pe pkcs7 override must be exact PKCS#7 bytes.")
    return signed_pe(
        gate.PE_MACHINE_X86,
        version=version,
        file_version=str(overrides.get("FileVersion", "1.0.17.34")),
        product_version=str(overrides.get("ProductVersion", "1.0.17")),
        pkcs7=pkcs7,
        authenticode=authenticode,
    )


def app_pe(machine: int, **overrides: object) -> bytes:
    version = {
        "CompanyName": gate.AUTHENTICODE_LEAF_O,
        "FileDescription": "Win's VPN",
        "ProductName": "Win's VPN",
        "ProductVersion": str(overrides.get("ProductVersion", "1.0.17")),
    }
    return signed_pe(
        machine,
        version=version,
        file_version=str(overrides.get("FileVersion", "1.0.17.34")),
        product_version=str(overrides.get("ProductVersion", "1.0.17")),
        codeview=bool(overrides.get("codeview", False)),
    )


def producer_vc_redist_pe(architecture: str, *, codeview: bool = False) -> bytes:
    name = PRODUCER_VC_REDIST_BASENAME[architecture]
    machine = gate.PE_MACHINE_X86 if architecture == "x64" else gate.PE_MACHINE_ARM64
    return signed_pe(
        machine,
        version={
            "CompanyName": gate.VC_REDIST_PUBLISHER_CN,
            "FileDescription": "Win32 Cabinet Self-Extractor",
            "OriginalFilename": name,
            "ProductName": PRODUCER_VC_REDIST_PRODUCT_NAME[architecture],
            "ProductVersion": gate.VC_REDIST_VERSION,
        },
        file_version=gate.VC_REDIST_VERSION,
        product_version=gate.VC_REDIST_VERSION,
        signer=microsoft_signer(),
        codeview=codeview,
    )


def producer_amneziawg_msi(architecture: str) -> bytes:
    name = PRODUCER_AMNEZIAWG_MSI_BASENAME[architecture]
    return (
        gate.MSI_OLE_MAGIC
        + b"WinsVPN-producer-shaped-msi\x00"
        + architecture.encode("ascii")
        + b"\x00"
        + gate.AMNEZIAWG_MSI_PUBLISHER_O.encode("ascii")
        + b"\x00"
        + name.encode("ascii")
    )


FIXTURE_CHROME_ID = "abcdefghijklmnopabcdefghijklmnop"
FIXTURE_EDGE_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"


def native_manifest(browser: str, extension_id: str | None = None) -> bytes:
    document: dict[str, object] = {
        "name": gate.NATIVE_HOST_JSON_NAME,
        "description": gate.NATIVE_HOST_JSON_DESCRIPTION,
        "path": gate.NATIVE_HOST_RELATIVE_PATH_VALUE,
        "type": "stdio",
    }
    if browser == "firefox":
        document["allowed_extensions"] = [gate.FIREFOX_NATIVE_EXTENSION_ID]
    else:
        defaults = {
            "chrome": FIXTURE_CHROME_ID,
            "edge": FIXTURE_EDGE_ID,
        }
        store_id = extension_id or defaults[browser]
        document["allowed_origins"] = [f"chrome-extension://{store_id}/"]
    return (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")


def patch_owner_issued_ids():
    return mock.patch.object(
        gate,
        "_owner_issued_chromium_ids",
        return_value={"chrome": FIXTURE_CHROME_ID, "edge": FIXTURE_EDGE_ID},
    )


def origin_digest(relative: str) -> str:
    return hashlib.sha256((gate.ORIGIN_ROOT / relative).read_bytes()).hexdigest()


def authenticode_signtool_stdout(leaf: dict[str, str]) -> str:
    return (
        "Successfully verified: snapshot.bin\n"
        "Hash of file (sha256): 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        f"Issued to: {leaf['common_name']}\n"
        "Signing Certificate Chain:\n"
        f"    SHA1 hash: {leaf['thumbprint']}\n"
        "Timestamp Verified by: WinsVPN Test TSA\n"
        "The signature is timestamped: 2026-08-25T00:00:00Z\n"
        "Signing time: 2026-08-25T00:00:00Z\n"
        "Revocation check: The certificate chain was verified and revocation was checked.\n"
    )


def valid_offline_authenticode_proof(
    leaf: dict[str, str],
    *,
    target_id: str = "windows-x64-installer",
    snapshot_sha256: str = "a" * 64,
    tool: str = "/abs/signtool.exe",
    snapshot_path: str = "/abs/snapshot.bin",
    surface: str | None = None,
) -> dict[str, object]:
    return {
        "argv": [tool, *gate.AUTHENTICODE_VERIFY_ARGV_PREFIX, snapshot_path],
        "shell": False,
        "exit_code": 0,
        "stdout_sha256": "b" * 64,
        "timestamp_verified": True,
        "digest_algorithm": "sha256",
        "revocation": "checked",
        "owner_authenticode_leaf_sha256": leaf["sha256"],
        "signer_subject": leaf["subject"],
        "thumbprint": leaf["thumbprint"],
        "snapshot_sha256": snapshot_sha256,
        "target_id": target_id,
        "surface": surface if surface is not None else gate.TARGET_SURFACES[target_id],
    }


def build_receipt_payload(
    *,
    name: str,
    digest: str,
    size_bytes: int,
    target: str = "windows-x64-inno-signed",
    release: str = "1.0.17+34",
    finished_utc: str | None = None,
    extra: dict[str, object] | None = None,
) -> bytes:
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    if finished_utc is None:
        finished_utc = now.isoformat().replace("+00:00", "Z")
    record: dict[str, object] = {
        "artifact": {"name": name, "sha256": digest, "size_bytes": size_bytes},
        "release": release,
        "platform": "windows",
        "publication_authorized": False,
        "toolchain": {"target": target},
        "finished_utc": finished_utc,
    }
    if extra:
        record.update(extra)
    return json.dumps(record, sort_keys=True).encode("ascii")


def flutter_pins() -> dict[str, str]:
    document = json.loads(
        (gate.ORIGIN_ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8")
    )
    flutter = document["tools"]["flutter"]
    return {
        "framework_version": flutter["version"],
        "framework_revision": flutter["revision"],
        "engine_revision": "a" * 40,
        "dart_sdk_version": flutter["dart_version"],
    }


def inno_compiler_identity(architecture: str) -> dict[str, object]:
    """The inno_compiler record build_installer.ps1 writes from the reviewed pins."""
    raw = (gate.ORIGIN_ROOT / "tools/inno-toolchain-pins.json").read_bytes()
    document = json.loads(raw)
    pinned = document["compilers"][f"windows_{architecture}"]
    publisher = document["publisher"]
    return {
        "contract": "winsvpn-inno-compiler-receipt-v1",
        "product": "Inno Setup",
        "vendor": "JRSoftware",
        "version": "7.1.0",
        "filename": "ISCC.exe",
        "architecture": architecture,
        "pe_machine": "x64",
        "output_architectures": [architecture],
        "sha256": pinned["sha256"],
        "size": pinned["size"],
        "product_version_string": pinned["product_version_string"],
        "publisher_name": "Pyrsys B.V.",
        "authenticode_leaf_sha256": publisher["authenticode_leaf_sha256"],
        "authenticode_leaf_serial_hex": publisher["authenticode_leaf_serial_hex"],
        "install_tree_sha256": pinned["install_tree_sha256"],
        "trusted_root_leaf": "Inno Setup 7",
        "pin_path": "tools/inno-toolchain-pins.json",
        "pin_sha256": hashlib.sha256(raw).hexdigest(),
    }


class WindowsCrossStoreGateFixtures:
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temp.name).resolve()
        self.root_patch = mock.patch.object(gate, "ROOT", self.repo)
        self.root_patch.start()
        self.owner_patch = mock.patch.object(
            gate,
            "_owner_issued_chromium_ids",
            return_value={"chrome": FIXTURE_CHROME_ID, "edge": FIXTURE_EDGE_ID},
        )
        self.owner_patch.start()
        self.receipt_patch = patch_receipt_issuer()
        self.receipt_patch.start()

    def tearDown(self) -> None:
        self.receipt_patch.stop()
        self.owner_patch.stop()
        self.root_patch.stop()
        self.temp.cleanup()

    def write(self, relative: str, payload: bytes) -> pathlib.Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def producer_fields(self) -> dict[str, str]:
        return {
            "path": gate.PRODUCER_RELATIVE_PATH,
            "sha256": origin_digest(gate.PRODUCER_RELATIVE_PATH),
            "inno_script_path": gate.INNO_SCRIPT_RELATIVE_PATH,
            "inno_script_sha256": origin_digest(gate.INNO_SCRIPT_RELATIVE_PATH),
            "inno_signing_wrapper_path": gate.SIGNING_WRAPPER_RELATIVE_PATH,
            "inno_signing_wrapper_sha256": origin_digest(
                gate.SIGNING_WRAPPER_RELATIVE_PATH
            ),
        }

    def candidate(
        self,
        target: str,
        *,
        standalone_winn3: bool = False,
        include_chrome_edge: bool = True,
        write_install_proof: bool = True,
        installer_bytes: bytes | None = None,
    ) -> tuple[str, dict[str, str]]:
        surface = gate.TARGET_SURFACES[target]
        architecture = gate.TARGET_ARCHITECTURES[target]
        machine = {
            "x64": gate.PE_MACHINE_X64,
            "arm64": gate.PE_MACHINE_ARM64,
        }[architecture]
        go_arch = "amd64" if architecture == "x64" else "arm64"
        artifact_rel = f"artifacts/{gate.TARGET_FILENAMES[target]}"
        artifact = self.write(
            artifact_rel, installer_bytes or installer_pe(target)
        )
        identity = {
            "schema_version": 2,
            "canonical_release": "1.0.17+34",
            "marketing_version": "1.0.17",
            "build_number": 33,
            "platform_mappings": {
                "windows": {
                    "product_version": "1.0.17",
                    "four_part_version": "1.0.17.34",
                }
            },
        }
        self.write(
            gate.RELEASE_IDENTITY_RELATIVE_PATH.as_posix(),
            (json.dumps(identity, sort_keys=True) + "\n").encode(),
        )
        release_input = self.write("docs/windows-release-input.json", b'{"frozen":true}\n')
        pe_names = set(gate._required_pe_basenames(standalone_winn3, architecture))
        payloads: dict[str, bytes] = {}
        for name in sorted(pe_names):
            relative = (
                f"stage/NativeMessagingHost/{name}"
                if name == gate.NATIVE_HOST_BASENAME
                else f"stage/{name}"
            )
            if name == "wins_vpn.exe":
                payloads[relative] = app_pe(machine)
            else:
                payloads[relative] = signed_pe(machine)
        vc_name = PRODUCER_VC_REDIST_BASENAME[architecture]
        payloads[f"stage/{vc_name}"] = producer_vc_redist_pe(architecture)
        payloads["stage/data/app.so"] = b"\x7fELF" + b"\x00" * 64
        payloads["stage/NativeMessagingHost/org.winsvpn.bridge.firefox.json"] = (
            native_manifest("firefox")
        )
        if include_chrome_edge:
            payloads["stage/NativeMessagingHost/org.winsvpn.bridge.chrome.json"] = (
                native_manifest("chrome")
            )
            payloads["stage/NativeMessagingHost/org.winsvpn.bridge.edge.json"] = (
                native_manifest("edge")
            )
        if not standalone_winn3:
            helper = {
                "source_version": "3.1.0",
                "engine_module": gate.AWG_GO_MODULE,
                "engine_version": gate.AWG_GO_VERSION,
                "engine_commit": gate.AWG_GO_COMMIT,
                "target": f"windows-{go_arch}",
            }
            if architecture == "arm64":
                helper.update(
                    reproducibility_builds=2,
                    reproducibility_status="two_clean_builds_byte_identical",
                )
            engine = {
                "engine_module": gate.AWG_GO_MODULE,
                "engine_version": gate.AWG_GO_VERSION,
                "engine_commit": gate.AWG_GO_COMMIT,
                "execution_guard_status": "verified_after_authenticode_phase",
                "target_architecture": go_arch,
                "artifact_sha256": hashlib.sha256(
                    payloads["stage/winsvpn_awg_engine.exe"]
                ).hexdigest(),
            }
            payloads["stage/amneziawg.exe.provenance.json"] = json.dumps(
                helper, sort_keys=True
            ).encode()
            payloads["stage/winsvpn_awg_engine.exe.provenance.json"] = json.dumps(
                engine, sort_keys=True
            ).encode()
            payloads[
                f"stage/{PRODUCER_AMNEZIAWG_MSI_BASENAME[architecture]}"
            ] = producer_amneziawg_msi(architecture)
        entries = []
        hashes: dict[str, str] = {}
        for relative, payload in sorted(payloads.items()):
            self.write(relative, payload)
            digest = hashlib.sha256(payload).hexdigest()
            hashes[gate._packed_inner_name(relative)] = digest
            entries.append(
                {"path": relative, "size": len(payload), "sha256": digest}
            )
        record = {
            "schema_version": 3,
            "target_architecture": architecture,
            "distribution_surface": surface,
            "standalone_winn3": standalone_winn3,
            "standalone_payload_verified": standalone_winn3,
            "installer": {
                "name": artifact.name,
                "size": artifact.stat().st_size,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            },
            "producer": self.producer_fields(),
            "signing": {
                "production_signed": True,
                "every_loose_pe_verified": True,
                "staged_xray_product_signed": not standalone_winn3,
                "inno_setup_and_uninstaller_signed": True,
                "self_signed_certificate_forbidden": True,
            },
            "release_input": {
                "path": "docs/windows-release-input.json",
                "sha256": hashlib.sha256(release_input.read_bytes()).hexdigest(),
            },
            "toolchain": flutter_pins(),
            "inno_compiler": inno_compiler_identity(architecture),
            "payload": entries,
        }
        self.write(
            artifact_rel + ".payload-manifest.json",
            (json.dumps(record, sort_keys=True) + "\n").encode(),
        )
        if write_install_proof:
            self.write_install_proof(target, artifact_rel, record, machine)
        return artifact_rel, hashes

    def write_install_proof(
        self,
        target: str,
        artifact_rel: str,
        record: dict[str, object],
        machine: int,
        *,
        installer: dict[str, object] | None = None,
        standalone_winn3: bool | None = None,
        installed: list[dict[str, object]] | None = None,
    ) -> pathlib.Path:
        artifact = self.repo / artifact_rel
        if installed is None:
            installed = []
            for entry in record["payload"]:
                packed = gate._packed_inner_name(str(entry["path"]))
                payload_type = gate._expected_payload_type(packed)
                item: dict[str, object] = {
                    "path": packed,
                    "type": payload_type,
                    "size": entry["size"],
                    "sha256": entry["sha256"],
                }
                if payload_type == "pe":
                    item["pe_machine"] = machine
                installed.append(item)
        proof = {
            "schema": gate.INSTALL_PROOF_SCHEMA,
            "schema_version": gate.INSTALL_PROOF_SCHEMA_VERSION,
            "target_id": target,
            "standalone_winn3": (
                record["standalone_winn3"]
                if standalone_winn3 is None
                else standalone_winn3
            ),
            "installer": installer
            or {
                "name": artifact.name,
                "size": artifact.stat().st_size,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            },
            "installed": installed,
        }
        return self.write(
            artifact_rel + gate.INSTALL_PROOF_SUFFIX,
            (json.dumps(proof, sort_keys=True) + "\n").encode(),
        )

    def packed_from_stage(self, artifact_rel: str) -> dict[str, bytes]:
        manifest = json.loads(
            (self.repo / (artifact_rel + ".payload-manifest.json")).read_text(
                encoding="utf-8"
            )
        )
        packed: dict[str, bytes] = {}
        for entry in manifest["payload"]:
            packed[gate._packed_inner_name(entry["path"])] = (
                self.repo / entry["path"]
            ).read_bytes()
        return packed

    def load_manifest(self, artifact: str) -> dict[str, object]:
        path = self.repo / (artifact + ".payload-manifest.json")
        return json.loads(path.read_text(encoding="utf-8"))

    def save_manifest(self, artifact: str, record: dict[str, object]) -> None:
        (self.repo / (artifact + ".payload-manifest.json")).write_text(
            json.dumps(record), encoding="utf-8"
        )

    def verify_fixture(
        self,
        target: str,
        artifact: str,
        hashes: dict[str, str],
        *,
        extract: bool = False,
        standalone_winn3: bool = False,
    ):
        architecture = gate.TARGET_ARCHITECTURES[target]
        awg_hashes = dict(gate.AWG_TOOL_SHA256)
        wintun_hashes = dict(gate.WINTUN_SHA256)
        xray_hashes = dict(gate.XRAY_SHA256)
        vc_hashes = dict(gate.VC_REDIST_SHA256)
        msi_hashes = dict(gate.AMNEZIAWG_MSI_SHA256)
        if "awg.exe" in hashes:
            awg_hashes[architecture] = hashes["awg.exe"]
        if "wintun.dll" in hashes:
            wintun_hashes[architecture] = hashes["wintun.dll"]
        if "xray.exe" in hashes:
            xray_hashes[architecture] = hashes["xray.exe"]
        vc_name = PRODUCER_VC_REDIST_BASENAME[architecture]
        if vc_name in hashes:
            vc_hashes[architecture] = hashes[vc_name]
        msi_name = PRODUCER_AMNEZIAWG_MSI_BASENAME[architecture]
        if msi_name in hashes:
            msi_hashes[architecture] = hashes[msi_name]
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(gate, "AWG_TOOL_SHA256", awg_hashes))
            stack.enter_context(mock.patch.object(gate, "WINTUN_SHA256", wintun_hashes))
            stack.enter_context(mock.patch.object(gate, "XRAY_SHA256", xray_hashes))
            stack.enter_context(mock.patch.object(gate, "VC_REDIST_SHA256", vc_hashes))
            stack.enter_context(
                mock.patch.object(gate, "AMNEZIAWG_MSI_SHA256", msi_hashes)
            )
            stack.enter_context(
                mock.patch.object(gate, "_verify_privacy_of_paths", return_value=None)
            )
            installer_bytes = (self.repo / artifact).read_bytes()
            artifact_name = pathlib.Path(artifact).name
            try:
                leaf = gate.authenticode_leaf_identity(artifact_name, installer_bytes)
            except gate.WindowsArtifactGateError:
                leaf = None
            tool = self.write("tools/signtool.exe", b"signtool-fixture")
            stack.enter_context(
                mock.patch.object(gate, "authenticode_host_is_windows", return_value=True)
            )
            stack.enter_context(
                mock.patch.object(gate, "OWNER_AUTHENTICODE_SIGNTOOL", str(tool))
            )
            self.authenticode_calls: list[dict[str, object]] = []

            def run(argv, **kwargs):
                self.authenticode_calls.append(
                    {"argv": list(argv), "kwargs": dict(kwargs)}
                )
                if kwargs.get("shell") is not False:
                    raise AssertionError("Authenticode argv used a shell")
                if argv[1:6] != list(gate.AUTHENTICODE_VERIFY_ARGV_PREFIX):
                    return subprocess.CompletedProcess(
                        argv, 1, stdout="", stderr="unexpected argv"
                    )
                if leaf is None:
                    return subprocess.CompletedProcess(
                        argv, 1, stdout="", stderr="unsigned"
                    )
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    stdout=authenticode_signtool_stdout(leaf),
                    stderr="",
                )

            stack.enter_context(mock.patch.object(gate.subprocess, "run", side_effect=run))
            if leaf is not None:
                stack.enter_context(
                    mock.patch.object(
                        gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]
                    )
                )
            else:
                stack.enter_context(
                    mock.patch.object(
                        gate, "_verify_authenticode_offline", return_value=None
                    )
                )
            if extract:
                packed = self.packed_from_stage(artifact)
                inventory = gate._payload_inventory(self.load_manifest(artifact))
                if leaf is None:
                    leaf = gate.authenticode_leaf_identity(
                        artifact_name, installer_bytes
                    )
                policy = gate.authenticode_custody_policy(
                    artifact_name, installer_bytes, leaf
                )
                stack.enter_context(
                    mock.patch.object(
                        gate,
                        "extract_packed_inner_payloads",
                        return_value=packed,
                    )
                )
                result = gate.verify_artifact(target, artifact)
                gate.verify_packed_inner_payloads(
                    packed,
                    inventory,
                    architecture,
                    "1.0.17",
                    "1.0.17.34",
                    standalone_winn3,
                    custody_policy=policy,
                )
                return result
            return gate.verify_artifact(target, artifact)


class WindowsCrossStoreGateAdapterTests(WindowsCrossStoreGateFixtures, unittest.TestCase):
    def test_complete_sidecar_without_install_proof_fails_closed(self) -> None:
        for target in gate.TARGET_FILENAMES:
            artifact, hashes = self.candidate(target, write_install_proof=False)
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"PENDING:.*owner/environment blocker",
            ):
                self.verify_fixture(target, artifact, hashes)

    def test_production_inner_payload_evidence_is_explicit_pending(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"^PENDING:"
        ) as raised:
            self.verify_fixture("windows-x64-installer", artifact, hashes)
        self.assertIn(gate.INNER_PAYLOAD_EVIDENCE_PENDING, str(raised.exception))
        self.assertIn("no reviewed exact Inno extractor", str(raised.exception))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.INNO_INNER_EXTRACTOR_ERROR
        ):
            gate.extract_packed_inner_payloads(self.repo / artifact)
        self.assertNotIn("innoextract", pathlib.Path(gate.__file__).read_text(encoding="utf-8").lower())

    def test_synthetic_extract_preserves_website_and_partner_center_contracts(
        self,
    ) -> None:
        seen_identities = set()
        seen_descriptions = set()
        for target in gate.TARGET_FILENAMES:
            artifact, hashes = self.candidate(target, write_install_proof=False)
            result = self.verify_fixture(target, artifact, hashes, extract=True)
            self.assertEqual(result["target_id"], target)
            self.assertEqual(result["distribution_surface"], gate.TARGET_SURFACES[target])
            self.assertEqual(result["product_version"], "1.0.17")
            self.assertEqual(result["file_version"], "1.0.17.34")
            self.assertEqual(
                result["file_description"], gate.TARGET_FILE_DESCRIPTIONS[target]
            )
            self.assertEqual(
                result["producer_identity"], gate.REVIEWED_PRODUCER_IDENTITIES[target]
            )
            self.assertFalse(result["standalone_winn3"])
            self.assertFalse(result["inner_payloads_proven_from_install_proof"])
            self.assertTrue(result["inner_payloads_proven_from_snapshot"])
            self.assertEqual(result["packed_app_so"], "data/app.so")
            self.assertEqual(result["descriptor"], gate.DESCRIPTOR_RELATIVE)
            self.assertEqual(
                result["descriptor_sha256"],
                origin_digest(gate.DESCRIPTOR_RELATIVE),
            )
            self.assertEqual(
                result["authenticode_argv"],
                list(gate.AUTHENTICODE_VERIFY_ARGV_PREFIX),
            )
            self.assertEqual(result["authenticode_digest_algorithm"], "sha256")
            self.assertEqual(result["authenticode_revocation"], "checked")
            self.assertTrue(result["authenticode_verified_offline"])
            self.assertTrue(result["timestamp_verified"])
            self.assertEqual(len(self.authenticode_calls), 1)
            call = self.authenticode_calls[0]
            argv = call["argv"]
            self.assertEqual(argv[1:6], list(gate.AUTHENTICODE_VERIFY_ARGV_PREFIX))
            self.assertTrue(str(argv[0]).endswith("signtool.exe"))
            self.assertIs(call["kwargs"]["shell"], False)
            seen_identities.add(result["producer_identity"])
            seen_descriptions.add(result["file_description"])
        self.assertEqual(len(seen_identities), 4)
        self.assertEqual(
            seen_descriptions,
            {
                "Win's VPN x64 website installer",
                "Win's VPN x64 Partner Center Win32 installer",
                "Win's VPN arm64 website installer",
                "Win's VPN arm64 Partner Center Win32 installer",
            },
        )

    def test_website_and_partner_center_cannot_be_byte_identical_relabels(self) -> None:
        website, hashes = self.candidate("windows-x64-installer", write_install_proof=False)
        partner = "artifacts/WinsVPN-PartnerCenter.exe"
        self.write(partner, (self.repo / website).read_bytes())
        record = self.load_manifest(website)
        record["distribution_surface"] = "partner-center"
        record["installer"] = {
            "name": "WinsVPN-PartnerCenter.exe",
            "size": (self.repo / partner).stat().st_size,
            "sha256": hashlib.sha256((self.repo / partner).read_bytes()).hexdigest(),
        }
        self.save_manifest(partner, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"FileDescription is not the reviewed partner-center producer identity",
        ):
            self.verify_fixture("windows-x64-partner-center", partner, hashes, extract=True)

    def test_stale_installer_and_payload_versions_fail_for_both_architectures(
        self,
    ) -> None:
        for target in ("windows-x64-installer", "windows-arm64-installer"):
            with self.subTest(target=target, stale="installer"):
                artifact, hashes = self.candidate(
                    target,
                    write_install_proof=False,
                    installer_bytes=installer_pe(target, ProductVersion="9.9.9"),
                )
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError,
                    rf"{re.escape(gate.TARGET_FILENAMES[target])} ProductVersion.*1\.0\.16",
                ):
                    self.verify_fixture(target, artifact, hashes, extract=True)
            with self.subTest(target=target, stale="wins_vpn.exe"):
                artifact, hashes = self.candidate(target, write_install_proof=False)
                machine = {
                    "x64": gate.PE_MACHINE_X64,
                    "arm64": gate.PE_MACHINE_ARM64,
                }[gate.TARGET_ARCHITECTURES[target]]
                stale = app_pe(machine, ProductVersion="9.9.9")
                (self.repo / "stage/wins_vpn.exe").write_bytes(stale)
                record = self.load_manifest(artifact)
                for entry in record["payload"]:
                    if entry["path"] == "stage/wins_vpn.exe":
                        entry["size"] = len(stale)
                        entry["sha256"] = hashlib.sha256(stale).hexdigest()
                self.save_manifest(artifact, record)
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError,
                    r"wins_vpn\.exe ProductVersion.*1\.0\.16",
                ):
                    self.verify_fixture(target, artifact, hashes, extract=True)

    def test_missing_product_or_file_version_fails_for_both_architectures(
        self,
    ) -> None:
        for target in ("windows-x64-installer", "windows-arm64-installer"):
            artifact, hashes = self.candidate(
                target,
                write_install_proof=False,
                installer_bytes=signed_pe(gate.PE_MACHINE_X86, pkcs7=reviewed_pkcs7()),
            )
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, r"VERSIONINFO"
            ):
                self.verify_fixture(target, artifact, hashes)

    def test_target_confusion_and_wrong_filename_fail(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        with self.assertRaisesRegex(gate.WindowsArtifactGateError, "another exact target"):
            self.verify_fixture("windows-x64-partner-center", artifact, hashes)

    def test_manifest_surface_confusion_fails(self) -> None:
        target = "windows-x64-installer"
        artifact, hashes = self.candidate(target, write_install_proof=False)
        manifest = self.repo / (artifact + ".payload-manifest.json")
        record = json.loads(manifest.read_text())
        record["distribution_surface"] = "partner-center"
        manifest.write_text(json.dumps(record))
        with self.assertRaisesRegex(gate.WindowsArtifactGateError, "another exact target"):
            self.verify_fixture(target, artifact, hashes)

    def test_path_escape_and_symlink_refused(self) -> None:
        with self.assertRaisesRegex(gate.WindowsArtifactGateError, "canonical"):
            gate.canonical_artifact("windows-x64-installer", "../WinsVPN-Setup.exe")
        outside = pathlib.Path(self.temp.name).parent / "outside-WinsVPN-Setup.exe"
        outside.write_bytes(b"x")
        link = self.repo / "WinsVPN-Setup.exe"
        try:
            link.symlink_to(outside)
            with self.assertRaisesRegex(gate.WindowsArtifactGateError, "symlink|reparse"):
                gate.canonical_artifact("windows-x64-installer", "WinsVPN-Setup.exe")
        finally:
            outside.unlink(missing_ok=True)

    def test_wrong_architecture_payload_fails(self) -> None:
        for target, bad_machine, expected in (
            ("windows-x64-installer", gate.PE_MACHINE_ARM64, "x64"),
            ("windows-arm64-installer", gate.PE_MACHINE_X64, "arm64"),
        ):
            artifact, hashes = self.candidate(target, write_install_proof=False)
            bad = app_pe(bad_machine)
            (self.repo / "stage/wins_vpn.exe").write_bytes(bad)
            record = self.load_manifest(artifact)
            for entry in record["payload"]:
                if entry["path"] == "stage/wins_vpn.exe":
                    entry["size"] = len(bad)
                    entry["sha256"] = hashlib.sha256(bad).hexdigest()
            self.save_manifest(artifact, record)
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, rf"PE32\+ {expected}"
            ):
                self.verify_fixture(target, artifact, hashes, extract=True)

    def test_missing_winn_v3_payload_fails(self) -> None:
        target = "windows-x64-installer"
        artifact, hashes = self.candidate(target, write_install_proof=False)
        record = self.load_manifest(artifact)
        record["payload"] = [
            entry
            for entry in record["payload"]
            if not entry["path"].endswith("winn-datapath.exe")
        ]
        self.save_manifest(artifact, record)
        with self.assertRaisesRegex(gate.WindowsArtifactGateError, "incomplete"):
            self.verify_fixture(target, artifact, hashes)

    def test_renamed_mullvad_hash_fails(self) -> None:
        target = "windows-x64-installer"
        artifact, hashes = self.candidate(target, write_install_proof=False)
        planted = self.write("stage/neutral.bin", b"withdrawn-driver")
        digest = hashlib.sha256(planted.read_bytes()).hexdigest()
        record = self.load_manifest(artifact)
        record["payload"].append(
            {"path": "stage/neutral.bin", "size": planted.stat().st_size, "sha256": digest}
        )
        self.save_manifest(artifact, record)
        with (
            mock.patch.object(gate, "WITHDRAWN_MULLVAD_SHA256", frozenset({digest})),
            self.assertRaisesRegex(gate.WindowsArtifactGateError, "including when renamed"),
        ):
            self.verify_fixture(target, artifact, hashes)

    def test_ignored_schema_values_fail_closed(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        record = self.load_manifest(artifact)
        record["producer"] = {}
        record["release_input"] = {"path": record["release_input"]["path"]}
        record["toolchain"] = {
            **record["toolchain"],
            "framework_version": "9.9.9",
        }
        self.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"exact schema|reviewed Flutter pin"
        ):
            self.verify_fixture("windows-x64-installer", artifact, hashes)

    def test_producer_inno_compiler_identity_is_bound_to_the_reviewed_pin(self) -> None:
        # R22 Y3-04: build_installer.ps1 writes inno_compiler into every v3
        # payload manifest. The gate accepts exactly that record and refuses a
        # missing, altered, extended or other-architecture identity.
        for target in ("windows-x64-installer", "windows-arm64-installer"):
            with self.subTest(target=target):
                artifact, hashes = self.candidate(target, write_install_proof=False)
                result = self.verify_fixture(target, artifact, hashes, extract=True)
                self.assertEqual(result["target_id"], target)
        target = "windows-x64-installer"
        artifact, hashes = self.candidate(target, write_install_proof=False)
        original = self.load_manifest(artifact)
        other = inno_compiler_identity("arm64")
        mutations = {
            "missing": (lambda record: record.pop("inno_compiler"), "exact schema"),
            "null": (lambda record: record.update(inno_compiler=None), "exact schema"),
            "extra key": (
                lambda record: record["inno_compiler"].update(note="x"),
                "exact schema",
            ),
            "compiler hash": (
                lambda record: record["inno_compiler"].update(sha256="1" * 64),
                "reviewed pin",
            ),
            "install tree": (
                lambda record: record["inno_compiler"].update(
                    install_tree_sha256="2" * 64
                ),
                "reviewed pin",
            ),
            "pin digest": (
                lambda record: record["inno_compiler"].update(pin_sha256="3" * 64),
                "reviewed pin",
            ),
            "size as text": (
                lambda record: record["inno_compiler"].update(
                    size=str(record["inno_compiler"]["size"])
                ),
                "JSON integer",
            ),
            "other architecture": (
                lambda record: record.update(inno_compiler=other),
                "reviewed pin",
            ),
        }
        for label, (mutate, message) in mutations.items():
            with self.subTest(mutation=label):
                record = json.loads(json.dumps(original))
                mutate(record)
                self.save_manifest(artifact, record)
                with self.assertRaisesRegex(gate.WindowsArtifactGateError, message):
                    self.verify_fixture(target, artifact, hashes, extract=True)

    def test_non_windows_signature_check_fails_closed(self) -> None:
        if gate.os.name == "nt":
            self.skipTest("non-Windows-only assertion")
        artifact, _ = self.candidate("windows-x64-installer", write_install_proof=False)
        with self.assertRaisesRegex(gate.WindowsArtifactGateError, "owner/environment blocker"):
            gate._verify_authenticode_offline(self.repo / artifact)

    def test_exact_cli_and_core_producer_mappings(self) -> None:
        with self.assertRaisesRegex(gate.WindowsArtifactGateError, "exactly --verify"):
            gate.main(["--verify", "windows-x64-installer"])
        for invented_target in (
            "windows-x64-website-zip",
            "windows-x64-store-msix",
        ):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                "unsupported exact Windows target",
            ):
                gate.canonical_artifact(invented_target, "artifacts/unused")
        for gate_id in (
            "windows-x64-authenticode",
            "windows-x64-store-signature",
            "windows-arm64-authenticode",
            "windows-arm64-store-signature",
        ):
            self.assertEqual(
                readiness.GATE_PRODUCER_IDS[gate_id],
                ("tools/windows_cross_store_artifact_gate.py",),
            )
        self.assertEqual(
            obfuscation.WINDOWS_CROSS_STORE_TARGETS,
            {
                "windows-x64-installer",
                "windows-x64-partner-center",
                "windows-arm64-installer",
                "windows-arm64-partner-center",
            },
        )

    def test_mutated_or_deleted_loose_files_do_not_count_as_packed_proof(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        (self.repo / "stage/wins_vpn.exe").write_bytes(b"tampered-not-packed")
        (self.repo / "stage/data/app.so").unlink()
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, r"owner/environment blocker"
        ):
            self.verify_fixture("windows-x64-installer", artifact, hashes)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.INNO_INNER_EXTRACTOR_ERROR
        ):
            gate.extract_packed_inner_payloads(self.repo / artifact)

    def test_gate_source_does_not_consult_path_inno_tools_or_run_the_installer(
        self,
    ) -> None:
        source = pathlib.Path(gate.__file__).read_text(encoding="utf-8")
        self.assertIn("import subprocess", source)
        self.assertIn("shell=False", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("import ctypes", source)
        self.assertNotIn("WinVerifyTrust", source)
        self.assertNotIn("Get-AuthenticodeSignature", source)
        self.assertNotIn("shutil.which", source)
        self.assertNotIn("innoextract", source.lower())
        self.assertNotIn("innounp", source.lower())
        self.assertNotIn("iscc.exe", source.lower())

    def test_inner_pe_reviewed_signer_matches_outer_custody_policy(self) -> None:
        policy = reviewed_custody_policy()
        self.assertTrue(policy.anchor_ders)
        pe = app_pe(gate.PE_MACHINE_X64)
        identity = gate._verify_inner_pe_authenticode("wins_vpn.exe", pe, policy)
        self.assertEqual(identity["sha256"], policy.leaf_sha256)

    def test_inner_pe_authenticode_framing_only_fails_closed(self) -> None:
        artifact, _hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        packed = self.packed_from_stage(artifact)
        framed = signed_pe(gate.PE_MACHINE_X64, authenticode=False)
        packed["wins_vpn.exe"] = framed
        record = self.load_manifest(artifact)
        for entry in record["payload"]:
            if entry["path"].endswith("wins_vpn.exe"):
                entry["size"] = len(framed)
                entry["sha256"] = hashlib.sha256(framed).hexdigest()
        self.save_manifest(artifact, record)
        inventory = gate._payload_inventory(self.load_manifest(artifact))
        policy = reviewed_custody_policy()
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"inner PE Authenticode is cryptographically invalid or untrusted|Authenticode PKCS#7",
        ) as raised:
            gate.verify_packed_inner_payloads(
                packed, inventory, "x64", "1.0.17", "1.0.17.34", False,
                custody_policy=policy,
            )
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"inner PE Authenticode is cryptographically invalid or untrusted|Authenticode PKCS#7",
        ):
            gate._verify_inner_pe_authenticode("wins_vpn.exe", framed, policy)

    def test_inner_pe_trusted_leaf_with_invalid_signature_fails_closed(self) -> None:
        invalid = signed_pe(
            gate.PE_MACHINE_X64,
            pkcs7=reviewed_pkcs7(),
        )
        policy = reviewed_custody_policy()
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.INNER_AUTHENTICODE_ERROR
        ) as raised:
            gate._verify_inner_pe_authenticode("wins_vpn.exe", invalid, policy)
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        identity = gate.authenticode_leaf_identity("wins_vpn.exe", invalid)
        self.assertEqual(identity["common_name"], gate.AUTHENTICODE_LEAF_CN)

    def test_inner_pe_cryptographically_valid_untrusted_publisher_fails_closed(
        self,
    ) -> None:
        _ca, leaf, key = untrusted_signer()
        untrusted = signed_pe(
            gate.PE_MACHINE_X64,
            signer=(_ca, leaf, key),
        )
        policy = reviewed_custody_policy()
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.INNER_AUTHENTICODE_ERROR
        ) as raised:
            gate._verify_inner_pe_authenticode("wins_vpn.exe", untrusted, policy)
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        self.assertNotIn("WIN'S VPN INC.", str(raised.exception))

    def test_inner_pe_lookalike_untrusted_ca_is_not_outer_custody_policy(
        self,
    ) -> None:
        policy = reviewed_custody_policy()
        self.assertTrue(policy.anchor_ders)
        _ca, leaf, key = lookalike_untrusted_signer()
        lookalike = signed_pe(
            gate.PE_MACHINE_X64,
            signer=(_ca, leaf, key),
        )
        identity = gate.authenticode_leaf_identity("wins_vpn.exe", lookalike)
        self.assertEqual(identity["common_name"], gate.AUTHENTICODE_LEAF_CN)
        self.assertEqual(identity["organization"], gate.AUTHENTICODE_LEAF_O)
        self.assertNotEqual(identity["sha256"], policy.leaf_sha256)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.INNER_AUTHENTICODE_ERROR
        ) as raised:
            gate._verify_inner_pe_authenticode("wins_vpn.exe", lookalike, policy)
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        self.assertNotIn("WIN'S VPN INC.", str(raised.exception))

    def test_public_verify_artifact_cannot_return_ok_when_signature_is_skipped(
        self,
    ) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.OUTER_SIGNATURE_SKIP_ERROR
        ) as raised:
            gate.verify_artifact(
                "windows-x64-installer", artifact, verify_signature=False
            )
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        self.assertNotIn('"ok": true', str(raised.exception).casefold())
        self.assertEqual(gate.OWNER_AUTHENTICODE_LEAF_SHA256, gate.OWNER_AUTHENTICODE_BLOCKED)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT",
        ):
            gate.verify_artifact("windows-x64-installer", artifact)
        with mock.patch.object(gate, "_verify_authenticode_offline", return_value=None):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT|outer Authenticode verification cannot be skipped",
            ):
                gate.verify_artifact("windows-x64-installer", artifact)
        result = self.verify_fixture(
            "windows-x64-installer", artifact, hashes, extract=True
        )
        self.assertTrue(result["ok"])
        self.assertIs(result["authenticode_verified_offline"], True)
        self.assertNotEqual(
            result["owner_authenticode_pin"], gate.OWNER_AUTHENTICODE_BLOCKED
        )
        self.assertEqual(
            result["authenticode_argv"], list(gate.AUTHENTICODE_VERIFY_ARGV_PREFIX)
        )
        self.assertRegex(result["authenticode_thumbprint"], r"^[0-9a-f]{40}$")

    def test_owner_authenticode_pin_stays_blocked_without_fixture_override(self) -> None:
        self.assertEqual(
            gate.OWNER_AUTHENTICODE_LEAF_SHA256, gate.OWNER_AUTHENTICODE_BLOCKED
        )
        self.assertEqual(
            gate.OWNER_AUTHENTICODE_SIGNTOOL, gate.OWNER_AUTHENTICODE_BLOCKED
        )
        self.assertEqual(
            gate.OWNER_UPLOAD_RECEIPT_PUBLIC_KEY_HEX, gate.OWNER_AUTHENTICODE_BLOCKED
        )
        self.assertTrue(gate.owner_authenticode_pin_blocked())
        self.assertTrue(gate.owner_authenticode_signtool_blocked())
        pe = installer_pe("windows-x64-installer")
        leaf = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", pe)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT",
        ):
            gate._require_owner_authenticode_leaf(leaf)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.OUTER_SIGNATURE_SKIP_ERROR
        ):
            gate._require_offline_authenticode_proof(
                None,
                leaf,
                target_id="windows-x64-installer",
                snapshot_sha256="0" * 64,
            )

    def test_timestamp_attribute_presence_is_not_a_false_green(self) -> None:
        missing = signed_pe(gate.PE_MACHINE_X64, timestamp=False)
        garbage = signed_pe(gate.PE_MACHINE_X64, timestamp="garbage")
        bound = signed_pe(gate.PE_MACHINE_X64, timestamp=True)
        self.assertFalse(gate.authenticode_timestamp_present("wins_vpn.exe", missing))
        self.assertTrue(gate.authenticode_timestamp_present("wins_vpn.exe", garbage))
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.TIMESTAMP_MISSING_ERROR
        ):
            gate._verify_authenticode_timestamp("wins_vpn.exe", missing)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.TIMESTAMP_UNVERIFIED_ERROR
        ):
            gate._verify_authenticode_timestamp("wins_vpn.exe", garbage)
        gate._verify_authenticode_timestamp("wins_vpn.exe", bound)
        identity = gate.authenticode_leaf_identity("wins_vpn.exe", bound)
        policy = gate.authenticode_custody_policy("wins_vpn.exe", bound, identity)
        gate._verify_outer_pe_authenticode("wins_vpn.exe", bound, policy)
        missing_identity = gate.authenticode_leaf_identity("wins_vpn.exe", missing)
        missing_policy = gate.authenticode_custody_policy(
            "wins_vpn.exe", missing, missing_identity
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.TIMESTAMP_MISSING_ERROR
        ):
            gate._verify_outer_pe_authenticode("wins_vpn.exe", missing, missing_policy)

    def test_outer_installer_framing_only_signature_fails_closed(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer",
            write_install_proof=False,
            installer_bytes=installer_pe(
                "windows-x64-installer",
                pkcs7=reviewed_pkcs7(),
            ),
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.OUTER_AUTHENTICODE_ERROR
        ) as raised:
            self.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )
        self.assertNotIn("owner/environment blocker", str(raised.exception))

    def test_outer_installer_trusted_leaf_with_invalid_signature_fails_closed(
        self,
    ) -> None:
        invalid = installer_pe("windows-x64-installer", pkcs7=reviewed_pkcs7())
        identity = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", invalid)
        policy = gate.authenticode_custody_policy(
            "WinsVPN-Setup.exe", invalid, identity
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.OUTER_AUTHENTICODE_ERROR
        ) as raised:
            gate._verify_outer_pe_authenticode("WinsVPN-Setup.exe", invalid, policy)
        self.assertNotIn("owner/environment blocker", str(raised.exception))

    def test_incomplete_authenticode_chain_cannot_emit_empty_anchor_policy(
        self,
    ) -> None:
        _ca, leaf, _key = reviewed_signer()
        pe = installer_pe(
            "windows-x64-installer",
            pkcs7=encode_pkcs7([leaf], leaf),
        )
        identity = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", pe)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"no verified issuer/anchor",
        ) as raised:
            gate.authenticode_custody_policy("WinsVPN-Setup.exe", pe, identity)
        self.assertNotIn("owner/environment blocker", str(raised.exception))
        empty = gate.AuthenticodeCustodyPolicy(
            leaf_sha256=identity["sha256"],
            leaf_der=b"\x30\x03\x02\x01\x00",
            anchor_ders=(),
            intermediate_ders=(),
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.INNER_AUTHENTICODE_ERROR
        ):
            gate._require_custody_policy(empty)

    def test_packed_private_symbol_files_are_refused(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        planted = self.write("stage/wins_vpn.pdb", b"private-symbols")
        record = self.load_manifest(artifact)
        record["payload"].append(
            {
                "path": "stage/wins_vpn.pdb",
                "size": planted.stat().st_size,
                "sha256": hashlib.sha256(planted.read_bytes()).hexdigest(),
            }
        )
        self.save_manifest(artifact, record)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "private symbol file"
        ):
            self.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )

    def test_architecture_confused_original_filename_fails(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer",
            write_install_proof=False,
            installer_bytes=installer_pe(
                "windows-x64-installer",
                OriginalFilename="WinsVPN-Setup-arm64.exe",
            ),
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "OriginalFilename is not the reviewed x64"
        ):
            self.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )

    def test_source_map_reference_in_packed_payload_is_refused(self) -> None:
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "source-map reference"
        ):
            gate._reject_packaged_private_symbols(
                "data/app.so", b"//# sourceMappingURL=app.so.map\n"
            )

    def test_caller_authored_winverifytrust_json_cannot_green_verify_artifact(
        self,
    ) -> None:
        artifact, _hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        installer_bytes = (self.repo / artifact).read_bytes()
        leaf = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", installer_bytes)
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]
                )
            )
            stack.enter_context(
                mock.patch.object(
                    gate,
                    "_verify_authenticode_offline",
                    return_value={
                        "winverifytrust_status": 0,
                        "timestamp_verified": True,
                        "owner_authenticode_leaf_sha256": leaf["sha256"],
                        "signer_subject": leaf["subject"],
                        "schema": gate.WEBSITE_WINVERIFYTRUST_SCHEMA,
                    },
                )
            )
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                gate.CALLER_AUTHORED_AUTHENTICODE_JSON_ERROR,
            ):
                gate.verify_artifact("windows-x64-installer", artifact)

    def test_caller_authored_success_json_stdout_is_not_authenticode_evidence(
        self,
    ) -> None:
        leaf = gate.authenticode_leaf_identity(
            "WinsVPN-Setup.exe", installer_pe("windows-x64-installer")
        )
        payload = json.dumps(
            {
                "winverifytrust_status": 0,
                "timestamp_verified": True,
                "signature_verified": True,
                "schema": gate.WEBSITE_WINVERIFYTRUST_SCHEMA,
            }
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            gate.CALLER_AUTHORED_AUTHENTICODE_JSON_ERROR,
        ):
            gate._parse_authenticode_verify_output(payload, "", leaf)

    def test_website_authenticode_proof_is_not_partner_center_upload_proof(
        self,
    ) -> None:
        leaf = gate.authenticode_leaf_identity(
            "WinsVPN-PartnerCenter.exe",
            installer_pe("windows-x64-partner-center"),
        )
        proof = valid_offline_authenticode_proof(
            leaf,
            target_id="windows-x64-partner-center",
            surface="website",
        )
        with mock.patch.object(gate, "OWNER_AUTHENTICODE_SIGNTOOL", "/abs/signtool.exe"):
            with mock.patch.object(
                gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]
            ):
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError,
                    gate.WEBSITE_SIGNING_AS_PARTNER_CENTER_ERROR,
                ):
                    gate._require_offline_authenticode_proof(
                        proof,
                        leaf,
                        target_id="windows-x64-partner-center",
                        snapshot_sha256="a" * 64,
                    )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            gate.WEBSITE_SIGNING_AS_PARTNER_CENTER_ERROR,
        ):
            gate._reject_website_signing_evidence(
                "windows-x64-partner-center",
                {
                    "store_evidence": {
                        "schema": gate.WEBSITE_WINVERIFYTRUST_SCHEMA,
                        "winverifytrust_receipt": True,
                        "path": "artifacts/WinsVPN-Setup.exe.authenticode.json",
                        "signing_contract": "windows-x64-authenticode",
                    }
                },
            )

    def test_weak_digest_and_revocation_uncertainty_fail_closed(self) -> None:
        leaf = gate.authenticode_leaf_identity(
            "WinsVPN-Setup.exe", installer_pe("windows-x64-installer")
        )
        sha1_stdout = authenticode_signtool_stdout(leaf).replace("sha256", "sha1")
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.WEAK_DIGEST_ERROR
        ):
            gate._parse_authenticode_verify_output(sha1_stdout, "", leaf)
        skipped = authenticode_signtool_stdout(leaf).replace(
            "Revocation check: The certificate chain was verified and revocation was checked.",
            "Revocation check skipped because the revocation function was unable to check revocation.",
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.REVOCATION_UNCERTAIN_ERROR
        ):
            gate._parse_authenticode_verify_output(skipped, "", leaf)
        wrong_thumb = authenticode_signtool_stdout(leaf).replace(
            leaf["thumbprint"], "0" * 40
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.OUTER_AUTHENTICODE_ERROR
        ):
            gate._parse_authenticode_verify_output(wrong_thumb, "", leaf)
        ca, cert, _key = reviewed_signer()
        weak = installer_pe(
            "windows-x64-installer",
            pkcs7=encode_pkcs7(
                [ca, cert],
                cert,
                timestamp=True,
                digest_oid="1.3.14.3.2.26",
            ),
        )
        identity = gate.authenticode_leaf_identity("WinsVPN-Setup.exe", weak)
        policy = gate.authenticode_custody_policy(
            "WinsVPN-Setup.exe", weak, identity
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.OUTER_AUTHENTICODE_ERROR
        ):
            gate._verify_outer_pe_authenticode("WinsVPN-Setup.exe", weak, policy)

    def test_unsigned_installer_cannot_skip_outer_authenticode(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer",
            write_install_proof=False,
            installer_bytes=installer_pe(
                "windows-x64-installer", authenticode=False
            ),
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"Authenticode PKCS#7|no embedded Authenticode|invalid WIN_CERTIFICATE",
        ):
            self.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )

    def test_hardlink_and_symlink_artifact_replacement_fail_closed(self) -> None:
        artifact, hashes = self.candidate(
            "windows-x64-installer", write_install_proof=False
        )
        origin = self.repo / artifact
        hard = self.repo / "artifacts" / "WinsVPN-Setup-hardlink.exe"
        os.link(origin, hard)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "single-link|singly-linked"
        ):
            self.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )
        hard.unlink()
        real = origin.with_name("WinsVPN-Setup.exe.real")
        origin.rename(real)
        origin.symlink_to(real)
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, "symlink|reparse"
        ):
            self.verify_fixture(
                "windows-x64-installer", artifact, hashes, extract=True
            )

    def test_hardlinked_signtool_is_refused(self) -> None:
        tool = self.write("tools/signtool.exe", b"signtool-fixture")
        os.link(tool, self.repo / "tools" / "signtool-alias.exe")
        with mock.patch.object(gate, "OWNER_AUTHENTICODE_SIGNTOOL", str(tool)):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError, "single-link regular file"
            ):
                gate._bind_authenticode_signtool()

    def test_stale_unbound_and_wrong_target_build_receipts_fail_closed(self) -> None:
        digest = "a" * 64
        fresh = build_receipt_payload(
            name="WinsVPN-Setup.exe", digest=digest, size_bytes=12
        )
        gate._bind_windows_build_receipt(
            "windows-x64-installer",
            fresh,
            expected_sha256=digest,
            expected_bytes=12,
        )
        stale = build_receipt_payload(
            name="WinsVPN-Setup.exe",
            digest=digest,
            size_bytes=12,
            finished_utc="2020-01-01T00:00:00Z",
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.BUILD_RECEIPT_STALE_ERROR
        ):
            gate._bind_windows_build_receipt(
                "windows-x64-installer",
                stale,
                expected_sha256=digest,
                expected_bytes=12,
            )
        unbound = build_receipt_payload(
            name="WinsVPN-Setup.exe",
            digest="b" * 64,
            size_bytes=12,
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.BUILD_RECEIPT_IDENTITY_ERROR
        ):
            gate._bind_windows_build_receipt(
                "windows-x64-installer",
                unbound,
                expected_sha256=digest,
                expected_bytes=12,
            )
        swapped = build_receipt_payload(
            name="WinsVPN-Setup-arm64.exe",
            digest=digest,
            size_bytes=12,
            target="windows-arm64-inno-signed",
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.BUILD_RECEIPT_IDENTITY_ERROR
        ):
            gate._bind_windows_build_receipt(
                "windows-x64-installer",
                swapped,
                expected_sha256=digest,
                expected_bytes=12,
            )

    def test_shell_and_relative_authenticode_argv_are_refused(self) -> None:
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.AUTHENTICODE_ARGV_ERROR
        ):
            gate._require_exact_authenticode_argv(
                [
                    "/abs/signtool.exe",
                    "verify",
                    "/pa",
                    "/all",
                    "/v",
                    "/tw",
                ],
                "/abs/snapshot.bin",
            )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.AUTHENTICODE_ARGV_ERROR
        ):
            gate._require_exact_authenticode_argv(
                [
                    "signtool.exe",
                    "verify",
                    "/pa",
                    "/all",
                    "/v",
                    "/tw",
                    "/abs/snapshot.bin",
                ],
                "/abs/snapshot.bin",
            )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError, gate.AUTHENTICODE_ARGV_ERROR
        ):
            gate._require_exact_authenticode_argv(
                [
                    "/abs/powershell.exe",
                    "-Command",
                    "Get-AuthenticodeSignature",
                    "/pa",
                    "/all",
                    "/v",
                    "/abs/snapshot.bin",
                ],
                "/abs/snapshot.bin",
            )
        leaf = gate.authenticode_leaf_identity(
            "WinsVPN-Setup.exe", installer_pe("windows-x64-installer")
        )
        proof = valid_offline_authenticode_proof(leaf)
        proof["shell"] = True
        with mock.patch.object(gate, "OWNER_AUTHENTICODE_SIGNTOOL", "/abs/signtool.exe"):
            with mock.patch.object(
                gate, "OWNER_AUTHENTICODE_LEAF_SHA256", leaf["sha256"]
            ):
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, gate.AUTHENTICODE_ARGV_ERROR
                ):
                    gate._require_offline_authenticode_proof(
                        proof,
                        leaf,
                        target_id="windows-x64-installer",
                        snapshot_sha256="a" * 64,
                    )

    def test_architecture_or_target_substituted_installer_fails(self) -> None:
        artifact, hashes = self.candidate(
            "windows-arm64-installer",
            write_install_proof=False,
            installer_bytes=installer_pe("windows-x64-installer"),
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"OriginalFilename is not the reviewed arm64|FileDescription is not the reviewed",
        ):
            self.verify_fixture(
                "windows-arm64-installer", artifact, hashes, extract=True
            )
        artifact, hashes = self.candidate(
            "windows-x64-partner-center",
            write_install_proof=False,
            installer_bytes=installer_pe("windows-x64-installer"),
        )
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"FileDescription is not the reviewed partner-center|OriginalFilename is not the reviewed x64",
        ):
            self.verify_fixture(
                "windows-x64-partner-center", artifact, hashes, extract=True
            )


if __name__ == "__main__":
    unittest.main()
