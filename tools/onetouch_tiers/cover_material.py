"""Throwaway cover, Winn leaf and ECH test material for the S7 harness (owner item 8).

The data-plane installer runs a winn3-gateway that refuses to serve without five inputs
(`winn3gw_cover_material` in server/wins_data_plane_setup_ONETOUCH.sh): the cover certificate and key, the
ECH key set, and the Winn leaf certificate and key. This module makes a set a test guest's gateway accepts,
and checks a set the way the gateway would.

What the gateway requires, read from its source (cmd/winn3-gateway/cover.go startCover and the packages it calls):
  * ech_keys: the JSON key file internal/echconfig.LoadServerKeys reads ("winn-ech-key-set/v1", 1 to 8
    entries, each an RFC 9849 ECHConfig with X25519 HPKE and a 32-byte private key that matches it), the
    exact bytes cmd/winn-ech-keygen writes. Private file: no group or other bits.
  * winn_cert / winn_key: the strict-profile leaf (tlsconfig.ServerAnonymousForALPN). Its first DNS SAN is
    the private ECH-inner server name (tlsconfig.PrivateServerNameFromCertificate).
  * cover_cert / cover_key: the certificate every prober sees. coverlisten.ReviewCoverCertificate refuses a
    cover leaf that is self-signed, a CA, sent without its issuing chain, issued by the same CA as the Winn
    leaf, named like the Winn leaf, carrying any subject attribute but CN, carrying an EV/OV/IV policy,
    without a publicly shaped DNS name (reserved TLDs such as .test are refused), expired or not yet valid,
    or valid for more than 398 days.

So the set uses two throwaway CAs: a "test CA" that issues the cover leaf (and the optional hub leaf) and a
separate "Winn CA" that issues the Winn leaf. One CA for both is refused by the gateway (same issuer DN).

Every key here is test material made on this machine for a disposable guest. Nothing reads a real key, and
the CLI never prints key bytes.

CLI:
  cover_material.py generate --out DIR --cover-host NAME [--winn-host NAME] [--hub-host NAME] [--days N]
  cover_material.py validate --dir DIR [--cover-host NAME] [--winn-host NAME]
  cover_material.py installer-check --dir DIR [--mode preflight|install] [--bash PATH]
  cover_material.py go-check --dir DIR --scratch DIR [--gateway] [--expect start|refuse]
"""
import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODULE_DIR = ROOT / "winn_protocol_experimental"

# The five gateway inputs, under the names winn3gw_cover_material derives with ${name,,}, and the
# injection variable it reads for each one (WINN3_COVER_${name#COVER_}_B64).
GATEWAY_FILES = ("cover_cert", "cover_key", "ech_keys", "winn_cert", "winn_key")
INJECTION = {
    "cover_cert": "WINN3_COVER_CERT_B64",
    "cover_key": "WINN3_COVER_KEY_B64",
    "ech_keys": "WINN3_COVER_ECH_KEYS_B64",
    "winn_cert": "WINN3_COVER_WINN_CERT_B64",
    "winn_key": "WINN3_COVER_WINN_KEY_B64",
}
PRIVATE_FILES = ("cover_key", "ech_keys", "winn_key", "test_ca.key", "winn_ca.key", "hub_key", "cover.env")
PUBLIC_FILES = ("cover_cert", "winn_cert", "test_ca.pem", "winn_ca.pem", "hub_cert", "ech_config_list.bin",
                "MANIFEST.json")

# internal/echconfig/ech.go constants.
ECH_KEY_FILE_FORMAT = "winn-ech-key-set/v1"
ECH_VERSION = 0xFE0D
ECH_KEM_X25519_HKDF_SHA256 = 0x0020
ECH_KDF_HKDF_SHA256 = 0x0001
ECH_AEAD_AES128GCM = 0x0001
ECH_AEAD_CHACHA20POLY1305 = 0x0003
ECH_MAX_NAME_LENGTH = 253
ECH_MAX_CONFIG_SIZE = 64 << 10

# internal/coverlisten/covercert.go.
RESERVED_TLDS = frozenset(("local", "localhost", "invalid", "test", "example", "internal", "onion", "home", "corp",
                           "lan", "alt"))
IDENTIFYING_POLICIES = {"2.23.140.1.1": "Extended Validation", "2.23.140.1.2.2": "Organization Validation",
                        "2.23.140.1.2.3": "Individual Validation"}
DV_POLICY = "2.23.140.1.2.1"
MAX_PUBLIC_VALIDITY = datetime.timedelta(days=398)
# One hour of backdating for guest clock skew, so N days plus that hour stays inside 398.
BACKDATE = datetime.timedelta(hours=1)
MAX_DAYS = 397

MANIFEST_FORMAT = "s7-cover-material/v1"


class MaterialError(Exception):
    """A request the generator refuses, or material that fails a check."""


def _crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as error:  # pragma: no cover - depends on the host
        raise MaterialError("the Python 'cryptography' package is required on the harness host: %s" % error)
    return x509, hashes, serialization, ec, x25519, ExtendedKeyUsageOID, NameOID


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------
def valid_dns_name(value):
    """internal/echconfig validPublicName."""
    if not value or len(value) > 253 or value.startswith(".") or value.endswith(".") or ".." in value:
        return False
    for label in value.split("."):
        if not label or len(label) > 63 or label[0] == "-" or label[-1] == "-":
            return False
        for character in label:
            if not (character.isascii() and (character.isalnum() or character == "-")):
                return False
    return True


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def plausible_public_name(name):
    """The coverlisten reviewNames rule for one DNS name: a dot, a non-reserved TLD, not an IP literal."""
    normalized = name.strip().lower().rstrip(".")
    bare = normalized[2:] if normalized.startswith("*.") else normalized
    if "." not in bare:
        return False
    if bare.rsplit(".", 1)[1] in RESERVED_TLDS:
        return False
    return not _is_ip(bare)


def names_related(first, second):
    """coverlisten namesRelated: equal, or one a parent of the other at a label boundary."""
    def normalize(name):
        name = name.strip().lower().rstrip(".")
        return name[2:] if name.startswith("*.") else name
    first, second = normalize(first), normalize(second)
    if not first or not second:
        return False
    return first == second or first.endswith("." + second) or second.endswith("." + first)


# ---------------------------------------------------------------------------
# ECH (byte format of internal/echconfig marshalConfig and EncodeKeyFile)
# ---------------------------------------------------------------------------
def _u16(value):
    return value.to_bytes(2, "big")


def _opaque16(value):
    if len(value) > 0xFFFF:
        raise MaterialError("ECH opaque value is too large")
    return _u16(len(value)) + value


def ech_config(config_id, public_name, public_key):
    """One ECHConfig exactly as echconfig.marshalConfig writes it."""
    if len(public_key) != 32 or len(public_name) > 255 or not valid_dns_name(public_name):
        raise MaterialError("invalid ECH public key or public name")
    suites = (_u16(ECH_KDF_HKDF_SHA256) + _u16(ECH_AEAD_AES128GCM)
              + _u16(ECH_KDF_HKDF_SHA256) + _u16(ECH_AEAD_CHACHA20POLY1305))
    name = public_name.encode("ascii")
    contents = (bytes([config_id]) + _u16(ECH_KEM_X25519_HKDF_SHA256) + _opaque16(public_key) + _opaque16(suites)
                + bytes([ECH_MAX_NAME_LENGTH, len(name)]) + name + _u16(0))
    return _u16(ECH_VERSION) + _opaque16(contents)


def ech_config_list(configs):
    body = b"".join(configs)
    return _u16(len(body)) + body


def ech_key_file_bytes(entries):
    """echconfig.EncodeKeyFile: json.MarshalIndent(keys, "", "  ") plus a newline.

    entries: list of (config bytes, 32-byte private key, send_as_retry)."""
    document = {"format": ECH_KEY_FILE_FORMAT, "keys": [
        {"config": base64.b64encode(config).decode(), "private_key": base64.b64encode(private).decode(),
         "send_as_retry": bool(retry)} for config, private, retry in entries]}
    return (json.dumps(document, indent=2) + "\n").encode()


def ech_generate(public_name, config_id=0):
    """echconfig.Generate: returns (config list, key file bytes, public description)."""
    _, _, serialization, _, x25519, _, _ = _crypto()
    if not valid_dns_name(public_name):
        raise MaterialError("ECH public name must be a valid DNS name")
    if not 0 <= config_id <= 255:
        raise MaterialError("ECH config ID must be 0 to 255")
    if config_id == 0:
        config_id = secrets.randbelow(255) + 1
    private = x25519.X25519PrivateKey.generate()
    raw_private = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    config = ech_config(config_id, public_name, raw_public)
    info = {"config_id": config_id, "public_name": public_name,
            "public_key_sha256": hashlib.sha256(raw_public).hexdigest(),
            "config_sha256": hashlib.sha256(config).hexdigest()}
    return ech_config_list([config]), ech_key_file_bytes([(config, raw_private, True)]), info


def _read_opaque16(data):
    if len(data) < 2:
        raise MaterialError("truncated")
    length = int.from_bytes(data[:2], "big")
    if length > len(data) - 2:
        raise MaterialError("truncated")
    return data[2:2 + length], data[2 + length:]


def parse_ech_config(config):
    """echconfig.validateConfig, returning (config_id, public_name, public_key). Raises MaterialError."""
    if len(config) < 4 or int.from_bytes(config[:2], "big") != ECH_VERSION \
            or int.from_bytes(config[2:4], "big") != len(config) - 4:
        raise MaterialError("invalid RFC 9849 ECH config framing")
    contents = config[4:]
    if len(contents) < 1 + 2 + 2 + 2 + 1 + 1 + 2:
        raise MaterialError("truncated RFC 9849 ECH config contents")
    config_id = contents[0]
    contents = contents[1:]
    if int.from_bytes(contents[:2], "big") != ECH_KEM_X25519_HKDF_SHA256:
        raise MaterialError("unsupported ECH HPKE KEM")
    try:
        public_key, rest = _read_opaque16(contents[2:])
    except MaterialError:
        raise MaterialError("invalid ECH public key")
    if len(public_key) != 32:
        raise MaterialError("invalid ECH public key")
    if not any(public_key):
        raise MaterialError("ECH public key is all zero")
    try:
        suites, rest = _read_opaque16(rest)
    except MaterialError:
        raise MaterialError("invalid ECH cipher suites")
    if not suites or len(suites) % 4:
        raise MaterialError("invalid ECH cipher suites")
    for offset in range(0, len(suites), 4):
        kdf = int.from_bytes(suites[offset:offset + 2], "big")
        aead = int.from_bytes(suites[offset + 2:offset + 4], "big")
        if kdf != ECH_KDF_HKDF_SHA256 or aead not in (ECH_AEAD_AES128GCM, ECH_AEAD_CHACHA20POLY1305):
            raise MaterialError("unsupported ECH cipher suite")
    if len(rest) < 2:
        raise MaterialError("truncated ECH public name")
    maximum, length, rest = rest[0], rest[1], rest[2:]
    if length == 0 or length > len(rest):
        raise MaterialError("invalid ECH public name length")
    name = rest[:length].decode("ascii", "replace")
    rest = rest[length:]
    if not valid_dns_name(name) or maximum < len(name):
        raise MaterialError("invalid ECH public name")
    try:
        extensions, rest = _read_opaque16(rest)
    except MaterialError:
        raise MaterialError("invalid ECH extension vector")
    if rest:
        raise MaterialError("invalid ECH extension vector")
    while extensions:
        if len(extensions) < 4:
            raise MaterialError("truncated ECH extension")
        size = int.from_bytes(extensions[2:4], "big")
        if size > len(extensions) - 4:
            raise MaterialError("truncated ECH extension")
        extensions = extensions[4 + size:]
    return config_id, name, public_key


def parse_ech_key_file(data):
    """echconfig.LoadKeyFile and TLSKeys. Returns a list of entry dicts. Raises MaterialError."""
    _, _, serialization, _, x25519, _, _ = _crypto()
    if len(data) > ECH_MAX_CONFIG_SIZE:
        raise MaterialError("ECH key file exceeds %d bytes" % ECH_MAX_CONFIG_SIZE)
    decoder = json.JSONDecoder()
    try:
        text = data.decode("utf-8")
        document, end = decoder.raw_decode(text.lstrip())
    except (UnicodeDecodeError, ValueError) as error:
        raise MaterialError("ECH key file is not JSON: %s" % error)
    if text.lstrip()[end:].strip():
        raise MaterialError("ECH key file contains extra JSON")
    if not isinstance(document, dict) or set(document) - {"format", "keys"}:
        raise MaterialError("ECH key file has unknown fields")
    keys = document.get("keys")
    if document.get("format") != ECH_KEY_FILE_FORMAT or not isinstance(keys, list) or not 1 <= len(keys) <= 8:
        raise MaterialError("unsupported or empty ECH key file")
    entries = []
    for entry in keys:
        if not isinstance(entry, dict) or set(entry) - {"config", "private_key", "send_as_retry"}:
            raise MaterialError("ECH key entry has unknown fields")
        try:
            config = base64.b64decode(entry.get("config", ""), validate=True)
            if base64.b64encode(config).decode() != entry.get("config"):
                raise ValueError("not canonical")
        except (ValueError, TypeError):
            raise MaterialError("invalid ECH config encoding")
        config_id, name, public_key = parse_ech_config(config)
        try:
            private = base64.b64decode(entry.get("private_key", ""), validate=True)
            if base64.b64encode(private).decode() != entry.get("private_key"):
                raise ValueError("not canonical")
        except (ValueError, TypeError):
            raise MaterialError("invalid ECH private key")
        if len(private) != 32:
            raise MaterialError("invalid ECH private key")
        derived = x25519.X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if derived != public_key:
            raise MaterialError("ECH private key does not match config public key")
        entries.append({"config": config, "config_id": config_id, "public_name": name,
                        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                        "send_as_retry": bool(entry.get("send_as_retry", False))})
    return entries


# ---------------------------------------------------------------------------
# X.509
# ---------------------------------------------------------------------------
def new_key():
    _, _, _, ec, _, _, _ = _crypto()
    return ec.generate_private_key(ec.SECP256R1())


def key_pem(key):
    _, _, serialization, _, _, _, _ = _crypto()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def cert_pem(cert):
    _, _, serialization, _, _, _, _ = _crypto()
    return cert.public_bytes(serialization.Encoding.PEM)


def _spki(public_key):
    _, _, serialization, _, _, _, _ = _crypto()
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def make_ca(common_name, not_before, not_after, key=None):
    x509, hashes, _, _, _, _, NameOID = _crypto()
    key = key or new_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(not_before).not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    return builder.sign(key, hashes.SHA256()), key


def issue_leaf(issuer_cert, issuer_key, key, common_name, dns_names, not_before, not_after, ip_addresses=(),
               dv_policy=False):
    """A DV-shaped server leaf: subject CN only, SANs, CA:FALSE, serverAuth."""
    x509, hashes, _, _, _, ExtendedKeyUsageOID, NameOID = _crypto()
    from cryptography.x509 import ObjectIdentifier
    sans = [x509.DNSName(name) for name in dns_names] + [x509.IPAddress(ipaddress.ip_address(a)) for a in ip_addresses]
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
               .issuer_name(issuer_cert.subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(not_before).not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                              critical=False))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if dv_policy:
        builder = builder.add_extension(x509.CertificatePolicies(
            [x509.PolicyInformation(ObjectIdentifier(DV_POLICY), None)]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _fingerprint(cert):
    _, hashes, _, _, _, _, _ = _crypto()
    return cert.fingerprint(hashes.SHA256()).hex()


# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------
def _forbidden_roots():
    home = Path.home()
    return [p.resolve() for p in (home / ".xprize", home / ".ssh")] + [home / ".xprize", home / ".ssh"]


def refuse_forbidden_path(path):
    """Never write into ~/.xprize or ~/.ssh, by any spelling of the path."""
    candidate = Path(os.path.abspath(os.path.expanduser(str(path))))
    probe = candidate
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    resolved = probe.resolve() / candidate.relative_to(probe)
    for root in _forbidden_roots():
        for form in (candidate, resolved):
            if form == root or root in form.parents:
                raise MaterialError("refusing an output path under %s" % root)
    return candidate


def _write(path, data, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(descriptor, view):]
    finally:
        os.close(descriptor)


# ---------------------------------------------------------------------------
# Generate
# ---------------------------------------------------------------------------
def generate(out, cover_host, winn_host=None, hub_host=None, days=90, now=None, config_id=0):
    """Write a complete material set into `out` (created 0700; must not exist or be empty). Returns the manifest."""
    out = refuse_forbidden_path(out)
    cover_host = (cover_host or "").strip().lower()
    if not valid_dns_name(cover_host) or not plausible_public_name(cover_host):
        raise MaterialError("cover host %r must be a DNS name with a public-shaped TLD (the gateway refuses "
                            "reserved TLDs such as .test, .invalid, .example and .local)" % cover_host)
    if winn_host is None:
        winn_host = "gw-%s.winn.invalid" % secrets.token_hex(4)
    winn_host = winn_host.strip().lower()
    if not valid_dns_name(winn_host):
        raise MaterialError("winn host %r is not a DNS name" % winn_host)
    if names_related(cover_host, winn_host):
        raise MaterialError("winn host %r is the cover host or a parent or child of it; the gateway refuses "
                            "that because the Winn name is the private ECH-inner SNI" % winn_host)
    if hub_host is not None:
        hub_host = hub_host.strip().lower()
        if not (valid_dns_name(hub_host) or _is_ip(hub_host)):
            raise MaterialError("hub host %r is neither a DNS name nor an IP address" % hub_host)
    if not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        raise MaterialError("--days must be 1 to %d (the gateway refuses a cover leaf valid over 398 days)"
                            % MAX_DAYS)
    if out.exists():
        if not out.is_dir() or out.is_symlink() or any(out.iterdir()):
            raise MaterialError("output %s exists and is not an empty directory; refusing to overwrite" % out)
        os.chmod(out, 0o700)
    else:
        out.mkdir(mode=0o700, parents=False)
        os.chmod(out, 0o700)

    now = now or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    not_before = now - BACKDATE
    not_after = not_before + datetime.timedelta(days=days)
    ca_after = not_after + datetime.timedelta(days=30)
    tag = secrets.token_hex(4)

    test_ca, test_ca_key = make_ca("S7 Test Root R1 %s" % tag, not_before, ca_after)
    winn_ca, winn_ca_key = make_ca("S7 Test Winn CA %s" % tag, not_before, ca_after)

    cover_key = new_key()
    cover_leaf = issue_leaf(test_ca, test_ca_key, cover_key, cover_host, [cover_host], not_before, not_after,
                            dv_policy=True)
    winn_key = new_key()
    winn_leaf = issue_leaf(winn_ca, winn_ca_key, winn_key, winn_host, [winn_host], not_before, not_after)
    config_list, ech_bytes, ech_info = ech_generate(cover_host, config_id)

    files = {
        "cover_cert": (cert_pem(cover_leaf) + cert_pem(test_ca), 0o644),
        "cover_key": (key_pem(cover_key), 0o600),
        "ech_keys": (ech_bytes, 0o600),
        "winn_cert": (cert_pem(winn_leaf), 0o644),
        "winn_key": (key_pem(winn_key), 0o600),
        "test_ca.pem": (cert_pem(test_ca), 0o644),
        "test_ca.key": (key_pem(test_ca_key), 0o600),
        "winn_ca.pem": (cert_pem(winn_ca), 0o644),
        "winn_ca.key": (key_pem(winn_ca_key), 0o600),
        "ech_config_list.bin": (config_list, 0o644),
    }
    if hub_host is not None:
        hub_key = new_key()
        dns, ips = ([], [hub_host]) if _is_ip(hub_host) else ([hub_host], [])
        hub_leaf = issue_leaf(test_ca, test_ca_key, hub_key, hub_host, dns, not_before, not_after, ip_addresses=ips)
        files["hub_cert"] = (cert_pem(hub_leaf) + cert_pem(test_ca), 0o644)
        files["hub_key"] = (key_pem(hub_key), 0o600)
    env_lines = ["# S7 throwaway TEST cover material for a disposable guest. Never production.",
                 "# Source inside a WINS_SECRETS_FILE (root, 0600). Each value is one line of base64."]
    for name in GATEWAY_FILES:
        env_lines.append("%s=%s" % (INJECTION[name], base64.b64encode(files[name][0]).decode()))
    files["cover.env"] = (("\n".join(env_lines) + "\n").encode(), 0o600)

    for name, (data, mode) in files.items():
        _write(out / name, data, mode)

    manifest = {
        "format": MANIFEST_FORMAT,
        "throwaway_test_material": True,
        "generated_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cover_host": cover_host,
        "winn_host": winn_host,
        "private_server_name": winn_host,
        "hub_host": hub_host,
        "days": days,
        "not_before_utc": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after_utc": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ca_fingerprint_sha256": _fingerprint(test_ca),
        "winn_ca_fingerprint_sha256": _fingerprint(winn_ca),
        "cover_issuer": test_ca.subject.rfc4514_string(),
        "winn_issuer": winn_ca.subject.rfc4514_string(),
        "ech": {"config_id": ech_info["config_id"], "public_name": ech_info["public_name"],
                "public_key_sha256": ech_info["public_key_sha256"],
                "config_list_sha256": hashlib.sha256(config_list).hexdigest(),
                "config_list_b64": base64.b64encode(config_list).decode()},
        "injection": {name: INJECTION[name] for name in GATEWAY_FILES},
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "mode": "%04o" % mode}
                  for name, (data, mode) in sorted(files.items())},
    }
    _write(out / "MANIFEST.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), 0o644)
    return manifest


# ---------------------------------------------------------------------------
# Validate (offline, the gateway's rules in Python)
# ---------------------------------------------------------------------------
def _load_certs(data):
    x509 = _crypto()[0]
    try:
        return x509.load_pem_x509_certificates(data)
    except ValueError as error:
        raise MaterialError("no parseable PEM certificate: %s" % error)


def _load_key(data):
    serialization = _crypto()[2]
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    text = data.decode("ascii", "replace")
    if not any(marker in text for marker in ("BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN RSA PRIVATE KEY")):
        raise MaterialError("not a PEM private key tls.LoadX509KeyPair reads")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as error:
        raise MaterialError("private key does not parse: %s" % error)
    if not isinstance(key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey)):
        raise MaterialError("private key type %s is not one Go TLS serves" % type(key).__name__)
    return key


def _dns_names(cert):
    x509 = _crypto()[0]
    try:
        return list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    .get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def _ip_names(cert):
    x509 = _crypto()[0]
    try:
        return list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    .get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        return []


def _is_ca(cert):
    x509 = _crypto()[0]
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return None


def _policies(cert):
    x509 = _crypto()[0]
    try:
        return [p.policy_identifier.dotted_string
                for p in cert.extensions.get_extension_for_class(x509.CertificatePolicies).value]
    except x509.ExtensionNotFound:
        return []


def review_cover_chain(chain, winn_leaf, now):
    """coverlisten.ReviewCoverCertificate in Python. Returns a list of findings (empty = acceptable)."""
    NameOID = _crypto()[6]
    findings = []
    leaf = chain[0]
    for attribute in leaf.subject:
        if attribute.oid != NameOID.COMMON_NAME:
            findings.append("cover leaf subject carries %s; only a Common Name is allowed" % attribute.oid.dotted_string)
    for oid in _policies(leaf):
        if oid in IDENTIFYING_POLICIES:
            findings.append("cover leaf asserts the %s policy" % IDENTIFYING_POLICIES[oid])
    if winn_leaf is not None:
        if leaf.issuer.public_bytes() == winn_leaf.issuer.public_bytes():
            findings.append("cover leaf is issued by the same CA as the Winn leaf")
        for cover_name in _dns_names(leaf):
            for winn_name in _dns_names(winn_leaf):
                if names_related(cover_name, winn_name):
                    findings.append("cover name %r is related to the Winn name %r" % (cover_name, winn_name))
    if leaf.subject.public_bytes() == leaf.issuer.public_bytes():
        findings.append("cover leaf is self-signed")
    if _is_ca(leaf):
        findings.append("cover leaf is a CA certificate")
    if len(chain) < 2:
        findings.append("cover certificate was supplied without its issuing chain")
    else:
        for index in range(len(chain) - 1):
            child, parent = chain[index], chain[index + 1]
            if child.issuer.public_bytes() != parent.subject.public_bytes():
                findings.append("cover chain does not link at position %d" % index)
                break
            if not _is_ca(parent):
                findings.append("cover chain position %d is not a CA" % (index + 1))
                break
    plausible = 0
    for name in _dns_names(leaf):
        if plausible_public_name(name):
            plausible += 1
        else:
            findings.append("cover leaf carries the implausible name %r" % name)
    for address in _ip_names(leaf):
        if address.is_loopback or address.is_unspecified:
            findings.append("cover leaf carries the loopback address %s" % address)
    if plausible == 0:
        findings.append("cover leaf carries no publicly resolvable DNS name")
    findings.extend(_validity_findings("cover leaf", leaf, now, cap=True))
    return findings


def _validity_findings(label, cert, now, cap=False):
    findings = []
    if now > cert.not_valid_after_utc:
        findings.append("%s expired on %s" % (label, cert.not_valid_after_utc.isoformat()))
    elif now < cert.not_valid_before_utc:
        findings.append("%s is not valid until %s" % (label, cert.not_valid_before_utc.isoformat()))
    if cap and cert.not_valid_after_utc - cert.not_valid_before_utc > MAX_PUBLIC_VALIDITY:
        findings.append("%s is valid for more than 398 days" % label)
    return findings


def _check_signature(child, parent):
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    public = parent.public_key()
    try:
        if isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(public, rsa.RSAPublicKey):
            public.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(),
                          child.signature_hash_algorithm)
        else:
            public.verify(child.signature, child.tbs_certificate_bytes)
        return True
    except Exception:  # noqa: BLE001 - any verification failure is a finding
        return False


def validate(directory, cover_host=None, winn_host=None, now=None):
    """Check a material set the way the gateway would, offline. Returns a list of problems (empty = passes).

    Gateway rules (startCover and the loaders it calls), plus three harness rules marked "harness:": the cover
    leaf names the cover host, the ECH public name is the cover host (one coherent origin, as winn-ech-keygen
    requires), and the MANIFEST digests match when a MANIFEST is present."""
    directory = Path(directory)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    problems = []
    manifest = None
    if (directory / "MANIFEST.json").is_file():
        try:
            manifest = json.loads((directory / "MANIFEST.json").read_text())
        except ValueError:
            problems.append("harness: MANIFEST.json does not parse")
    if manifest:
        cover_host = cover_host or manifest.get("cover_host")
        winn_host = winn_host or manifest.get("winn_host")

    data = {}
    for name in GATEWAY_FILES:
        path = directory / name
        if path.is_symlink():
            problems.append("%s: is a symlink" % name)
            continue
        if not path.is_file():
            problems.append("%s: missing" % name)
            continue
        mode = stat.S_IMODE(path.lstat().st_mode)
        if name in ("cover_key", "ech_keys", "winn_key") and mode & 0o077:
            problems.append("%s: mode %04o has group/other bits (securefile.ReadPrivateLimited refuses)" % (name, mode))
        if name in ("cover_cert", "winn_cert") and mode & 0o022:
            problems.append("%s: mode %04o is group/other writable (securefile.ReadPublicIntegrity refuses)"
                            % (name, mode))
        data[name] = path.read_bytes()
        if manifest and name in manifest.get("files", {}):
            if hashlib.sha256(data[name]).hexdigest() != manifest["files"][name]["sha256"]:
                problems.append("harness: %s does not match its MANIFEST sha256" % name)
    if len(data) != len(GATEWAY_FILES):
        return problems

    if os.path.realpath(directory / "cover_cert") == os.path.realpath(directory / "winn_cert") \
            or data["cover_cert"] == data["winn_cert"]:
        problems.append("distinct: cover and Winn leaf certificates are identical")
    if os.path.realpath(directory / "cover_key") == os.path.realpath(directory / "winn_key") \
            or data["cover_key"] == data["winn_key"]:
        problems.append("distinct: cover and Winn leaf keys are identical")

    keys, chains = {}, {}
    for prefix in ("cover", "winn"):
        try:
            keys[prefix] = _load_key(data[prefix + "_key"])
        except MaterialError as error:
            problems.append("%s_key: %s" % (prefix, error))
        try:
            chains[prefix] = _load_certs(data[prefix + "_cert"])
        except MaterialError as error:
            problems.append("%s_cert: %s" % (prefix, error))
        if prefix in keys and prefix in chains:
            if _spki(keys[prefix].public_key()) != _spki(chains[prefix][0].public_key()):
                problems.append("%s_key: does not match the %s_cert leaf (tls.LoadX509KeyPair refuses)"
                                % (prefix, prefix))
    if "cover" in keys and "winn" in keys and \
            _spki(keys["cover"].public_key()) == _spki(keys["winn"].public_key()):
        problems.append("distinct: cover and Winn leaf use the same key pair")

    winn_leaf = chains["winn"][0] if "winn" in chains else None
    if winn_leaf is not None:
        names = _dns_names(winn_leaf)
        if not names:
            problems.append("winn_cert: no DNS SAN, so the gateway derives no private server name and no "
                            "client reaches the Winn profile")
        elif winn_host and names[0] != winn_host:
            problems.append("winn_cert: first DNS SAN %r is not the Winn host %r" % (names[0], winn_host))
        problems.extend("winn_cert: " + f for f in _validity_findings("Winn leaf", winn_leaf, now))
        if _is_ca(winn_leaf):
            problems.append("winn_cert: the Winn leaf is a CA certificate")
    if "cover" in chains:
        chain = chains["cover"]
        problems.extend("cover_cert: " + f for f in review_cover_chain(chain, winn_leaf, now))
        for index in range(len(chain) - 1):
            if chain[index].issuer.public_bytes() == chain[index + 1].subject.public_bytes() \
                    and not _check_signature(chain[index], chain[index + 1]):
                problems.append("cover_cert: chain signature at position %d does not verify" % index)
        if cover_host and cover_host not in _dns_names(chain[0]):
            problems.append("harness: cover_cert leaf does not name the cover host %r in its SAN" % cover_host)

    try:
        entries = parse_ech_key_file(data["ech_keys"])
    except MaterialError as error:
        problems.append("ech_keys: %s" % error)
    else:
        for entry in entries:
            if cover_host and entry["public_name"] != cover_host:
                problems.append("harness: ECH public name %r is not the cover host %r"
                                % (entry["public_name"], cover_host))
            if not plausible_public_name(entry["public_name"]):
                problems.append("ech_keys: public name %r has a reserved TLD (winn-ech-keygen refuses it)"
                                % entry["public_name"])
        if (directory / "ech_config_list.bin").is_file():
            retry = [e["config"] for e in entries if e["send_as_retry"]]
            if (directory / "ech_config_list.bin").read_bytes() != ech_config_list(retry):
                problems.append("harness: ech_config_list.bin is not the retry config list of ech_keys")
    return problems


# ---------------------------------------------------------------------------
# The installer's own winn3gw_cover_material, extracted from the shipped text
# ---------------------------------------------------------------------------
INSTALLER_FUNCTIONS = ("winn3gw_err", "winn3gw_die", "stat_uid_mode", "require_root_private_keyfile",
                       "require_root_regular_file", "winn3gw_cover_material")
# Root-only helpers only. The uid becomes 0 (the harness is not root); the mode stays the real one, so the
# installer's own group/other check still runs. chown is recorded, sync -f is a presence check.
INSTALLER_SHIMS = r'''
err() { printf '[ERR] %s\n' "$*" >&2; }
stat() {
  if [[ "$1" == -c ]]; then
    local out
    out="$(command stat -c '%a' "$3" 2>/dev/null)" || return 1
    printf '0:%s\n' "${out}"
  else
    local out
    out="$(command stat -f '%Lp' "$3" 2>/dev/null)" || return 1
    printf '0:%s\n' "${out}"
  fi
}
chown() { printf 'chown %s\n' "$*" >> "${COVER_TRACE}"; }
sync() { [[ "$1" == -f && -e "$2" ]]; }
'''


def default_bash():
    for candidate in (os.environ.get("WINS_TEST_BASH"), "/Users/owner/.homebrew/Homebrew/bin/bash",
                      shutil.which("bash")):
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    return "bash"


def installer_script(mode, credentials_dir, env_file=None, overrides=None, installer=None):
    """A bash program that runs the installer's winn3gw_cover_material MODE with only root helpers shimmed."""
    sys.path.insert(0, str(HERE))
    import tier_common  # noqa: E402
    installer = installer or tier_common.Installer()
    import shlex
    lines = ["set -u", "COVER_TRACE=%s" % shlex.quote(str(Path(credentials_dir).parent / "cover.trace"))]
    lines.append("WINN3_GATEWAY_CREDENTIALS_DIR=%s" % shlex.quote(str(credentials_dir)))
    for name in GATEWAY_FILES:
        lines.append("unset WINN3_GATEWAY_%s %s" % (name.upper(), INJECTION[name]))
    if env_file is not None:
        lines.append(". %s" % shlex.quote(str(env_file)))
    for key, value in (overrides or {}).items():
        if value is None:
            lines.append("unset %s" % key)
        else:
            lines.append("%s=%s" % (key, shlex.quote(str(value))))
    body = "\n".join(installer.function(name) for name in INSTALLER_FUNCTIONS)
    return "\n".join(lines) + "\n" + INSTALLER_SHIMS + body + "\nwinn3gw_cover_material %s\n" % shlex.quote(mode)


def installer_check(mode, credentials_dir, env_file=None, overrides=None, bash=None, installer=None):
    """Run the extracted function. Returns subprocess.CompletedProcess (rc 0 = the installer accepted)."""
    bash = bash or default_bash()
    script = installer_script(mode, credentials_dir, env_file, overrides, installer)
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
    return subprocess.run([bash, "-c", script], capture_output=True, text=True, timeout=60, env=environment)


# ---------------------------------------------------------------------------
# The gateway's own Go loaders, built offline in a scratch copy of the module
# ---------------------------------------------------------------------------
GO_INTERNAL_TEST = r'''package zzcovermaterial

// Generated by tools/onetouch_tiers/cover_material.py into a SCRATCH copy of the module only.
// It drives the material through the calls cmd/winn3-gateway startCover makes, in order, with the
// pinned dependencies (no quic-go is needed below startCover's listener wiring).

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/coverlisten"
	"winsvpn.local/winnprotocol/internal/decoy"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func TestZZCoverMaterialThroughGatewayLoaders(t *testing.T) {
	dir := os.Getenv("COVER_MATERIAL_DIR")
	if dir == "" {
		t.Skip("COVER_MATERIAL_DIR is unset")
	}
	coverHost := os.Getenv("COVER_MATERIAL_COVER_HOST")
	winnHost := os.Getenv("COVER_MATERIAL_WINN_HOST")
	p := func(name string) string { return filepath.Join(dir, name) }
	stage := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("STAGE %s: %v", name, err)
		}
		t.Logf("ok %s", name)
	}
	fail := func(name, format string, args ...any) {
		t.Helper()
		t.Fatalf("STAGE "+name+": "+format, args...)
	}

	echKeys, err := echconfig.LoadServerKeys(p("ech_keys"))
	stage("echconfig.LoadServerKeys", err)
	file, err := echconfig.LoadKeyFile(p("ech_keys"))
	stage("echconfig.LoadKeyFile", err)
	raw, err := os.ReadFile(p("ech_keys"))
	stage("read ech_keys", err)
	encoded, err := echconfig.EncodeKeyFile(file)
	stage("echconfig.EncodeKeyFile", err)
	if !bytes.Equal(encoded, raw) {
		fail("ech byte format", "file bytes differ from echconfig.EncodeKeyFile (winn-ech-keygen) output")
	}
	info, err := echconfig.Describe(file)
	stage("echconfig.Describe", err)
	if len(info) != 1 || info[0].PublicName != coverHost || !info[0].SendAsRetry {
		fail("ech describe", "entries=%d public_name=%q send_as_retry=%v, want 1 %q true",
			len(info), info[0].PublicName, info[0].SendAsRetry, coverHost)
	}
	_, generated, err := echconfig.Generate(coverHost, info[0].ConfigID)
	stage("echconfig.Generate reference", err)
	reference, _ := base64.StdEncoding.DecodeString(generated.Keys[0].Config)
	ours, _ := base64.StdEncoding.DecodeString(file.Keys[0].Config)
	if len(reference) != len(ours) || len(ours) < 41 {
		fail("ech config bytes", "length %d, echconfig.Generate gives %d", len(ours), len(reference))
	}
	copy(reference[9:41], ours[9:41])
	if !bytes.Equal(reference, ours) {
		fail("ech config bytes", "config differs from echconfig.marshalConfig output outside the public key")
	}
	list, err := echconfig.RetryConfigList(file)
	stage("echconfig.RetryConfigList", err)
	stage("echconfig.ValidateConfigList", echconfig.ValidateConfigList(list))
	if published, err := os.ReadFile(p("ech_config_list.bin")); err == nil && !bytes.Equal(published, list) {
		fail("ech config list", "ech_config_list.bin differs from the retry config list")
	}

	suite, err := tlsconfig.ParseSuite(protocol.DefaultSuite)
	stage("tlsconfig.ParseSuite", err)
	winnH2, err := tlsconfig.ServerAnonymousForALPN(p("winn_cert"), p("winn_key"), suite, "h2")
	stage("strict H2 TLS (tlsconfig.ServerAnonymousForALPN)", err)
	winnH3, err := tlsconfig.ServerAnonymousForALPN(p("winn_cert"), p("winn_key"), suite, "h3")
	stage("strict H3 TLS (tlsconfig.ServerAnonymousForALPN)", err)
	stage("strict H2 ECH (echconfig.ConfigureServer)", echconfig.ConfigureServer(winnH2, echKeys, true))
	stage("strict H3 ECH (echconfig.ConfigureServer)", echconfig.ConfigureServer(winnH3, echKeys, true))
	logf := func(format string, args ...any) { t.Logf("gateway: "+format, args...) }
	base := coverlisten.Options{CoverCertPath: p("cover_cert"), CoverKeyPath: p("cover_key"), ECHKeys: echKeys, Logf: logf}
	h2Options := base
	h2Options.Winn = winnH2
	h2Options.CoverALPN = []string{"h2", "http/1.1"}
	h2, err := coverlisten.Apply(h2Options)
	stage("cover H2 (coverlisten.Apply)", err)
	h3Options := base
	h3Options.Winn = winnH3
	h3Options.CoverALPN = []string{"h3"}
	h3, err := coverlisten.Apply(h3Options)
	stage("cover H3 (coverlisten.Apply)", err)
	_, err = decoy.NewOrigin(decoy.Config{CoverTLS: h2.TLS, PrivateServerName: h2.PrivateServerName, Logf: logf})
	stage("decoy origin (decoy.NewOrigin)", err)
	stage("H2 probe resistance (coverlisten.Verify)", coverlisten.Verify(h2.TLS))
	stage("H3 probe resistance (coverlisten.Verify)", coverlisten.Verify(h3.TLS))
	if h2.PrivateServerName != winnHost || h3.PrivateServerName != winnHost {
		fail("private server name", "derived %q/%q, want %q", h2.PrivateServerName, h3.PrivateServerName, winnHost)
	}
	if winnLeaf, _ := coverlisten.ServesWinnLeaf(h2.TLS, winnH2); winnLeaf {
		fail("cover leaf", "the cover profile serves the Winn leaf")
	}

	pool := func(name string) *x509.CertPool {
		data, err := os.ReadFile(p(name))
		stage("read "+name, err)
		certs := x509.NewCertPool()
		if !certs.AppendCertsFromPEM(data) {
			fail("pool", "%s holds no certificate", name)
		}
		return certs
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	stage("loopback listen", err)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				server := tls.Server(conn, h2.TLS)
				_ = server.SetDeadline(time.Now().Add(5 * time.Second))
				_ = server.Handshake()
				_ = server.Close()
			}()
		}
	}()
	dial := func(config *tls.Config) (tls.ConnectionState, error) {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), config)
		if err != nil {
			return tls.ConnectionState{}, err
		}
		defer conn.Close()
		return conn.ConnectionState(), nil
	}
	prober, err := dial(&tls.Config{RootCAs: pool("test_ca.pem"), ServerName: coverHost, NextProtos: []string{"h2"}})
	stage("prober verifies the cover chain for the cover host against test_ca.pem", err)
	if prober.ECHAccepted || !slices.Contains(prober.PeerCertificates[0].DNSNames, coverHost) {
		fail("prober", "ECH accepted=%v names=%v", prober.ECHAccepted, prober.PeerCertificates[0].DNSNames)
	}
	client, err := dial(&tls.Config{RootCAs: pool("winn_ca.pem"), ServerName: winnHost, NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{suite.Curve}, EncryptedClientHelloConfigList: list})
	stage("an ECH client reaches the strict Winn profile and verifies the Winn leaf against winn_ca.pem", err)
	if !client.ECHAccepted || client.PeerCertificates[0].DNSNames[0] != winnHost || client.CurveID != suite.Curve {
		fail("ech client", "ECH accepted=%v leaf=%v curve=%v", client.ECHAccepted,
			client.PeerCertificates[0].DNSNames, client.CurveID)
	}
	t.Logf("PASS cover material accepted by the gateway loaders")
}
'''

GO_GATEWAY_TEST = r'''package main

// Generated by tools/onetouch_tiers/cover_material.py into a SCRATCH copy of cmd/winn3-gateway only.
// runServe is the gateway's production entry point; the baseline options come from the package's own
// operatorValueOptions, with every cover input replaced by the generated material.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestZZGeneratedCoverMaterialStartsTheGateway(t *testing.T) {
	dir := os.Getenv("COVER_MATERIAL_DIR")
	if dir == "" {
		t.Skip("COVER_MATERIAL_DIR is unset")
	}
	coverHost := os.Getenv("COVER_MATERIAL_COVER_HOST")
	p := func(name string) string { return filepath.Join(dir, name) }
	opts := operatorValueOptions(t)
	opts.certPath = p("winn_cert")
	opts.keyPath = p("winn_key")
	opts.echKeysPath = p("ech_keys")
	opts.coverCertPath = p("cover_cert")
	opts.coverKeyPath = p("cover_key")
	if os.Getenv("COVER_MATERIAL_EXPECT") == "refuse" {
		opts.runFor = 3 * time.Second
		err := runServe(opts, new(bytes.Buffer))
		if err == nil {
			t.Fatal("STAGE gateway: runServe served material that was expected to be refused")
		}
		t.Logf("REFUSED: %v", err)
		return
	}
	opts.runFor = 4 * time.Second
	buf := &safeBuffer{}
	done := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		done <- runServe(opts, buf)
	}()
	t.Cleanup(wg.Wait)
	listen := waitListening(t, buf, done, 5*time.Second)

	data, err := os.ReadFile(p("test_ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(data)
	var state tls.ConnectionState
	var lastErr error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		conn, err := tls.Dial("tcp", listen, &tls.Config{RootCAs: roots, ServerName: coverHost, NextProtos: []string{"http/1.1"}})
		if err != nil {
			lastErr = err
			continue
		}
		state = conn.ConnectionState()
		_ = conn.Close()
		lastErr = nil
		break
	}
	if lastErr != nil {
		t.Fatalf("STAGE cover HTTPS: %v", lastErr)
	}
	if !slices.Contains(state.PeerCertificates[0].DNSNames, coverHost) {
		t.Fatalf("STAGE cover HTTPS: leaf names %v, want %s", state.PeerCertificates[0].DNSNames, coverHost)
	}
	t.Logf("cover HTTPS on %s verified for %s, issuer %q", listen, coverHost, state.PeerCertificates[0].Issuer.CommonName)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, listen, &tls.Config{RootCAs: roots, ServerName: coverHost, NextProtos: []string{"h3"}},
		&quic.Config{HandshakeIdleTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("STAGE cover QUIC: %v", err)
	}
	_ = qc.CloseWithError(0, "")
	t.Logf("PASS gateway started and served the generated cover certificate over TCP and QUIC")
}
'''


def module_go_version(module_dir=MODULE_DIR):
    for line in (Path(module_dir) / "go.mod").read_text().splitlines():
        if line.startswith("go "):
            return line.split()[1]
    raise MaterialError("go.mod has no go directive")


def _go_version_of(binary):
    try:
        done = subprocess.run([binary, "env", "GOVERSION"], capture_output=True, text=True, timeout=30,
                              env=dict(os.environ, GOTOOLCHAIN="local"))
    except OSError:
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def _version_tuple(text):
    parts = []
    for piece in text.replace("go", "", 1).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits or 0))
    return tuple(parts)


def find_go(module_dir=MODULE_DIR):
    """A local Go toolchain at least as new as go.mod asks for, used with GOTOOLCHAIN=local (no download)."""
    wanted = module_go_version(module_dir)
    candidates = [os.environ.get("WINS_GO"), shutil.which("go"), str(Path.home() / ".local/go/bin/go")]
    for seed in [c for c in candidates if c]:
        modcache = subprocess.run([seed, "env", "GOMODCACHE"], capture_output=True, text=True, timeout=30,
                                  env=dict(os.environ, GOTOOLCHAIN="local")).stdout.strip() if os.access(seed, os.X_OK) else ""
        if modcache:
            import platform
            goarch = {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
            cached = Path(modcache) / "golang.org" / ("toolchain@v0.0.1-go%s.%s-%s" % (wanted, sys.platform, goarch)) / "bin" / "go"
            candidates.append(str(cached))
    for candidate in [c for c in candidates if c]:
        if os.access(candidate, os.X_OK):
            version = _go_version_of(candidate)
            if version and _version_tuple(version) >= _version_tuple("go" + wanted):
                return candidate
    raise MaterialError("no local Go toolchain >= go%s (set WINS_GO); nothing is downloaded" % wanted)


def offline_go_env(scratch):
    environment = dict(os.environ)
    environment.update({"GOPROXY": "off", "GOFLAGS": "-mod=mod -buildvcs=false", "GONOSUMDB": "*",
                        "GOTOOLCHAIN": "local", "GOWORK": "off", "CGO_ENABLED": "0",
                        "TMPDIR": str(scratch)})
    return environment


class GoCheck:
    """Clone the module copy-on-write into `scratch`, add one generated _test.go there, build offline."""

    def __init__(self, scratch, module_dir=MODULE_DIR, gateway=False):
        self.scratch = refuse_forbidden_path(scratch)
        self.module_dir = Path(module_dir)
        self.gateway = gateway
        self.binary = self.scratch / ("gateway.test" if gateway else "loaders.test")
        self.go = find_go(self.module_dir)
        self.notes = []

    def build(self):
        self.scratch.mkdir(parents=True, exist_ok=True)
        copy = self.scratch / "module"
        if not copy.exists():
            flags = ["-cR"] if sys.platform == "darwin" else ["-R", "--reflink=auto"]
            subprocess.run(["cp"] + flags + [str(self.module_dir), str(copy)], check=True, timeout=300)
        environment = offline_go_env(self.scratch)
        if self.gateway:
            package = "./cmd/winn3-gateway"
            target = copy / "cmd" / "winn3-gateway" / "zz_cover_material_test.go"
            target.write_text(GO_GATEWAY_TEST)
            quic = self._substitute_quic(copy, environment)
            if quic:
                self.notes.append(quic)
        else:
            package = "./internal/zzcovermaterial"
            (copy / "internal" / "zzcovermaterial").mkdir(exist_ok=True)
            (copy / "internal" / "zzcovermaterial" / "check_test.go").write_text(GO_INTERNAL_TEST)
        done = subprocess.run([self.go, "test", "-c", "-o", str(self.binary), package], cwd=copy,
                              capture_output=True, text=True, timeout=1200, env=environment)
        if done.returncode != 0:
            raise MaterialError("offline Go build failed (rc %d): %s" % (done.returncode, done.stderr.strip()[-2000:]))
        return self.binary

    def _substitute_quic(self, copy, environment):
        """cover.go imports quic-go. When the pinned version is absent from the module cache the gateway cannot
        build offline; if an older quic-go IS cached, use it in the scratch copy only and say so."""
        modcache = subprocess.run([self.go, "env", "GOMODCACHE"], capture_output=True, text=True,
                                  env=environment, timeout=30).stdout.strip()
        pinned = None
        for line in (copy / "go.mod").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("github.com/quic-go/quic-go", "require") and "quic-go/quic-go" in line:
                pinned = parts[-1]
        root = Path(modcache) / "github.com" / "quic-go"
        if pinned and (root / ("quic-go@" + pinned)).is_dir():
            return None
        available = sorted((p.name.split("@", 1)[1] for p in root.glob("quic-go@v*") if p.is_dir()),
                           key=_version_tuple)
        if not available:
            raise MaterialError("quic-go %s is not in the module cache and no other version is; the gateway "
                                "package cannot build offline" % pinned)
        chosen = available[-1]
        subprocess.run([self.go, "mod", "edit", "-replace",
                        "github.com/quic-go/quic-go=github.com/quic-go/quic-go@" + chosen],
                       cwd=copy, check=True, env=environment, timeout=60)
        return ("quic-go %s (pinned) is not in the module cache; the scratch copy uses cached quic-go %s "
                "instead. The cover material path does not depend on quic-go; the QUIC listener does." % (pinned, chosen))

    def run(self, material_dir, cover_host, winn_host, expect="start"):
        environment = dict(os.environ, COVER_MATERIAL_DIR=str(material_dir), COVER_MATERIAL_COVER_HOST=cover_host,
                           COVER_MATERIAL_WINN_HOST=winn_host, COVER_MATERIAL_EXPECT=expect,
                           TMPDIR=str(self.scratch))
        name = "TestZZGeneratedCoverMaterialStartsTheGateway" if self.gateway else "TestZZCoverMaterialThroughGatewayLoaders"
        return subprocess.run([str(self.binary), "-test.run", "^%s$" % name, "-test.v", "-test.count=1"],
                              capture_output=True, text=True, timeout=300, env=environment,
                              cwd=str(self.scratch))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cmd_generate(args):
    manifest = generate(args.out, args.cover_host, args.winn_host, args.hub_host, args.days, config_id=args.config_id)
    print("wrote %s (0700)" % Path(args.out))
    for name, entry in sorted(manifest["files"].items()):
        print("  %-20s %s sha256=%s" % (name, entry["mode"], entry["sha256"]))
    print("cover host %s; Winn leaf (private server name) %s; hub %s" % (
        manifest["cover_host"], manifest["winn_host"], manifest["hub_host"] or "none"))
    print("test CA sha256 %s; Winn CA sha256 %s" % (manifest["ca_fingerprint_sha256"],
                                                   manifest["winn_ca_fingerprint_sha256"]))
    print("ECH config_id %d public_name %s" % (manifest["ech"]["config_id"], manifest["ech"]["public_name"]))
    problems = validate(args.out)
    for problem in problems:
        print("PROBLEM " + problem)
    return 1 if problems else 0


def _cmd_validate(args):
    problems = validate(args.dir, args.cover_host, args.winn_host)
    for problem in problems:
        print("PROBLEM " + problem)
    print("validate: %s" % ("FAIL" if problems else "PASS"))
    return 1 if problems else 0


def _cmd_installer_check(args):
    directory = Path(args.dir)
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as area:
        credentials = Path(area) / "credentials"
        credentials.mkdir(mode=0o700)
        done = installer_check(args.mode, credentials, directory / "cover.env", bash=args.bash)
        print(done.stderr.strip())
        if done.returncode == 0 and args.mode == "install":
            for name in GATEWAY_FILES:
                same = (credentials / name).read_bytes() == (directory / name).read_bytes()
                print("  installed %s %s" % (name, "matches" if same else "DIFFERS"))
                if not same:
                    return 1
        print("installer winn3gw_cover_material %s: rc %d" % (args.mode, done.returncode))
        return done.returncode


def _cmd_go_check(args):
    manifest = json.loads((Path(args.dir) / "MANIFEST.json").read_text())
    check = GoCheck(args.scratch, gateway=args.gateway)
    check.build()
    for note in check.notes:
        print("NOTE " + note)
    done = check.run(args.dir, manifest["cover_host"], manifest["winn_host"], args.expect)
    print(done.stdout.strip())
    print("go-check (%s): rc %d" % ("gateway runServe" if args.gateway else "gateway loaders", done.returncode))
    return done.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate", help="write a throwaway material set")
    g.add_argument("--out", required=True)
    g.add_argument("--cover-host", required=True)
    g.add_argument("--winn-host")
    g.add_argument("--hub-host")
    g.add_argument("--days", type=int, default=90)
    g.add_argument("--config-id", type=int, default=0)
    g.set_defaults(func=_cmd_generate)
    v = sub.add_parser("validate", help="check a material set the way the gateway would")
    v.add_argument("--dir", required=True)
    v.add_argument("--cover-host")
    v.add_argument("--winn-host")
    v.set_defaults(func=_cmd_validate)
    i = sub.add_parser("installer-check", help="run the installer's own winn3gw_cover_material on cover.env")
    i.add_argument("--dir", required=True)
    i.add_argument("--mode", choices=("preflight", "install"), default="preflight")
    i.add_argument("--bash")
    i.set_defaults(func=_cmd_installer_check)
    c = sub.add_parser("go-check", help="build the gateway's loaders offline in a scratch copy and run them")
    c.add_argument("--dir", required=True)
    c.add_argument("--scratch", required=True)
    c.add_argument("--gateway", action="store_true", help="also start the real runServe (cmd/winn3-gateway)")
    c.add_argument("--expect", choices=("start", "refuse"), default="start")
    c.set_defaults(func=_cmd_go_check)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except MaterialError as error:
        print("cover_material: %s" % error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
