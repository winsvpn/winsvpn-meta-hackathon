"""S7 owner item 8: the cover, Winn leaf and ECH test material (tools/onetouch_tiers/cover_material.py).

Four independent judges of one generated set:
  * the installer's own winn3gw_cover_material, extracted from the shipped text and run under bash 5 with only
    the root-only helpers shimmed (preflight and the install path);
  * openssl and direct parsing in this file, for the properties the generator could get wrong silently;
  * the module's own validate(), the gateway's rules in Python, including the wrong readings it must refuse;
  * the gateway's own Go code, built offline in a scratch copy of the module: the loaders startCover calls with
    the pinned dependencies, and the real runServe (with a cached quic-go when the pinned one is not cached).

Everything runs on the operator Mac and touches no guest, host or network. Set WINS_COVER_SKIP_GO=1 to skip the
Go builds. WINS_COVER_MATERIAL_MODULE points the suite at another copy of the module (the mutant runs use it).
"""
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TIERS = ROOT / "tools" / "onetouch_tiers"
sys.path.insert(0, str(TIERS))
sys.path.insert(0, str(ROOT / "tools"))
MODULE_PATH = Path(os.environ.get("WINS_COVER_MATERIAL_MODULE") or TIERS / "cover_material.py")
_spec = importlib.util.spec_from_file_location("cover_material_under_test", MODULE_PATH)
cm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cm)
from tier_common import Installer  # noqa: E402

INSTALLER = Installer(ROOT / "server/wins_data_plane_setup_ONETOUCH.sh")
BASH = os.environ.get("WINS_TEST_BASH") or cm.default_bash()
OPENSSL = os.environ.get("WINS_OPENSSL") or next(
    (c for c in ("$HOME/.homebrew/Homebrew/bin/openssl", shutil.which("openssl")) if c and os.access(c, os.X_OK)),
    None)
SKIP_GO = os.environ.get("WINS_COVER_SKIP_GO") == "1"
COVER_HOST = "cdn.s7-cover.net"
WINN_HOST = "gw-s7.winn.invalid"
HUB_HOST = "hub.s7.test"
GOOD = None
_AREA = None


def setUpModule():
    global GOOD, _AREA
    _AREA = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
    GOOD = Path(_AREA.name) / "good"
    cm.generate(GOOD, COVER_HOST, WINN_HOST, HUB_HOST, days=90)


def tearDownModule():
    _AREA.cleanup()


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def openssl(*args, data=None):
    return subprocess.run([OPENSSL] + list(args), input=data, capture_output=True, timeout=60)


def pem_blocks(data):
    return re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n", data, re.S)


class Variant:
    """A writable copy of the good set without its MANIFEST, so one edit is the only difference."""

    def __init__(self, test):
        area = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        test.addCleanup(shutil.rmtree, area)
        self.dir = Path(area) / "set"
        shutil.copytree(GOOD, self.dir)
        (self.dir / "MANIFEST.json").unlink()
        self.manifest = json.loads((GOOD / "MANIFEST.json").read_text())

    def path(self, name):
        return self.dir / name

    def load(self, name):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        data = self.path(name).read_bytes()
        if name.endswith(".key"):
            return serialization.load_pem_private_key(data, None)
        return x509.load_pem_x509_certificate(data)

    def put(self, name, data):
        mode = stat.S_IMODE(self.path(name).stat().st_mode)
        self.path(name).write_bytes(data)
        os.chmod(self.path(name), mode)

    def cover(self, dns=(COVER_HOST,), not_before=None, not_after=None, issuer="test_ca", chain=True, key=None,
              cn=COVER_HOST):
        """Re-issue the cover leaf (keeping cover_key unless `key` is given)."""
        from cryptography.hazmat.primitives import serialization
        ca, ca_key = self.load(issuer + ".pem"), self.load(issuer + ".key")
        leaf_key = key or serialization.load_pem_private_key(self.path("cover_key").read_bytes(), None)
        start = not_before or now() - datetime.timedelta(hours=1)
        leaf = cm.issue_leaf(ca, ca_key, leaf_key, cn, list(dns), start,
                             not_after or start + datetime.timedelta(days=90))
        self.put("cover_cert", cm.cert_pem(leaf) + (cm.cert_pem(ca) if chain else b""))
        return leaf

    def ech(self, mutate):
        document = json.loads(self.path("ech_keys").read_bytes())
        mutate(document)
        self.put("ech_keys", (json.dumps(document, indent=2) + "\n").encode())

    def validate(self):
        return cm.validate(self.dir, COVER_HOST, WINN_HOST)


def ech_entry(directory):
    document = json.loads((Path(directory) / "ech_keys").read_bytes())
    entry = document["keys"][0]
    return document, base64.b64decode(entry["config"]), base64.b64decode(entry["private_key"])


# ---------------------------------------------------------------------------
class GenerateTests(unittest.TestCase):
    def test_layout_modes_and_manifest(self):
        self.assertEqual(stat.S_IMODE(GOOD.stat().st_mode), 0o700)
        manifest = json.loads((GOOD / "MANIFEST.json").read_text())
        for name in cm.GATEWAY_FILES + ("test_ca.pem", "winn_ca.pem", "hub_cert", "hub_key", "cover.env"):
            path = GOOD / name
            self.assertTrue(path.is_file() and not path.is_symlink(), name)
            want = 0o600 if name in cm.PRIVATE_FILES else 0o644
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), want, name)
            self.assertEqual(manifest["files"][name]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest(), name)
        self.assertEqual(manifest["cover_host"], COVER_HOST)
        self.assertEqual(manifest["private_server_name"], WINN_HOST)
        text = (GOOD / "MANIFEST.json").read_text()
        _, _, private = ech_entry(GOOD)
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn(base64.b64encode(private).decode(), text)
        for name in ("cover_key", "winn_key", "ech_keys", "test_ca.key", "winn_ca.key", "hub_key"):
            self.assertNotIn(base64.b64encode((GOOD / name).read_bytes()).decode()[:40], text)

    @unittest.skipUnless(OPENSSL, "openssl is not installed")
    def test_manifest_ca_fingerprint_is_the_test_ca(self):
        done = openssl("x509", "-in", str(GOOD / "test_ca.pem"), "-noout", "-fingerprint", "-sha256")
        self.assertEqual(done.returncode, 0, done.stderr)
        fingerprint = done.stdout.decode().strip().split("=", 1)[1].replace(":", "").lower()
        self.assertEqual(json.loads((GOOD / "MANIFEST.json").read_text())["ca_fingerprint_sha256"], fingerprint)

    def test_cover_env_carries_exactly_the_five_injections(self):
        values = {}
        for line in (GOOD / "cover.env").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            name, _, value = line.partition("=")
            self.assertRegex(value, r"^[A-Za-z0-9+/]+=*$", name)
            values[name] = value
        self.assertEqual(set(values), {"WINN3_COVER_CERT_B64", "WINN3_COVER_KEY_B64", "WINN3_COVER_ECH_KEYS_B64",
                                       "WINN3_COVER_WINN_CERT_B64", "WINN3_COVER_WINN_KEY_B64"})
        # The installer derives the injection name from the file name: WINN3_COVER_${name#COVER_}_B64.
        for name in cm.GATEWAY_FILES:
            injection = "WINN3_COVER_%s_B64" % re.sub(r"^COVER_", "", name.upper())
            self.assertEqual(base64.b64decode(values[injection], validate=True), (GOOD / name).read_bytes(), name)

    def test_generated_set_passes_validate(self):
        self.assertEqual(cm.validate(GOOD), [])
        self.assertEqual(cm.validate(GOOD, COVER_HOST, WINN_HOST), [])

    def test_cli_generates_validates_and_never_prints_key_material(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as area:
            out = Path(area) / "cli"
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            done = subprocess.run([sys.executable, "-B", str(MODULE_PATH), "generate", "--out", str(out),
                                   "--cover-host", COVER_HOST, "--hub-host", "192.0.2.10", "--days", "30"],
                                  capture_output=True, text=True, timeout=120, env=env)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            printed = done.stdout + done.stderr
            self.assertNotIn("PRIVATE KEY", printed)
            _, _, private = ech_entry(out)
            self.assertNotIn(base64.b64encode(private).decode(), printed)
            for name in ("cover_key", "winn_key", "test_ca.key", "winn_ca.key", "hub_key", "cover.env"):
                body = (out / name).read_text()
                for line in body.splitlines():
                    if len(line) >= 24 and not line.startswith(("-----", "#")):
                        self.assertNotIn(line.split("=", 1)[-1][:24], printed, name)
            done = subprocess.run([sys.executable, "-B", str(MODULE_PATH), "validate", "--dir", str(out)],
                                  capture_output=True, text=True, timeout=120, env=env)
            self.assertEqual(done.returncode, 0, done.stdout)
            self.assertIn("validate: PASS", done.stdout)
            manifest = json.loads((out / "MANIFEST.json").read_text())
            self.assertRegex(manifest["winn_host"], r"^gw-[0-9a-f]{8}\.winn\.invalid$")

    def test_refusals(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as area:
            for host in ("cdn.s7.test", "cdn.s7.invalid", "www.example", "cdn.local", "cdnonly", "192.0.2.1", "",
                         "bad_name.net"):
                with self.subTest(cover_host=host):
                    with self.assertRaises(cm.MaterialError):
                        cm.generate(Path(area) / "c", host)
                    self.assertFalse((Path(area) / "c").exists())
            for winn in (COVER_HOST, "s7-cover.net", "x.cdn.s7-cover.net"):
                with self.subTest(winn_host=winn):
                    with self.assertRaises(cm.MaterialError):
                        cm.generate(Path(area) / "w", COVER_HOST, winn)
            for days in (0, 398, 1000):
                with self.subTest(days=days):
                    with self.assertRaises(cm.MaterialError):
                        cm.generate(Path(area) / "d", COVER_HOST, days=days)
            cm.generate(Path(area) / "edge", COVER_HOST, days=cm.MAX_DAYS)
            self.assertEqual(cm.validate(Path(area) / "edge"), [])
            occupied = Path(area) / "occupied"
            occupied.mkdir()
            (occupied / "keep").write_text("x")
            with self.assertRaises(cm.MaterialError):
                cm.generate(occupied, COVER_HOST)
            self.assertEqual(sorted(p.name for p in occupied.iterdir()), ["keep"])
        for forbidden in (Path.home() / ".ssh" / "s7-cover-refusal", Path.home() / ".xprize" / "s7-cover-refusal",
                          "~/.ssh/s7-cover-refusal", Path.home() / ".ssh"):
            with self.subTest(out=str(forbidden)):
                with self.assertRaises(cm.MaterialError):
                    cm.generate(forbidden, COVER_HOST)
                self.assertFalse(Path(os.path.expanduser(str(forbidden))).joinpath("cover_cert").exists())
                if str(forbidden).endswith("s7-cover-refusal"):
                    self.assertFalse(Path(os.path.expanduser(str(forbidden))).exists())


# ---------------------------------------------------------------------------
@unittest.skipUnless(OPENSSL, "openssl is not installed")
class IndependentChecks(unittest.TestCase):
    """Properties checked without the module's own code: openssl, and direct byte or X.509 parsing here."""

    def split(self, name):
        blocks = pem_blocks((GOOD / name).read_bytes())
        area = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, area)
        paths = []
        for index, block in enumerate(blocks):
            paths.append(Path(area) / ("%d.pem" % index))
            paths[-1].write_bytes(block)
        return paths

    def test_cover_cert_carries_its_issuing_chain(self):
        blocks = pem_blocks((GOOD / "cover_cert").read_bytes())
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[1], (GOOD / "test_ca.pem").read_bytes())

    def test_cover_chain_verifies_for_the_cover_host_against_the_test_ca_only(self):
        leaf = self.split("cover_cert")[0]
        good = openssl("verify", "-CAfile", str(GOOD / "test_ca.pem"), "-purpose", "sslserver",
                       "-verify_hostname", COVER_HOST, str(leaf))
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        for wrong_ca, host in (("winn_ca.pem", COVER_HOST), ("test_ca.pem", "other.s7-cover.net")):
            bad = openssl("verify", "-CAfile", str(GOOD / wrong_ca), "-verify_hostname", host, str(leaf))
            self.assertNotEqual(bad.returncode, 0, (wrong_ca, host))

    def test_winn_leaf_verifies_against_the_winn_ca_for_the_winn_host_only(self):
        good = openssl("verify", "-CAfile", str(GOOD / "winn_ca.pem"), "-purpose", "sslserver",
                       "-verify_hostname", WINN_HOST, str(GOOD / "winn_cert"))
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        bad = openssl("verify", "-CAfile", str(GOOD / "test_ca.pem"), str(GOOD / "winn_cert"))
        self.assertNotEqual(bad.returncode, 0)

    def test_hub_cert_verifies_for_the_hub_host_against_the_test_ca(self):
        leaf = self.split("hub_cert")[0]
        done = openssl("verify", "-CAfile", str(GOOD / "test_ca.pem"), "-purpose", "sslserver",
                       "-verify_hostname", HUB_HOST, str(leaf))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_cover_and_winn_keys_are_distinct_and_each_matches_its_leaf(self):
        public = {}
        for prefix in ("cover", "winn"):
            key = openssl("pkey", "-in", str(GOOD / (prefix + "_key")), "-pubout")
            cert = openssl("x509", "-in", str(GOOD / (prefix + "_cert")), "-noout", "-pubkey")
            self.assertEqual(key.returncode, 0, key.stderr)
            self.assertEqual(key.stdout, cert.stdout, prefix)
            public[prefix] = key.stdout
        self.assertNotEqual(public["cover"], public["winn"])
        self.assertNotEqual((GOOD / "cover_cert").read_bytes(), (GOOD / "winn_cert").read_bytes())

    def test_cover_leaf_is_dv_shaped(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        leaf = x509.load_pem_x509_certificate((GOOD / "cover_cert").read_bytes())
        winn = x509.load_pem_x509_certificate((GOOD / "winn_cert").read_bytes())
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(sans.get_values_for_type(x509.DNSName), [COVER_HOST])
        self.assertEqual([a.oid for a in leaf.subject], [NameOID.COMMON_NAME])
        self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertNotEqual(leaf.issuer, leaf.subject)
        self.assertNotEqual(leaf.issuer, winn.issuer)
        self.assertLessEqual(leaf.not_valid_after_utc - leaf.not_valid_before_utc, datetime.timedelta(days=398))
        self.assertTrue(leaf.not_valid_before_utc <= now() <= leaf.not_valid_after_utc)

    def test_ech_config_bytes_match_the_gateway_layout(self):
        document, config, private = ech_entry(GOOD)
        self.assertEqual(list(document), ["format", "keys"])
        self.assertEqual(document["format"], "winn-ech-key-set/v1")
        self.assertEqual(list(document["keys"][0]), ["config", "private_key", "send_as_retry"])
        self.assertIs(document["keys"][0]["send_as_retry"], True)
        name = COVER_HOST.encode()
        self.assertEqual(config[0:2], b"\xfe\x0d")
        self.assertEqual(int.from_bytes(config[2:4], "big"), len(config) - 4)
        self.assertEqual(config[5:7], b"\x00\x20")
        self.assertEqual(config[7:9], b"\x00\x20")
        public = config[9:41]
        self.assertEqual(config[41:51], b"\x00\x08\x00\x01\x00\x01\x00\x01\x00\x03")
        self.assertEqual(config[51:53 + len(name)], bytes([253, len(name)]) + name)
        self.assertEqual(config[53 + len(name):], b"\x00\x00")
        self.assertEqual(len(private), 32)
        # openssl derives the X25519 public key from the raw private key (PKCS#8 wrapper for OID 1.3.101.110).
        der = bytes.fromhex("302e020100300506032b656e04220420") + private
        derived = openssl("pkey", "-inform", "DER", "-pubout", "-outform", "DER", data=der)
        self.assertEqual(derived.returncode, 0, derived.stderr)
        self.assertEqual(derived.stdout[-32:], public)
        listed = (GOOD / "ech_config_list.bin").read_bytes()
        self.assertEqual(listed, len(config).to_bytes(2, "big") + config)
        self.assertEqual((GOOD / "ech_keys").read_bytes(),
                         (json.dumps(document, indent=2) + "\n").encode(), "Go json.MarshalIndent layout")


# ---------------------------------------------------------------------------
class ValidateRejects(unittest.TestCase):
    """Wrong readings the gateway (or the harness) refuses must fail validate()."""

    def assertProblem(self, variant, pattern):
        problems = variant.validate()
        self.assertTrue(any(re.search(pattern, p) for p in problems), "%r not in %r" % (pattern, problems))

    def test_the_unchanged_variant_passes(self):
        self.assertEqual(Variant(self).validate(), [])

    def test_cover_key_that_does_not_match_the_cover_cert(self):
        v = Variant(self)
        v.put("cover_key", cm.key_pem(cm.new_key()))
        self.assertProblem(v, r"^cover_key: does not match")

    def test_cover_cert_without_the_cover_host(self):
        v = Variant(self)
        v.cover(dns=("other.s7-cover.net",), cn="other.s7-cover.net")
        self.assertProblem(v, r"does not name the cover host")
        v.cover(dns=())
        self.assertProblem(v, r"no publicly resolvable DNS name")

    def test_cover_cert_with_a_reserved_tld(self):
        v = Variant(self)
        v.cover(dns=(COVER_HOST, "cdn.s7.test"))
        self.assertProblem(v, r"implausible name 'cdn\.s7\.test'")

    def test_expired_not_yet_valid_and_overlong_cover_certs(self):
        v = Variant(self)
        v.cover(not_before=now() - datetime.timedelta(days=40), not_after=now() - datetime.timedelta(days=10))
        self.assertProblem(v, r"cover leaf expired on")
        v.cover(not_before=now() + datetime.timedelta(days=2))
        self.assertProblem(v, r"not valid until")
        v.cover(not_before=now() - datetime.timedelta(days=1), not_after=now() + datetime.timedelta(days=400))
        self.assertProblem(v, r"more than 398 days")

    def test_leaf_without_chain_and_self_signed_cover(self):
        v = Variant(self)
        v.cover(chain=False)
        self.assertProblem(v, r"without its issuing chain")
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(v.path("cover_key").read_bytes(), None)
        start = now() - datetime.timedelta(hours=1)
        ca, _ = cm.make_ca(COVER_HOST, start, start + datetime.timedelta(days=30), key=key)
        v.put("cover_cert", cm.cert_pem(ca))
        self.assertProblem(v, r"self-signed")
        self.assertProblem(v, r"is a CA certificate")

    def test_cover_issued_by_the_winn_ca(self):
        v = Variant(self)
        v.cover(issuer="winn_ca")
        self.assertProblem(v, r"same CA as the Winn leaf")

    def test_cover_subject_with_an_organization(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        v = Variant(self)
        leaf = v.load("cover_cert")
        ca_key = v.load("test_ca.key")
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, COVER_HOST),
                                            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Operator Ltd")]))
                   .issuer_name(leaf.issuer).public_key(leaf.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(leaf.not_valid_before_utc).not_valid_after(leaf.not_valid_after_utc)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(COVER_HOST)]), critical=False))
        v.put("cover_cert", cm.cert_pem(builder.sign(ca_key, hashes.SHA256())) + v.path("test_ca.pem").read_bytes())
        self.assertProblem(v, r"only a Common Name is allowed")

    def test_truncated_ech_material(self):
        v = Variant(self)
        v.ech(lambda d: d["keys"][0].update(config=base64.b64encode(base64.b64decode(d["keys"][0]["config"])[:-3])
                                            .decode()))
        self.assertProblem(v, r"^ech_keys: invalid RFC 9849 ECH config framing")
        v = Variant(self)
        data = v.path("ech_keys").read_bytes()
        v.put("ech_keys", data[:len(data) // 2])
        self.assertProblem(v, r"^ech_keys: ECH key file is not JSON")
        v = Variant(self)
        v.ech(lambda d: d["keys"][0].update(private_key=base64.b64encode(b"\x01" * 31).decode()))
        self.assertProblem(v, r"^ech_keys: invalid ECH private key")

    def test_wrong_version_and_wrong_shape_ech(self):
        def version(d):
            config = bytearray(base64.b64decode(d["keys"][0]["config"]))
            config[1] = 0x0C
            d["keys"][0]["config"] = base64.b64encode(bytes(config)).decode()
        v = Variant(self)
        v.ech(version)
        self.assertProblem(v, r"^ech_keys: invalid RFC 9849 ECH config framing")
        cases = [
            (lambda d: d.update(format="winn-ech-key-set/v2"), r"unsupported or empty ECH key file"),
            (lambda d: d.update(keys=[]), r"unsupported or empty ECH key file"),
            (lambda d: d.update(extra=1), r"unknown fields"),
            (lambda d: d["keys"][0].update(extra=1), r"unknown fields"),
        ]
        for mutate, pattern in cases:
            with self.subTest(pattern=pattern):
                v = Variant(self)
                v.ech(mutate)
                self.assertProblem(v, pattern)
        v = Variant(self)
        v.put("ech_keys", v.path("ech_keys").read_bytes() + b"{}\n")
        self.assertProblem(v, r"extra JSON")

    def test_ech_private_key_that_does_not_match_its_config(self):
        _, other, _ = cm.ech_generate(COVER_HOST, 7)
        v = Variant(self)
        other_private = json.loads(other)["keys"][0]["private_key"]
        v.ech(lambda d: d["keys"][0].update(private_key=other_private))
        self.assertProblem(v, r"does not match config public key")

    def test_ech_public_name_that_is_not_the_cover_host(self):
        _, other, _ = cm.ech_generate("static.other-origin.net", 7)
        v = Variant(self)
        v.put("ech_keys", other)
        self.assertProblem(v, r"ECH public name 'static\.other-origin\.net' is not the cover host")

    def test_cover_and_winn_leaf_identical(self):
        v = Variant(self)
        v.put("cover_cert", v.path("winn_cert").read_bytes())
        v.put("cover_key", v.path("winn_key").read_bytes())
        self.assertProblem(v, r"^distinct: cover and Winn leaf certificates are identical")
        self.assertProblem(v, r"^distinct: cover and Winn leaf keys are identical")
        self.assertProblem(v, r"same CA as the Winn leaf")
        v = Variant(self)
        from cryptography.hazmat.primitives import serialization
        winn_key = serialization.load_pem_private_key(v.path("winn_key").read_bytes(), None)
        v.cover(key=winn_key)
        v.put("cover_key", v.path("winn_key").read_bytes())
        self.assertProblem(v, r"same key pair")

    def test_file_level_refusals(self):
        v = Variant(self)
        os.chmod(v.path("cover_key"), 0o644)
        self.assertProblem(v, r"^cover_key: mode 0644 has group/other bits")
        v = Variant(self)
        os.chmod(v.path("winn_cert"), 0o666)
        self.assertProblem(v, r"^winn_cert: mode 0666 is group/other writable")
        v = Variant(self)
        os.rename(v.path("cover_cert"), v.dir / "elsewhere.pem")
        os.symlink(v.dir / "elsewhere.pem", v.path("cover_cert"))
        self.assertProblem(v, r"^cover_cert: is a symlink")
        v = Variant(self)
        v.path("ech_keys").unlink()
        self.assertProblem(v, r"^ech_keys: missing")

    def test_manifest_digest_mismatch(self):
        area = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, area)
        copy = Path(area) / "set"
        shutil.copytree(GOOD, copy)
        data = (copy / "cover_cert").read_bytes()
        (copy / "cover_cert").write_bytes(data + b"\n")
        self.assertIn("harness: cover_cert does not match its MANIFEST sha256", cm.validate(copy))


# ---------------------------------------------------------------------------
def bash_major():
    try:
        done = subprocess.run([BASH, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True, timeout=30)
        return int(done.stdout.strip())
    except (OSError, ValueError):
        return 0


@unittest.skipUnless(bash_major() >= 4, "bash 4+ is required for ${name,,}; set WINS_TEST_BASH")
class InstallerCoverMaterialTests(unittest.TestCase):
    """The shipped installer's winn3gw_cover_material, extracted from its text, with root-only helpers shimmed."""

    def setUp(self):
        area = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, area)
        self.area = Path(area)
        self.credentials = self.area / "credentials"
        self.credentials.mkdir(mode=0o700)
        self.env = GOOD / "cover.env"

    def run_cover(self, mode="preflight", env_file="default", overrides=None):
        env_file = self.env if env_file == "default" else env_file
        return cm.installer_check(mode, self.credentials, env_file, overrides, bash=BASH, installer=INSTALLER)

    def env_without(self, injection):
        lines = [line for line in self.env.read_text().splitlines() if not line.startswith(injection + "=")]
        path = self.area / ("without-" + injection)
        path.write_text("\n".join(lines) + "\n")
        return path

    def test_the_extracted_text_is_the_shipped_function(self):
        body = INSTALLER.function("winn3gw_cover_material")
        self.assertIn(body, INSTALLER.text)
        self.assertIn('injection="WINN3_COVER_${name#COVER_}_B64"', body)
        self.assertIn('path="${!variable:-${WINN3_GATEWAY_CREDENTIALS_DIR}/${name,,}}"', body)
        script = cm.installer_script("preflight", self.credentials, self.env, installer=INSTALLER)
        for name in cm.INSTALLER_FUNCTIONS:
            self.assertIn(INSTALLER.function(name), script)

    def test_generated_cover_env_passes_the_installer_preflight(self):
        done = self.run_cover()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(list(self.credentials.iterdir()), [], "preflight writes nothing")

    def test_no_material_at_all_is_refused(self):
        done = self.run_cover(env_file=None)
        self.assertEqual(done.returncode, 1)
        self.assertIn("Missing cover material: WINN3_GATEWAY_COVER_CERT or WINN3_COVER_CERT_B64", done.stderr)

    def test_each_missing_item_is_refused_by_name(self):
        for name in cm.GATEWAY_FILES:
            injection = cm.INJECTION[name]
            with self.subTest(item=name):
                done = self.run_cover(env_file=self.env_without(injection))
                self.assertEqual(done.returncode, 1, done.stderr)
                self.assertIn("Missing cover material: WINN3_GATEWAY_%s or %s" % (name.upper(), injection),
                              done.stderr)

    def test_invalid_or_empty_base64_is_refused(self):
        for value in ("not base64!", "", "===="):
            with self.subTest(value=value):
                done = self.run_cover(overrides={"WINN3_COVER_CERT_B64": value})
                self.assertEqual(done.returncode, 1, done.stderr)
                self.assertTrue("Invalid WINN3_COVER_CERT_B64" in done.stderr
                                or "Missing cover material: WINN3_GATEWAY_COVER_CERT" in done.stderr, done.stderr)

    def test_cover_and_winn_leaf_on_the_same_path_are_refused(self):
        same = str(self.credentials / "cover_cert")
        done = self.run_cover(overrides={"WINN3_GATEWAY_WINN_CERT": same})
        self.assertEqual(done.returncode, 1)
        self.assertIn("Cover and Winn leaf material must be distinct", done.stderr)
        same = str(self.credentials / "cover_key")
        done = self.run_cover(overrides={"WINN3_GATEWAY_WINN_KEY": same})
        self.assertEqual(done.returncode, 1)
        self.assertIn("Cover and Winn leaf material must be distinct", done.stderr)

    def test_install_path_writes_the_exact_material_and_it_still_validates(self):
        done = self.run_cover("install")
        self.assertEqual(done.returncode, 0, done.stderr)
        for name in cm.GATEWAY_FILES:
            written = self.credentials / name
            self.assertEqual(written.read_bytes(), (GOOD / name).read_bytes(), name)
            self.assertEqual(stat.S_IMODE(written.stat().st_mode), 0o600, name)
        self.assertEqual(sorted(p.name for p in self.credentials.iterdir()), sorted(cm.GATEWAY_FILES),
                         "no temporary file is left behind")
        trace = (self.area / "cover.trace").read_text().splitlines()
        self.assertEqual(len([t for t in trace if t.startswith("chown root:root ")]), 5, trace)
        self.assertEqual(cm.validate(self.credentials, COVER_HOST, WINN_HOST), [])
        # A second run finds the files in place and takes the installer's existing-file branch.
        again = self.run_cover("preflight", env_file=None)
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_pre_placed_material_goes_through_the_real_ownership_and_mode_gates(self):
        for name in cm.GATEWAY_FILES:
            shutil.copy2(GOOD / name, self.credentials / name)
        done = self.run_cover(env_file=None)
        self.assertEqual(done.returncode, 0, done.stderr)
        os.chmod(self.credentials / "winn_key", 0o644)
        done = self.run_cover(env_file=None)
        self.assertEqual(done.returncode, 1)
        self.assertIn("has mode 644", done.stderr)
        os.chmod(self.credentials / "winn_key", 0o600)
        os.rename(self.credentials / "cover_cert", self.area / "real_cover_cert")
        os.symlink(self.area / "real_cover_cert", self.credentials / "cover_cert")
        done = self.run_cover(env_file=None)
        self.assertEqual(done.returncode, 1)
        self.assertIn("is a symlink", done.stderr)


# ---------------------------------------------------------------------------
GO_REASON = None
if SKIP_GO:
    GO_REASON = "WINS_COVER_SKIP_GO=1"
else:
    try:
        cm.find_go()
    except (cm.MaterialError, OSError, subprocess.SubprocessError) as error:
        GO_REASON = "no offline Go toolchain: %s" % error


class _GoBase(unittest.TestCase):
    gateway = False

    @classmethod
    def setUpClass(cls):
        cls._scratch = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        try:
            cls.check = cm.GoCheck(Path(cls._scratch) / "go", gateway=cls.gateway)
            cls.check.build()
        except cm.MaterialError as error:
            shutil.rmtree(cls._scratch, ignore_errors=True)
            if "module cache" in str(error) or "lookup disabled" in str(error):
                raise unittest.SkipTest("cannot build offline from the local module cache: %s" % error)
            raise

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._scratch, ignore_errors=True)

    def go(self, directory, expect="start"):
        return self.check.run(directory, COVER_HOST, WINN_HOST, expect)


@unittest.skipIf(GO_REASON, GO_REASON or "")
class GoLoaderTests(_GoBase):
    """startCover's material calls (echconfig, tlsconfig, coverlisten, decoy) with the pinned dependencies."""

    def assertRefused(self, variant, stage, detail):
        self.assertNotEqual(variant.validate(), [], "validate() must agree with the gateway")
        done = self.go(variant.dir)
        self.assertNotEqual(done.returncode, 0, done.stdout)
        self.assertIn("STAGE " + stage, done.stdout)
        self.assertIn(detail, done.stdout)

    def test_generated_material_passes_the_gateway_loaders_and_live_handshakes(self):
        done = self.go(GOOD)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("PASS cover material accepted by the gateway loaders", done.stdout)
        self.assertIn("ok an ECH client reaches the strict Winn profile", done.stdout)
        self.assertIn("ok echconfig.EncodeKeyFile", done.stdout)

    def test_cover_issued_by_the_winn_ca_is_refused(self):
        v = Variant(self)
        v.cover(issuer="winn_ca")
        self.assertRefused(v, "cover H2 (coverlisten.Apply)", "cover certificate identifies the operator")

    def test_expired_or_reserved_tld_cover_is_refused(self):
        v = Variant(self)
        v.cover(not_before=now() - datetime.timedelta(days=40), not_after=now() - datetime.timedelta(days=10))
        self.assertRefused(v, "cover H2 (coverlisten.Apply)", "could not be a real public origin")
        v = Variant(self)
        v.cover(dns=("cdn.s7.test",), cn="cdn.s7.test")
        self.assertRefused(v, "cover H2 (coverlisten.Apply)", "could not be a real public origin")

    def test_mismatched_cover_key_is_refused(self):
        v = Variant(self)
        v.put("cover_key", cm.key_pem(cm.new_key()))
        self.assertRefused(v, "cover H2 (coverlisten.Apply)", "private key does not match public key")

    def test_bad_ech_material_is_refused_by_the_gateway_parser(self):
        _, other, _ = cm.ech_generate(COVER_HOST, 7)
        v = Variant(self)
        other_private = json.loads(other)["keys"][0]["private_key"]
        v.ech(lambda d: d["keys"][0].update(private_key=other_private))
        self.assertRefused(v, "echconfig.LoadServerKeys", "ECH private key does not match config public key")

        def version(d):
            config = bytearray(base64.b64decode(d["keys"][0]["config"]))
            config[1] = 0x0C
            d["keys"][0]["config"] = base64.b64encode(bytes(config)).decode()
        v = Variant(self)
        v.ech(version)
        self.assertRefused(v, "echconfig.LoadServerKeys", "invalid RFC 9849 ECH config framing")
        v = Variant(self)
        os.chmod(v.path("ech_keys"), 0o640)
        self.assertRefused(v, "echconfig.LoadServerKeys", "want no group/other access")


@unittest.skipIf(GO_REASON, GO_REASON or "")
class GatewayStartTests(_GoBase):
    """The real runServe of cmd/winn3-gateway. If the pinned quic-go is not in the module cache, the scratch copy
    uses the newest cached quic-go (GoCheck.notes says so); the cover material path does not depend on it."""
    gateway = True

    def test_generated_material_starts_the_gateway_and_is_served_to_probers(self):
        done = self.go(GOOD)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("PASS gateway started and served the generated cover certificate over TCP and QUIC",
                      done.stdout)
        self.assertIn("verified for %s" % COVER_HOST, done.stdout)

    def test_the_gateway_refuses_an_expired_cover_and_mismatched_ech_at_startup(self):
        v = Variant(self)
        v.cover(not_before=now() - datetime.timedelta(days=40), not_after=now() - datetime.timedelta(days=10))
        done = self.go(v.dir, expect="refuse")
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertIn("REFUSED: cover H2: cover certificate could not be a real public origin", done.stdout)
        _, other, _ = cm.ech_generate(COVER_HOST, 7)
        v = Variant(self)
        other_private = json.loads(other)["keys"][0]["private_key"]
        v.ech(lambda d: d["keys"][0].update(private_key=other_private))
        done = self.go(v.dir, expect="refuse")
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertIn("REFUSED: -ech-keys: ECH private key does not match config public key", done.stdout)
        # Control: the refusal mode does not pass good material.
        done = self.go(GOOD, expect="refuse")
        self.assertNotEqual(done.returncode, 0, done.stdout)


# ---------------------------------------------------------------------------
THIS = Path(__file__).resolve()
MUTANTS = [
    # (id, old text, new text, exact count, the test that must kill it)
    ("winn-leaf-reuses-cover-key", "    winn_key = new_key()\n", "    winn_key = cover_key\n", 1,
     "IndependentChecks::test_cover_and_winn_keys_are_distinct_and_each_matches_its_leaf"),
    ("ech-version-byte", "ECH_VERSION = 0xFE0D", "ECH_VERSION = 0xFE0C", 1,
     "IndependentChecks::test_ech_config_bytes_match_the_gateway_layout"),
    ("cover-san-omits-host", "cover_host, [cover_host], not_before", "cover_host, [], not_before", 1,
     "IndependentChecks::test_cover_leaf_is_dv_shaped"),
    ("cover-issued-by-winn-ca", "cover_leaf = issue_leaf(test_ca, test_ca_key,",
     "cover_leaf = issue_leaf(winn_ca, winn_ca_key,", 1,
     "IndependentChecks::test_cover_chain_verifies_for_the_cover_host_against_the_test_ca_only"),
    ("cover-chain-omitted", '"cover_cert": (cert_pem(cover_leaf) + cert_pem(test_ca), 0o644),',
     '"cover_cert": (cert_pem(cover_leaf), 0o644),', 1,
     "IndependentChecks::test_cover_cert_carries_its_issuing_chain"),
    ("env-misnames-ech-injection", '"ech_keys": "WINN3_COVER_ECH_KEYS_B64",', '"ech_keys": "WINN3_COVER_ECH_KEY_B64",', 1,
     "InstallerCoverMaterialTests::test_generated_cover_env_passes_the_installer_preflight"),
    ("validity-cap-lifted", "MAX_DAYS = 397", "MAX_DAYS = 3970", 1, "GenerateTests::test_refusals"),
    ("validate-accepts-a-bare-leaf", "if len(chain) < 2:", "if len(chain) < 1:", 1,
     "ValidateRejects::test_leaf_without_chain_and_self_signed_cover"),
]


@unittest.skipIf(os.environ.get("WINS_COVER_MATERIAL_MODULE"), "already running against a mutant copy")
class MutantTests(unittest.TestCase):
    """Each exact-count edit of cover_material.py, applied to a temp copy, is killed by the named test."""

    def run_against(self, source, node):
        area = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, area)
        path = Path(area) / "cover_material.py"
        path.write_text(source)
        env = dict(os.environ, WINS_COVER_MATERIAL_MODULE=str(path), WINS_COVER_SKIP_GO="1",
                   PYTHONDONTWRITEBYTECODE="1", WINS_TEST_BASH=BASH)
        return subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                               "%s::%s" % (THIS, node)], capture_output=True, text=True, timeout=600,
                              env=env, cwd=str(THIS.parent))

    def test_mutants_apply_exactly_and_are_killed(self):
        source = MODULE_PATH.read_text()
        killers = sorted({m[4] for m in MUTANTS})
        for node in killers:
            with self.subTest(control=node):
                done = self.run_against(source, node)
                self.assertEqual(done.returncode, 0, "control must pass unmutated: " + done.stdout[-3000:])
                self.assertNotIn("skipped", done.stdout.splitlines()[-1] if done.stdout else "", done.stdout)
        for ident, old, new, count, node in MUTANTS:
            with self.subTest(mutant=ident):
                self.assertEqual(source.count(old), count, "%s: anchor must occur exactly %d time(s)" % (ident, count))
                mutated = source.replace(old, new)
                self.assertNotEqual(mutated, source)
                done = self.run_against(mutated, node)
                self.assertEqual(done.returncode, 1, "%s survived %s:\n%s" % (ident, node, done.stdout[-3000:]))
                self.assertRegex(done.stdout, r"(?m)^(SUB)?FAILED [^\n]*%s" % re.escape(node))


if __name__ == "__main__":
    unittest.main()
