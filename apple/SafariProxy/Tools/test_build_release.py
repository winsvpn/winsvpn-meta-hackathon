"""Offline checks for the Developer ID release builder and the identities it relies on."""
import importlib.util
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent
APPLE = TOOLS.parent
SPEC = importlib.util.spec_from_file_location("safari_release_builder", TOOLS / "build_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class SignatureEncodingTests(unittest.TestCase):
    def test_der_to_raw_pads_and_strips(self):
        r, s = b"\x00" + b"\x80" + b"\x01" * 31, b"\x05"
        der = bytes([0x30, 4 + len(r) + len(s), 0x02, len(r)]) + r + bytes([0x02, len(s)]) + s
        raw = release.der_to_raw(der)
        self.assertEqual(raw, b"\x80" + b"\x01" * 31 + b"\x00" * 31 + b"\x05")

    def test_der_to_raw_rejects_other_encodings(self):
        with self.assertRaises(release.ReleaseError):
            release.der_to_raw(b"\x31\x06\x02\x01\x01\x02\x01\x01")

    def test_openssl_es256_signature_converts_to_64_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key.pem"
            subprocess.run(["/usr/bin/openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)],
                           check=True, capture_output=True)
            der = subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(key)], input=b"payload",
                                 check=True, capture_output=True).stdout
            self.assertEqual(len(release.der_to_raw(der)), 64)


class ReleaseIdentityTests(unittest.TestCase):
    def test_system_extension_bundle_is_named_after_its_identifier(self):
        project = (APPLE / "SafariProxy.xcodeproj/project.pbxproj").read_text()
        self.assertIn('"path" = "org.winsvpn.safariproxy.network.systemextension"', project)
        self.assertIn('"PRODUCT_NAME" = "$(PRODUCT_BUNDLE_IDENTIFIER)"', project)
        self.assertIn('"PRODUCT_MODULE_NAME" = "SafariProxyNetwork"', project)
        base = re.search(r"^SAFARI_PROXY_BASE_ID = (\S+)$", (APPLE / "Config/Common.xcconfig").read_text(), re.M)[1]
        self.assertEqual(set(release.BUNDLES), {base, base + ".web", base + ".network"})

    def test_mach_service_is_inside_the_team_prefixed_app_group(self):
        network = plistlib.loads((APPLE / "Config/Network-Info.plist").read_bytes())
        groups = plistlib.loads((APPLE / "Config/Network.entitlements").read_bytes())[
            "com.apple.security.application-groups"]
        self.assertEqual(groups, ["$(TeamIdentifierPrefix)$(SAFARI_PROXY_BASE_ID)"])
        self.assertTrue(network["NetworkExtension"]["NEMachServiceName"].startswith(groups[0]))
        self.assertEqual(network["SafariProxyAppGroup"], groups[0])

    def test_developer_id_network_extension_values(self):
        for name in ("MacApp", "MacWeb", "Network"):
            values = plistlib.loads((APPLE / "Config" / (name + ".entitlements")).read_bytes())[
                "com.apple.developer.networking.networkextension"]
            self.assertTrue(set(values) <= release.NE_VALUES, name)


if __name__ == "__main__":
    unittest.main()
