"""Native Safari contracts. No browser launch, Keychain access or network is used."""
from pathlib import Path
import plistlib
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
APPLE = ROOT / "apple/SafariProxy"


def test_native_authentication_and_packet_boundary(tmp_path):
    swift = shutil.which("swiftc")
    if not swift:
        pytest.skip("Swift compiler is unavailable")
    output = tmp_path / "safari-control-tests"
    command = [swift, "-module-cache-path", str(tmp_path / "modules"), "-o", str(output),
               str(APPLE / "Shared/ControlProtocol.swift"),
               str(APPLE / "Shared/WinnPacketABI.swift"),
               str(APPLE / "Tests/ControlProtocolTests.swift")]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    result = subprocess.run([str(output)], check=True, capture_output=True, text=True, timeout=10)
    assert "PASS: authenticated control" in result.stdout


def test_standalone_component_identities_and_entitlements():
    def read(name):
        return plistlib.loads((APPLE / "Config" / name).read_bytes())
    app = read("MacApp-Info.plist")
    web = read("Web-Info.plist")
    network = read("Network-Info.plist")
    assert app["SafariProxySystemExtensionIdentifier"] == "$(SAFARI_PROXY_BASE_ID).network"
    assert web["SafariProxySystemExtensionIdentifier"] == app["SafariProxySystemExtensionIdentifier"]
    assert web["NSExtension"]["NSExtensionPointIdentifier"] == "com.apple.Safari.web-extension"
    assert network["NetworkExtension"]["NEProviderClasses"] == {
        "com.apple.networkextension.app-proxy": "$(PRODUCT_MODULE_NAME).TransparentProxyProvider",
        "com.apple.networkextension.dns-proxy": "$(PRODUCT_MODULE_NAME).DNSProxyProvider",
    }
    groups = [read(name)["keychain-access-groups"] for name in
              ("MacApp.entitlements", "MacWeb.entitlements", "Network.entitlements")]
    assert groups[0] == groups[2]
    assert groups[1] == ["$(AppIdentifierPrefix)$(SAFARI_PROXY_BASE_ID).control"]
    assert groups[0] == groups[1] + ["$(AppIdentifierPrefix)$(SAFARI_PROXY_BASE_ID).session"]
    assert 'com.apple.security.application-groups' not in read('MacWeb.entitlements')
    assert read('Network.entitlements')['com.apple.security.network.server'] is True
    assert read("iOSApp.entitlements") == {}
    assert read("iOSWeb.entitlements") == {}
