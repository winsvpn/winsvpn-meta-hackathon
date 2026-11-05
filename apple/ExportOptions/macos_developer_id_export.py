import plistlib
import subprocess
import sys
from pathlib import Path


NE_KEY = "com.apple.developer.networking.networkextension"
SYSTEM_CAPABILITY = "packet-tunnel-provider-systemextension"
APP_CAPABILITY = "packet-tunnel-provider"


def info(bundle):
    with (bundle / "Contents" / "Info.plist").open("rb") as stream:
        return plistlib.load(stream)


def entitlements(bundle):
    subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(bundle)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    result = subprocess.run(
        ["/usr/bin/codesign", "--display", "--xml", "--entitlements", "-", str(bundle)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if not result.stdout:
        return {}
    return plistlib.loads(result.stdout)


def validate(app, host_id, provider_id, team):
    host_info = info(app)
    host_entitlements = entitlements(app)
    if host_info.get("CFBundleIdentifier") != host_id:
        raise ValueError("Unexpected host identity")
    if host_entitlements.get("com.apple.developer.team-identifier") != team:
        raise ValueError("Unexpected host team")
    if host_entitlements.get("com.apple.developer.system-extension.install") is not True:
        raise ValueError("Missing system-extension installation entitlement")

    providers = []
    extension_directory = app / "Contents" / "Library" / "SystemExtensions"
    for extension in extension_directory.glob("*.systemextension"):
        extension_info = info(extension)
        if extension_info.get("CFBundleIdentifier") != provider_id:
            continue
        extension_entitlements = entitlements(extension)
        if extension_entitlements.get("com.apple.developer.team-identifier") != team:
            raise ValueError("Unexpected provider team")
        if SYSTEM_CAPABILITY not in extension_entitlements.get(NE_KEY, []):
            raise ValueError("Missing packet-tunnel system-extension entitlement")
        classes = extension_info.get("NetworkExtension", {}).get("NEProviderClasses", {})
        provider_class = classes.get("com.apple.networkextension.packet-tunnel")
        if not isinstance(provider_class, str) or not provider_class.endswith(".PacketTunnelProvider"):
            raise ValueError("Missing packet-tunnel provider class")
        providers.append(extension)

    if len(providers) != 1:
        raise ValueError("Exactly one matching system-extension provider is required")

    for extension in app.rglob("*.appex"):
        extension_info = info(extension)
        point = extension_info.get("NSExtension", {}).get("NSExtensionPointIdentifier")
        extension_entitlements = entitlements(extension)
        if point == "com.apple.networkextension.packet-tunnel":
            raise ValueError("Packet-tunnel app extension is forbidden in this lane")
        if APP_CAPABILITY in extension_entitlements.get(NE_KEY, []):
            raise ValueError("App-extension packet-tunnel entitlement is forbidden")


def main():
    if len(sys.argv) != 6:
        raise ValueError("Expected archive, export directory, host ID, provider ID and team")
    archive = Path(sys.argv[1]).resolve(strict=True)
    export = Path(sys.argv[2]).absolute()
    host_id, provider_id, team = sys.argv[3:]
    if not host_id or not provider_id or not team:
        raise ValueError("Release identities are required")
    if export.exists():
        raise ValueError("Export directory must not already exist")

    applications = list((archive / "Products" / "Applications").glob("*.app"))
    if len(applications) != 1:
        raise ValueError("Archive must contain exactly one host app")
    validate(applications[0], host_id, provider_id, team)

    subprocess.run(
        [
            "/usr/bin/xcodebuild",
            "-exportArchive",
            "-archivePath", str(archive),
            "-exportPath", str(export),
            "-exportOptionsPlist",
            str(Path(__file__).with_name("macos-developer-id.plist")),
        ],
        check=True,
        timeout=900,
    )

    applications = list(export.glob("*.app"))
    if len(applications) != 1:
        raise ValueError("Exported app is unavailable for validation")
    validate(applications[0], host_id, provider_id, team)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Developer ID export refused; lane validation did not pass.", file=sys.stderr)
        sys.exit(1)
