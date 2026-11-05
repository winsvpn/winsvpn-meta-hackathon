# Apple Export Options

These plists are release-lane templates for signed `xcodebuild -exportArchive`
runs after the matching `.xcarchive` has been created.

- `ios-app-store-connect.plist`: iOS App Store Connect upload for TestFlight or App Store review.
- `ios-testflight-internal.plist`: iOS App Store Connect upload limited to internal TestFlight.
- `ios-app-store-local.plist`: local iOS App Store-style export without uploading to Apple.
- `ios-debugging-local.plist`: local iOS debugging export for development-device QA with development provisioning profiles.
- `ios-release-testing.plist`: local iOS release-testing export for signed device QA.
- `macos-debugging-local.plist`: local macOS debugging export for development-machine QA with development provisioning profiles.
- `macos-app-store-connect.plist`: macOS App Store Connect upload for TestFlight or App Store review.
- `macos-app-store-local.plist`: local macOS App Store-style export without uploading to Apple.
- `macos-developer-id.plist`: local Developer ID export, permitted only through
  `macos_developer_id_export.py`. The archive and exported app must contain a
  signed packet-tunnel system extension with the system-extension entitlement
  and must contain no packet-tunnel app extension. This lane remains blocked
  until its system-extension target, activation path and device gates pass.

Do not add provisioning profile UUIDs, certificate hashes, API keys, or passwords to
these files. Xcode should resolve signing through the Apple team configured in the
project and the local Xcode account/keychain.

## App Store Connect Upload Lanes

Use the local App Store export lanes first so the IPA/package payload is verified
without uploading. After the matching App Store-local lanes pass and the App Store
Connect app records, privacy answers, screenshots, support URL, and review metadata
are ready, the archive-based internal TestFlight lane remains available:

```bash
set -o pipefail
WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE=1 WINS_REQUIRE_APPLE_ENGINE=1 \
  WINS_APPLE_AUTHENTICATION_KEY_PATH=/private/path/AuthKey_XXXXXXXXXX.p8 \
  WINS_APPLE_AUTHENTICATION_KEY_ID=XXXXXXXXXX \
  WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID=00000000-0000-0000-0000-000000000000 \
  bash tools/apple_runtime_smoke.sh 2>&1 | tee /tmp/wins-ios-testflight-upload.log
```

For approved release candidates, use
`python3 tools/apple_upload_exact_release_candidates.py` with its explicit
Apple ID and SHA-256 confirmations. That lane uploads the already validated IPA
and PKG byte-for-byte; the archive export flags can produce different package
hashes and therefore are not the final owner-approved upload path.

The `.p8` key must stay outside the project folder and must be readable only by
the current user (`chmod 600`). The smoke harness rejects missing, partial,
project-local, or group/world-readable API-key configuration before building or
uploading.

## iOS Release-Testing Profile Unblock

The `ios-release-testing.plist` lane needs device-scoped distribution profiles
that are separate from App Store profiles. App Store profiles and all-devices
profiles do not satisfy this lane because the local QA IPA must be installable
on the attached iPhone before TestFlight/App Store submission. If the smoke
output reports `exportArchive No Accounts` or missing release-testing profiles,
sign in again to Apple Developer/Xcode and create or download both of these
profiles:

- Type: iOS App release-testing / Ad Hoc distribution profile
- Bundle ID: `org.winsvpn.app`
- Bundle ID: `org.winsvpn.app.PacketTunnel`
- Certificate: Apple Distribution for Win's VPN Inc
- Device coverage: include the physical iPhone used for QA
- Capabilities: Packet Tunnel, `group.org.winsvpn.app`, and
  `5YT8H4U72M.org.winsvpn.shared`

After downloading the `.mobileprovision` files, verify them before rerunning the
export lane. The helper intentionally rejects profiles without explicit device
coverage:

```bash
python3 tools/apple_profile_manager.py --source ~/Downloads
```

If the helper reports `iOS release-testing profile readiness: ok`, install the
matching profiles locally:

```bash
python3 tools/apple_profile_manager.py --source ~/Downloads --install
```

If you are downloading the two profiles from Apple Developer in the browser,
you can also leave the helper waiting in another terminal. It rescans Downloads,
installs usable profiles as they appear, and exits as soon as both bundle IDs are
ready:

```bash
python3 tools/apple_profile_manager.py --source ~/Downloads --install --watch-seconds 600
```

Then refresh Xcode accounts and rerun the release-testing export smoke:

```bash
set -o pipefail
WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE=1 WINS_REQUIRE_APPLE_ENGINE=1 \
  bash tools/apple_runtime_smoke.sh 2>&1 | tee /tmp/wins-ios-release-testing.log
```

## macOS Universal-Purchase Profiles

The iOS and macOS targets share `org.winsvpn.app` for universal purchase, but
their provisioning profiles remain platform-specific. Download these four
profiles from Apple Developer:

- macOS App Development for `org.winsvpn.app`
- macOS App Development for `org.winsvpn.app.PacketTunnel`
- Mac App Store Connect for `org.winsvpn.app`
- Mac App Store Connect for `org.winsvpn.app.PacketTunnel`

Validate and install all four alongside the existing iOS release-testing
profiles:

```bash
python3 tools/apple_profile_manager.py --source ~/Downloads --install --require-macos
```

The manager rejects the retired `org.winsvpn.macos` profiles, Developer ID
profiles in place of Mac App Store profiles, missing device coverage for
development builds, wrong certificate classes, and profiles missing Packet
Tunnel, the shared app group, or the shared keychain group.

If the profiles are valid but command-line Xcode reports `No Accounts`, create
a private target-aware development signing xcconfig outside the repository:

```bash
python3 tools/apple_profile_manager.py \
  --write-macos-development-xcconfig /private/tmp/wins-macos-development.xcconfig
```

The helper selects one validated macOS development profile for `Runner` and one
for `PacketTunnel`, writes the file with mode `600`, rejects project-local or
symbolic-link destinations, and does not write profile names into source. Pass
that external file to signed Mac smoke lanes only through the environment:

```bash
WINS_MACOS_DEVELOPMENT_XCCONFIG=/private/tmp/wins-macos-development.xcconfig \
  WINS_SIGNED_MACOS_BUILD=1 WINS_MACOS_ARCHIVE_SMOKE=1 \
  WINS_REQUIRE_APPLE_ENGINE=1 bash tools/apple_runtime_smoke.sh
```

This development xcconfig can create the signed Mac archive used by local
debugging and Mac App Store export lanes. App Store Connect upload still needs
the separate external `.p8` API-key configuration described above.

If App Store Connect API-key authentication is used instead of the interactive
Xcode account, keep the private key outside the project folder with owner-only
permissions and pass it only through `WINS_APPLE_AUTHENTICATION_KEY_PATH`,
`WINS_APPLE_AUTHENTICATION_KEY_ID`, and
`WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID`.

When saving smoke output with `tee`, preserve the real exit status:

```bash
set -o pipefail
WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE=1 WINS_REQUIRE_APPLE_ENGINE=1 \
  bash tools/apple_runtime_smoke.sh 2>&1 | tee /tmp/wins-ios-release-testing.log
```
