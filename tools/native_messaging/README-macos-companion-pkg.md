# macOS native-messaging companion PKG

The Mac App Store app is sandboxed and cannot register an out-of-sandbox
Chrome, Edge, or Firefox native-messaging host. `install_macos_native_host.sh`
is a repository operator helper: it depends on Python and the checkout, and it
is not a consumer installer. The helper reads Chrome and Edge ids from one
authenticated owner-identity snapshot. Missing identity leaves live Chrome and
Edge registrations in place. Stale or invalid identity aborts instead of
treating that failure as an owner-block success.

Consumer delivery is a separate product PKG produced by
`tools/build_macos_native_host_companion_pkg.sh` and verified fail-closed by
`tools/verify_macos_native_host_companion_pkg.py`.

The verifier first copies one stable, unaliased regular-file view of the PKG
into a private mode-0400 custody file. Signature, stapling, Gatekeeper,
expansion, and payload checks all consume that same byte view. The custody
digest, byte count, inode metadata, and mode are rechecked after inspection, so
changing the caller pathname cannot swap the artifact between gates. The
expanded `Distribution` and component `PackageInfo` must bind the exact package
identifier and the release version recorded from `pubspec.yaml` in the schema-2
receipt. Extra product components and extra receipt fields are rejected.

The producer packages a prebuilt universal `x86_64+arm64` Developer ID
Application-signed, notarizable `wins_bridge_host`. Owner ruling 2026-10-16:
release line 1.0.16 ships an arm64-only (Apple silicon) host, because Dart
cannot cross-compile a `macos_x64` executable and the release Mac has no
Rosetta. The verifier accepts arm64-only only for 1.0.16, and the Distribution
`hostArchitectures` and minimum macOS are then taken from the host itself
(`arm64`, and the `LC_BUILD_VERSION` minimum, 14.0 for Dart 3.13.5), so an
Intel Mac or an older macOS refuses the install instead of receiving a host
that cannot run. It installs that binary at the exact system path:

`/Library/Application Support/Win's VPN/NativeMessagingHost/wins_bridge_host`

Firefox is registered only as `companion@winsvpn.org` at
`/Library/Application Support/Mozilla/NativeMessagingHosts/org.winsvpn.bridge.json`.
Chrome is registered only at
`/Library/Google/Chrome/NativeMessagingHosts/org.winsvpn.bridge.json`.
Edge is registered only at
`/Library/Microsoft/Edge/NativeMessagingHosts/org.winsvpn.bridge.json`.
Chrome and Edge origins are bound to the exact distinct owner-issued ids in the
package receipt. No Chrome id, Edge id, Developer ID Installer identity,
Application signature, notarization credential, or source-closure receipt is
invented.

Consumer `preinstall` and `postinstall` scripts are static POSIX `/bin/sh`.
They do not call Python and they do not depend on this repository. They refuse
symlink parents, snapshot live files, verify the incoming payload against the
receipt and fail before mutation when it is unsafe, then atomically replace
through `dest.new` plus `/bin/mv -f`, restoring rollback on failure. Installed
files are root:wheel with non-user-writable ancestry. An explicit uninstall
helper removes only those exact paths; it is not run by the PKG scripts.

The postinstall also issues the browser-bridge trust root that the app and
the host both require, `/Library/Application Support/wins_vpn/browser_bridge.identity`
(exact keys `v` and `secret`, `v` 1, 64 lowercase hex from `/dev/urandom`,
root:wheel 0444, single link). A valid receipt is kept byte for byte; an
unsafe or malformed one is left untouched and the install fails before
mutation. The uninstall helper removes it with the other exact files.

Sign the built host with `tools/native_messaging/sign_macos_native_host.sh
--host /absolute/wins_bridge_host`. The host signature must pass
`codesign --verify --strict`, identify Developer ID Application team
`5YT8H4U72M`, carry hardened runtime, and carry exactly the entitlements in
`tools/native_messaging/macos_native_host.entitlements`: the App Group
`5YT8H4U72M.group.org.winsvpn.app` (where the sandboxed app writes its IPC
discovery file) and `com.apple.security.cs.allow-unsigned-executable-memory`
(without it hardened runtime kills the Dart AOT host with a CODESIGNING
"Invalid Page" fault; `allow-jit` does not cover it). The final product
PKG must be signed by Developer ID Installer team `5YT8H4U72M`, notarized, and
stapled before the verifier prints PASS. Until the Installer certificate, Chrome id, Edge id, Application-signed host,
notarization credentials, and receipt inputs are all present, the producer stays
owner-blocked and does not emit a public PKG.

Operator check, which still does not write a PKG when a gate is missing:

```
sh tools/build_macos_native_host_companion_pkg.sh \
  --host /absolute/prebuilt/wins_bridge_host \
  --output /absolute/companion.pkg \
  --check-only
```

Verify a finished PKG only after it exists as a regular signed artifact:

```
python3 tools/verify_macos_native_host_companion_pkg.py /absolute/companion.pkg
```
