# Apple Private Symbol Custody

Release iOS and macOS builds produce two independent symbol sets:

- Flutter `app.*.symbols` files map obfuscated Dart stack traces.
- Xcode archive `.dSYM` bundles map native Runner, PacketTunnel, framework, and
  engine crash addresses.

Both sets are private release records. They must not be copied into an IPA,
PKG, website download, source archive, Git commit, support bundle, or public CI
artifact.

## Current signing and custody status (verified 2026-08-24)

- The local keychain currently exposes usable Apple Development, Apple
  Distribution, and Developer ID Application code-signing identities. The iOS
  host, PacketTunnel, and embedded watchOS signing inputs are substantially
  ready for a fresh candidate build.
- No `3rd Party Mac Developer Installer` or `Developer ID Installer` identity
  is currently available. A current macOS App Store PKG therefore cannot be
  produced, and Developer ID installer packaging is also blocked. Historical
  macOS exports and custody records are not current release evidence.
- The App Store Connect authentication variables are not configured as a
  complete path/key-ID/issuer-ID set in the current release shell. No current
  live authentication or upload authority is claimed.
- No final `1.0.15+30` IPA or PKG custody record exists yet. Run collection only
  after the matching signed artifact has been freshly produced and verified.

## Release contract

The Release and Profile Xcode project configurations use
`DEBUG_INFORMATION_FORMAT=dwarf-with-dsym`, then strip the installed products
with `STRIP_STYLE=all`. Xcode creates dSYMs before the delivered Mach-O files
are stripped and signed. Required PacketTunnel and Go/C bridge exports are
still verified with `nm` after linking; the artifact gate permits required
external ABI entries but rejects local and STABS symbol entries, `__DWARF`, and
`__debug*` sections in delivery Mach-O files.

The final App Store-local export lanes invoke:

```bash
python3 tools/apple_release_symbol_custody.py collect \
  --platform ios \
  --artifact "build/apple/exports/ios-app-store-local/Win's VPN.ipa" \
  --flutter-symbols ".artifacts/private-release-symbols/apple/ios/1.0.15+30" \
  --archive build/apple/archives/wins-vpn-ios.xcarchive
```

After the missing macOS installer-signing material is provisioned, use
`--platform macos` with the exact freshly produced final PKG and macOS xcarchive.
The runtime tool supplies these arguments automatically; the example is for
recovery and audit only and does not claim that a current PKG exists.

Custody records are stored by default at:

```text
.artifacts/private-release-symbols/apple/artifact-custody/
  <platform>/<version+build>/<artifact-sha256>/
```

Each directory contains copied Flutter symbols, copied xcarchive dSYMs, and a
`manifest.json` that binds their names, sizes, and SHA-256 hashes to the exact
IPA or PKG. Existing records are immutable: a repeated collection verifies the
record, while any mismatch fails instead of overwriting it. The entire
`.artifacts/private-release-symbols` tree is ignored by Git.

Collection binds the original artifact, Flutter symbol root, and xcarchive
path with `lstat` and `O_NOFOLLOW` descriptors before hashing or copying.
Top-level aliases and nested symlink substitution are refused. Custody hashes
remain SHA-256 of the bound regular-file bytes, so dSYM UUIDs are preserved
exactly.

## Operator custody

After every final export:

1. Run the custody verifier against the exact artifact before moving or
   uploading it.
2. Back up the artifact-keyed directory to encrypted, access-controlled
   storage. Preserve at least two independent copies for the supported crash
   analysis lifetime of that release.
3. Record who transferred the directory and verify the copied manifest hashes.
4. Restrict access to release engineers handling crash symbolication. Treat
   symbols as sensitive implementation metadata even though they are not
   signing keys.
5. Never regenerate or substitute dSYMs after an artifact is signed. A rebuilt
   binary has different UUIDs and cannot symbolicate the released artifact.

Run these source-only checks before the next Apple build:

```bash
python3 tools/apple_release_symbol_custody.py self-test
python3 tools/test_apple_release_symbol_custody.py
python3 tools/test_apple_release_hardening.py
python3 tools/validate_release_artifact_privacy.py --self-test
```

The default exact-secret/privacy artifact scan resolves the manifest-pinned
IPA and PKG in addition to Android, Windows, and Linux artifacts. It rejects
embedded user-home and source-tree paths as release-fatal metadata leakage.
