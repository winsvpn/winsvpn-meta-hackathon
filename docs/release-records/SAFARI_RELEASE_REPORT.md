# Safari standalone proxy: Developer ID release report

Date: 2026-11-02 (America/New_York). Lane: `safari-proxy-release`, worktree `/Users/owner/.podium/lanes/landing/safari-wt`, based on `landing-wave1` at `5bf525c`.
Owner decision implemented: "Separate Safari package" (`owner_decision_safari_design_20261005.md`, `owner_decision_safari_standalone_proxy_20261004.md`).

## Result

The DMG below is Developer ID signed, notarized and stapled. The app inside it is also stapled. It was built from committed source at `d233c2b`, and the receipt records `dirty_inputs: false`.

| Item | Value |
|---|---|
| Artifact | `/Users/owner/Desktop/WinsVPN Safari Proxy release/WinsVPN-Safari-Proxy-1.0.16-33-macOS.dmg` |
| SHA-256 | `711f7bc6f72ccc0c6a282375b1524bd460326d7ffd7b912abb15e97adb3342a0` |
| Size | 5,123,765 bytes |
| Version | 1.0.16 (33), from `pubspec.yaml` through `generate_project.py` |
| Minimum macOS | 14.0, arm64 only |
| Notarization, app ZIP | submission `d1ead0a1-f629-4762-a4e4-593052c17f69`: **Accepted**, 0 issues |
| Notarization, DMG | submission `e9cac958-60bd-463a-9ecf-13c487050751`: **Accepted**, 0 issues |
| Receipt | `release-receipt.json` beside the DMG. It lists component cdhashes, entitlements, profiles, engine and web input digests. `SHA256SUMS` is there too. |

The checks below all passed on the staged app and DMG. The DMG was then mounted read-only, and the shipped app was checked again with codesign and stapler. Its signature identity matched the staged copy for all three components.

- `codesign --verify --deep --strict` on the app and on the DMG.
- `spctl -a -vvv -t exec` on the app and `spctl -a -t open --context context:primary-signature` on the DMG. Both returned `source=Notarized Developer ID`, `origin=Developer ID Application: Win's VPN Inc (5YT8H4U72M)`.
- `xcrun stapler validate` on the app and on the DMG.
- The published copy on the Desktop was re-checked independently with `shasum -c`, `spctl` and `stapler`.

## What is in the package

| Component | Bundle ID | Location | Profile (MAC_APP_DIRECT) |
|---|---|---|---|
| Containing app | `org.winsvpn.safariproxy` | `SafariProxyMac.app` | Wins VPN Safari Proxy Developer ID org.winsvpn.safariproxy |
| Safari web extension | `org.winsvpn.safariproxy.web` | `Contents/PlugIns/SafariWebMac.appex` | ... org.winsvpn.safariproxy.web |
| App proxy + DNS proxy system extension | `org.winsvpn.safariproxy.network` | `Contents/Library/SystemExtensions/org.winsvpn.safariproxy.network.systemextension` | ... org.winsvpn.safariproxy.network |

Every component has the hardened runtime, a secure timestamp, no `get-task-allow`, and only the Developer ID network extension values `app-proxy-provider-systemextension` and `dns-proxy-systemextension`. The app also has `com.apple.developer.system-extension.install`. The embedded web resources were compared byte for byte with `extension/dist/wins-vpn-proxy-safari.zip` (SHA-256 `9404dbfa...3808`). The engine archive `libSafariWinn-macos-arm64.a` was built from source by `build_engine.py` (input digest `0d2dd332...5e7e`).

## Packaging choice: DMG, not an Installer pkg

A system extension activates only when its containing app is in `/Applications`. A drag-install DMG puts it there with no admin-run installer and no install scripts. Removing it means dragging the app to the Trash after deactivating the extension. A pkg would need the Developer ID Installer identity (it is not in the codesigning identity list on this Mac) and an admin authorization, and it would add nothing for one app bundle.

## Script: `apple/SafariProxy/Tools/build_release.py`

```
python3 apple/SafariProxy/Tools/build_release.py \
  --api-key ~/.appstoreconnect/private_keys/AuthKey_<KEYID>.p8
```

The steps run in order: `engine, web, project, profiles, archive, export, inspect, notarize, verify, publish, clean`. Use `--steps` to pick a subset. Intermediates go to `apple/SafariProxy/build/` (git-ignored). DerivedData stays inside that directory. `clean` deletes the DerivedData, the archive, the export and the private module cache. A clean run took about 2 minutes 10 seconds, including both notarizations.

- **engine**: stages a private Go module cache from the shared cache's module ZIPs, then runs `build_engine.py`, which enforces the go.sum h1 pins and runs the bridge tests under `-race`. Two pinned modules were missing from the shared cache (`golang.org/x/exp@v0.0.0-20250711185948-6ae5c78190dc`, `golang.org/x/time@v0.16.0`). The script fetched them from the Go module proxy, and the same h1 pins verified them.
- **project**: runs `generate_project.py` and refuses any difference from the working tree. It refuses uncommitted release inputs unless `--allow-dirty` is passed, which is meant for rehearsals only.
- **profiles**: uses the App Store Connect API key to register the three bundle IDs if they are missing, enable `NETWORK_EXTENSIONS` (and `SYSTEM_EXTENSION_INSTALL` on the app), and fetch or create one Developer ID profile per bundle ID. The JWT is signed with `/usr/bin/openssl`, which reads the key file itself. The script redacts the issuer ID from every printed line and every log. A grep of the logs and the receipt found no occurrence of it.
- **archive/export**: manual Developer ID signing, with the profile chosen per target as `Wins VPN Safari Proxy Developer ID $(PRODUCT_BUNDLE_IDENTIFIER)`. Automatic Xcode signing cannot work for this project. Development profiles carry the non-suffixed NE values, so Xcode reports a profile mismatch. Apple DTS calls this a known Xcode limitation for Developer ID system extensions.
- **notarize**: notarizes a ZIP of the app and staples it, builds an APFS `ULFO` DMG with an `/Applications` link, signs the DMG, notarizes it and staples it.

## Source fixes made (commit `d233c2b`)

1. **System extension bundle name.** The generated product was `SafariProxyNetwork.systemextension`. sysextd looks a system extension up by `<CFBundleIdentifier>.systemextension`, so activation would have failed with "extension not found". The product is now `org.winsvpn.safariproxy.network.systemextension`, with `PRODUCT_NAME = $(PRODUCT_BUNDLE_IDENTIFIER)`. `PRODUCT_MODULE_NAME` stays `SafariProxyNetwork`, so `NEProviderClasses` is unchanged. `package_debug.py` was updated to match.
2. **App group.** The app group changed from `group.org.winsvpn.safariproxy` to `$(TeamIdentifierPrefix)$(SAFARI_PROXY_BASE_ID)`, which resolves to `5YT8H4U72M.org.winsvpn.safariproxy`. The `group.` form is not registered on the portal, and the API cannot assign it to a profile. On macOS 15 and later, a profile has to authorize that form. The team-prefixed form needs neither. It also now prefixes `NEMachServiceName` (`5YT8H4U72M.org.winsvpn.safariproxy.network`), which the NE system extension rules require. The old `group.` value did not prefix it. Only the system extension reads or writes this container (the DNS broker port file).
3. **`Resources/Legal.plist`** was regenerated. The committed file had been hand-edited so that its unused `version` label read `2026-10-04.v5`. The generator and the hub legal version that the app actually sends (`SafariHubSession.bundledLegalVersion`) are both `2026-08-31.v4`. The displayed body and its hash did not change.
4. Added `Tools/build_release.py` and `Tools/test_build_release.py`. The tests cover ES256 DER-to-raw conversion, the system extension naming, the Mach service and app group prefix, and the NE entitlement values.

Bundle ID base: `org.winsvpn.safariproxy`. It was already defined in `Common.xcconfig` and is not a placeholder, so it was kept.

## Tests (run on this Mac, on the committed tree)

| Suite | Result |
|---|---|
| Go bridge acceptance tests (`build_engine.py`, `go test -race`, 8 named tests) | 8 passed |
| `Tools/test_build_release.py` + `Tools/test_build_engine.py` (unittest) | 10 passed |
| `extension/tools/test_safari_forwarding.py`, `test_safari_standalone.py`, `test_safari_target.py`, `test_safari_candidate.py` (pytest). These cover the real Swift/C stack runtime, the DNS broker loopback, the 77-assertion hub session suite, the session and provider lifecycle verifiers, and the Swift control-protocol tests | 16 passed |
| `extension/build.py safari` gates | passed (27 files, 4/4 gates) |
| `tools/test_toolchain_pin_consistency.py` | 27 passed, 1 failed. The failure is in `installer/windows/dependencies/amneziawg...` provenance JSON, outside this lane. `build_release.py` reads the Go pin from `tools/toolchain-pins.json` and adds no literal. |

Not run: device or activation tests of the installed system extension, and live Safari traffic tests. These remain gates under the owner decision.

## What the owner must do (nothing was approved or installed on this Mac)

1. Open the DMG and drag **SafariProxyMac** onto **Applications**. Launch it from `/Applications`, because activation is refused anywhere else.
2. Start the connection in the app. macOS shows "System Extension Blocked". Open **System Settings > General > Login Items & Extensions**, find **Network Extensions** (the entry for SafariProxyMac / `org.winsvpn.safariproxy.network`), turn it on, and confirm with your password or Touch ID. On macOS 14 the control is in **System Settings > Privacy & Security** ("System software from Win's VPN Inc was blocked", then **Allow**).
3. Click **Allow** when macOS asks to let SafariProxyMac add proxy configurations. That prompt comes from the transparent proxy and DNS proxy configurations.
4. In **Safari > Settings > Extensions**, enable the Win's VPN proxy extension.

## Remaining risks and open items

- **DNS scope.** The DNS proxy is installed through `NEDNSProxyManager`, which is system-wide. While it is connected, every app's DNS goes through this provider, not only Safari's. The transparent proxy, by contrast, claims only flows whose `sourceAppSigningIdentifier` is `com.apple.Safari` or `com.apple.SafariTechnologyPreview`. Whether that scope difference is acceptable is a design question for the debate.
- **Safari flow attribution is unverified on a device.** Safari's sockets are opened by `com.apple.WebKit.Networking`. If the target OS does not report Safari as the source signing identifier, `handleNewFlow` claims nothing and Safari traffic is not proxied. The code comment calls this a device-test gate.
- **DNS broker port file.** Both providers run in the same root system extension process, so the group container is root's. The publish and read sites are consistent, but this has not been exercised on a device.
- The app's user-visible name is `SafariProxyMac`. A display name (`CFBundleDisplayName`) and an app icon are not set, and nothing in the package uses the brand assets yet.
- arm64 only. Intel Macs are not supported because `build_engine.py` builds arm64 archives only.
- **Shared Go module cache.** Many extracted module trees in `~/.local/gopath/pkg/mod` (circl, quic-go, klauspost/compress, pgx and others) contain symlinks into `~/.winsvpn-secrets/...`, apparently left by a secret-quarantine pass on 2026-10-24. `build_engine.py` correctly refuses them. `build_release.py` avoids the problem by rebuilding a private cache from the verified ZIPs. Other builds that read the shared cache may be affected. The cache was not modified.
- **Side effects on the developer account and this Mac.**
  - Before manual signing was chosen, Xcode automatic signing registered the App IDs `org.winsvpn.safariproxy`, `.web` and `.network` on team 5YT8H4U72M and created three development profiles ("Mac Team Provisioning Profile: org.winsvpn.safariproxy*").
  - The API created three Developer ID profiles (expiring 2044-10-29), installed in `~/Library/Developer/Xcode/UserData/Provisioning Profiles`.
  - Nothing was pushed, deployed, or submitted to a store, and no server was changed.
- **Cleanup.** The DerivedData, archive, export, staging copies, engine work directories, private module cache and `extension/dist` were deleted. `apple/SafariProxy/build/logs` and `release-receipt.json` (348 KB) are kept for audit. The release on the Desktop is kept.
