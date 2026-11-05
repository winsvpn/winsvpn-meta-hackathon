# Cross-Store Release Checklist

Last reviewed: 2026-08-25

Engineering checklist for store listings, privacy labels, and freeze receipts
across every shipping client surface. This does not authorize owner signing,
upload, or console mutation.

Canonical freeze platforms in `tools/release_dependency_freeze.py`:

| Freeze platform | Source roots | Store surfaces |
|---|---|---|
| `android` | `android/` (phone and TV flavors) | Google Play phone + TV |
| `wear_os` | `wear_os/` | Google Play Wear OS |
| `ios` | `ios/` plus shared Apple engine trees | Apple App Store (iPhone + watch companion) |
| `macos` | `macos/` plus shared Apple engine trees | Mac App Store required; Developer ID optional |
| `windows` | `windows/` and `installer/windows` | Website Win32 / Partner Center Win32 path |
| `linux` | `linux/` | Website tarball / Flathub / Snap (separate manifests) |
| `extension` | `extension/` | Chrome Web Store, Edge Add-ons, Firefox AMO |

Phone and TV share one native freeze root because they are Gradle product
flavors of the same application ID. Wear OS is a separate project and must not
inherit a phone or TV receipt. The watchOS companion is frozen with iOS, not as
its own freeze platform.

## Shared gates

- Freeze: create shared inputs, every platform manifest, then
  `RELEASE_INPUT_INDEX.json`. Shared manifests, platform manifests, the
  index, begin/finish receipts, and upload-readiness evidence must stay
  under `.artifacts/` and bind the exact artifact bytes.
- Production `tools/release_dependency_freeze.py` fails closed unless the
  source state is immutable/clean and every selected freeze input belongs
  to the exact tracked Git HEAD tree. Untracked files such as
  `installer/windows/dependencies/xray-arm64.exe`, staged-only paths, dirty
  worktree edits, and Git symlinks hashed as regular blobs cannot enter a
  release fingerprint. Isolated fixture/test mode is for local harnesses
  without Git; it cannot authorize release and the production CLI refuses
  it.
- Upload-readiness evidence: `tools/cross_store_upload_readiness.py`
  records the complete freeze platform set, store surfaces, obfuscation
  and privacy gate producers, and optional exact-artifact receipts. It
  never uploads and never sets `publication_authorized` or
  `store_upload_authorized` true. Recording or revalidating final local
  readiness requires a current, immutable GCP three-VM acceptance receipt
  whose revalidated client binding names the exact same
  `RELEASE_INPUT_INDEX.json`, by absolute path and SHA-256. The proof order,
  receipt schema, and no-production boundary are in
  [GCP proof fleet runbook](runbooks/GCP_PROOF_FLEET.md).
- Android phone/TV receipts may use targets `android-release-apk`,
  `android-release-aab`, `android-tv-release-apk`, and
  `android-tv-release-aab` on platform `android`.
- The 16 required upload targets include distinct Play AABs
  `android-phone-tablet-aab` and `android-tv-aab`. The production Play phone
  upload is the phone/tablet AAB. The phone APK is sidecar-only and is not
  the production upload. A phone/tablet AAB or a TV APK receipt is not TV
  AAB evidence. `android-tv-aab` remains one of the 16 required targets.
- Wear receipts use `wear_os/tools/signed_aab_receipt.py`.
- Extension packages are produced by `extension/build.py` as three upload
  targets: `chrome-extension-package`, `edge-extension-package`, and
  `firefox-extension-package`. Chrome and Edge packages are distinct; one
  browser's zip or receipt is not the other browser's evidence. Firefox AMO
  requires `data_collection_permissions.required: ["none"]`.
- Privacy policy URL for every store: `https://www.winsvpn.org/privacy/`.
- Default store builds must not expose external purchase links. Play Billing /
  App Store IAP remain owner-gated follow-ups, not implied by this checklist.

## Non-negotiable ordering

The required sequence is: final local tests and Fable 5, GLM 5.3, and Daybreak
Blue reviews; immutable freeze; genuine exact signed artifacts and receipts;
isolated fresh three-VM GCP proof; cross-store and owner store readiness; then,
and only then, a separately authorized production deployment or publication.
Neither a planned GCP proof nor a receipt for another release can satisfy this
gate. Do not upload an artifact, change a store portal, enable a public
download, or deploy a production server before the GCP proof receipt has been
reverified against the frozen release index.

## Google Play (phone, TV, Wear)

- Phone, TV, and Wear build on compile/target API 37 and NDK r30
  (`30.0.16248370`) under the owner decision of 2026-10-06, recorded in the
  dated, machine-checkable ruling
  `docs/rulings/ANDROID_API37_ADOPTION_20261006.json`. It supersedes the API 36
  compatibility exception for release `1.0.16+33`
  (`docs/rulings/ANDROID_API36_COMPATIBILITY_EXCEPTION_20260913.json`, kept as
  history), which required re-evaluation before the next Android release
  candidate, no later than 30 days after publication of that release.
- API 37 adoption requires reviewed Build-Tools 37.x, phone/TV/Wear runtime
  evidence, a local-network permission and product decision, adaptive TV
  validation, CT/ECH validation, and full native ABI load/tunnel-start tests.
  These stay open until closed or waived by the owner, before the next Android
  release candidate is uploaded to a store.
- Phone Data safety and `VpnService` / foreground-service /
  `QUERY_ALL_PACKAGES` answers: `docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md`.
- TV: Leanback launcher, same package, separate TV APK receipt and a
  required Play TV AAB (`android-tv-aab` / `android-tv-release-aab`). The TV
  flavor inherits `QUERY_ALL_PACKAGES` and ships the same per-app picker
  named `Exclude Apps From VPN (Split Tunneling)`. Do not treat
  `android-phone-tablet-aab` or `android-tv-release-apk` as the TV AAB.
- Wear: non-standalone, no Internet, no VPN, no `QUERY_ALL_PACKAGES`, no
  off-device collection. Do not copy the phone Data safety matrix onto Wear.
- `QUERY_ALL_PACKAGES` Play Console declaration remains `PENDING` until Play
  Console shows `Approved`. That is an owner publication gate.

## Apple App Store (iOS, watchOS, macOS)

- Release `1.0.15+30` requires one iOS App Store IPA with the embedded watchOS
  app and one macOS App Store PKG. Developer ID macOS distribution is optional
  and separately evidenced. Its absence or failure does not change the required
  target count, 100% readiness, freeze completeness, or App Store upload
  readiness. App Store IPA/PKG receipts must not claim Developer ID
  notarization. A Developer ID artifact, if produced, requires a Notarized
  Developer ID ticket of its own. tvOS is post-release native product work under
  `docs/rulings/TVOS_POST_RELEASE_PRODUCT_SCOPE_20260824.json`; it is not a
  current blocker, upload target, freeze platform, dashboard target, or
  readiness denominator.
- Source privacy manifests collect Coarse Location, Device ID, User ID, and
  Product Interaction on host apps. PacketTunnel and the watch companion
  collect nothing.
- Purchase History is **not collected**. Live App Store Connect still lists it
  as of 2026-07-11; the next owner submission must remove it. Do not publish
  that console change from this repository.
- Watch privacy manifest: `ios/WinsWatch Watch App/PrivacyInfo.xcprivacy`.
- Machine-checkable label: `app_store/apple/review/privacy_label_manifest.json`.
- Owner upload, TestFlight, and App Review remain unauthorized until
  `owner_signoff.json` `submission_approved` is true after a current rebuild.

## Microsoft Store / Windows Win32

- Production route is the signed Win32 Inno installer, not Store-signed MSIX.
- Release `1.0.15+30` uses product version `1.0.15` and four-part `1.0.15.30`.
  Website and Partner Center x64 listing metadata lives in `app_store/windows/`.
  Production MSIX identity `1.0.15.30` is fail-closed and is not an upload
  target. Private Flutter symbols use distinct
  `manifest-website.json` and `manifest-partner-center.json` receipts.
- The upload matrix requires four distinct Windows candidates: website x64,
  Partner Center x64, website ARM64, and Partner Center ARM64. The ARM64 names
  are `WinsVPN-Setup-arm64.exe` and `WinsVPN-PartnerCenter-arm64.exe`.
- Flutter 3.47.6 has a real `windows-arm64` target and publishes ARM64 engine
  artifacts. Stable chooses that target only when `flutter build windows` runs
  on a Windows ARM64 host. A Windows x64 host has no supported x64-to-ARM64
  target override. This remains a named upstream cross-compilation constraint,
  not a reason to relabel x64 output as native ARM64.
- Native ARM64 production builds must run on Windows ARM64. The producer checks
  host equals target, then checks every loose EXE/DLL is PE32+ ARM64. Winn v3,
  the AWG service, the rebuilt AmneziaWG helper, Xray, Wintun, and the Flutter
  runner all have to pass that same machine gate.
- Inno Setup's bootstrap is a vendor compatibility executable. The ARM64
  package label refers to its native application and VPN payload, not to an
  assertion that the Inno bootstrap stub itself is ARM64. x64 emulation never
  satisfies the Flutter runner or payload gates.
- The ARM64 installer is Windows 11 only. Inno Setup 7.1.0 has no ARM64 loader,
  so `winsvpn.iss` sets `SetupArchitecture=x64` and the ARM64 installer starts
  with the x64 loader. Windows 10 on ARM cannot run an x64 program at all and
  refuses the installer in the shell before any Setup code runs; on every ARM64
  host that can start the loader, `MinVersion=10.0.22000` in the ARM64 branch of
  `winsvpn.iss` makes Setup refuse with its own message.
- Before freezing an ARM64 release, run
  `tools/build_windows_amneziawg_client.ps1 -TargetArchitecture arm64` on the
  reviewed Windows host. It verifies the official 3.1.0 ARM64 MSI and payload
  signatures, builds the Go 1.27 helper twice, requires byte-identical results,
  and publishes architecture-specific inputs. Then build each signed surface
  with `installer/windows/build_installer.ps1 -TargetArchitecture arm64`.
- Primary upstream evidence: Flutter 3.47.6
  `build_windows.dart` maps `windows_arm64` to CMake `ARM64`; its
  `build_windows` command selects `windows-arm64` on an ARM64 host. Flutter's
  x64-host cross-target request remains open as issue 129808. AmneziaWG Windows
  client 3.1.0 publishes the exact signed ARM64 MSI used by the dependency
  producer.
- See `docs/DESKTOP_STORE_RELEASE_READINESS.md`. Public-trust signing identity
  and Partner Center enrollment remain owner actions.

- The Windows installer payload is not byte-reproducible (MSVC and native-host
  timestamps); two builds of one freeze differ. That is accepted for release
  `1.0.16+33` only, by `docs/rulings/WINDOWS_PAYLOAD_NONREPRODUCIBLE_ACCEPTANCE_20261022.md`.
  Each receipt binds the exact installer bytes, so a rebuild is a new artifact.
- A Windows receipt binds the digest and revision of the secret inventory its
  installer was scanned with, and `verify-receipt` runs the exact scan again and
  refuses any other inventory file, even one that would also pass. Keep the exact
  inventory file that finish used for the receipt's whole lifetime. An inventory
  change means a new remote run, a new finish and a new receipt.

## Linux

- Website/manual tarballs are the current Linux release path, with distinct
  `wins-vpn-linux-x64.tar.gz` and `wins-vpn-linux-arm64.tar.gz` candidates.
  Those required website upload kinds are native tarballs, not DEB. The
  derived Debian package is not a separate 16-target upload. Flathub and
  Snap are dual-arch separate manifests covering x64 and arm64. Each tarball
  must be built natively on its matching Linux architecture. Flutter
  3.47.6 still refuses Linux x64-host to ARM64-target builds.
- The release and Debian producers derive architecture from ELF64 headers and
  reject a candidate if any packaged ELF, including a nested shared library or
  browser native host, targets another machine. A filename or requested Debian
  architecture is never accepted as architecture evidence.
- Local key signing requires all three inputs together:
  `WINS_LINUX_COSIGN_KEY`, `WINS_LINUX_COSIGN_PUBKEY`, and
  `WINS_LINUX_COSIGN_TRUST_ANCHOR=/etc/winsvpn/release-signing/cosign.pub`.
  The private key must be current-user-owned with mode `0600` or stricter. The
  installer accepts offline verification only when its explicit public-key path
  is that root-owned, non-writable trust-anchor route.
- Neither architecture is publishable until its exact candidate has a current
  build receipt, signature, clean install/upgrade/remove evidence, and live VPN
  qualification on the matching architecture.
- Flathub/Snap submissions need separate store manifests and confinement
  justifications. Do not treat the tarball as a Flathub receipt.

## Browser extensions

- One source tree, per-browser manifest fragments, three store uploads.
- Chrome Web Store (`chrome-extension-package`): host permissions stay
  optional; no remote code.
- Edge Add-ons (`edge-extension-package`): a required upload target of its
  own. Do not hide Edge under Chrome or reuse the Chrome zip or Chrome
  receipt as Edge evidence.
- Firefox AMO (`firefox-extension-package`): Gecko ID
  `companion@winsvpn.org`, `strict_min_version` 140.0,
  `data_collection_permissions.required` is `["none"]`. The producer writes
  unsigned `wins-vpn-companion-firefox.zip` and a distinct-inode `.xpi` copy
  of those exact bytes. Mozilla signing is absent until AMO evidence exists.
- Packaged JavaScript is whitespace-only minification of authored
  `extension/src`. Identifier mangling is forbidden. AMO and Chrome Web Store
  source disclosure for that transform remains an owner portal action.
- Listing drafts, privacy label, and the unbound release candidate stay in
  `extension/store_listings/` and remain pending without upload receipts.
- Native messaging host manifests are extension freeze producers under
  `tools/native_messaging/`.

## Receipt isolation

- A native-only change invalidates only that freeze platform.
- Shared Dart/`lib/`/lockfile changes invalidate every platform.
- Wear pairing contract helper `tools/wear_os_pairing_contract_check.py` is a
  producer for both `android` and `wear_os`.
- Historical 5-platform freeze indexes are incomplete after this checklist:
  regenerate the index so it binds Wear OS and extension source inputs before
  treating any receipt as current.

## Artifact custody and receipt freshness

- Create each local target receipt only with
  `tools/cross_store_target_receipt.py produce`. Supply the exact existing
  release-input index, artifact, build receipt, immutable output path, and a
  target-specific gate-evidence directory. The producer's `list-targets`
  command distinguishes the 16 required targets from the one optional
  Developer ID target.
- The target receipt producer is not a builder, signer, uploader, deployer, or
  publication authorization tool. It derives artifact and producer hashes,
  verifies the exact build receipt and source/dependency freeze, executes the
  target's signing and obfuscation/privacy verification pair with shell-disabled
  argv, and publishes only after the validator accepts the complete receipt.
- Receipts are immutable owner-only files under `.artifacts/`. Publication uses
  a same-directory durable temporary file and atomic no-clobber link. Existing
  receipts are never replaced, and a failed or partial write cannot create a
  success receipt. Use a new immutable output path for a new artifact custody
  transaction.
- Receipt and gate-evidence directories must be owner-controlled mode `0700`;
  produced JSON and SHA-256 sidecars are mode `0600`. The producer rejects
  symlinks, reparse points, hardlink aliases, non-regular files, unsafe output
  names, duplicate JSON keys at any depth, boolean-as-integer schema values,
  clock rollback, stale artifacts, and target/platform/build/gate substitution.
- Final readiness does not trust a receipt's `passed` claim. It independently
  re-executes both exact, hash-bound gates for every one of the 16 required
  targets before recording readiness. A Developer ID receipt is verified and
  retained separately when produced, but is never read into that required
  aggregate or denominator.
- Upload-target receipts must report `ok: true`. A structurally valid receipt
  that reports failure is not release evidence.
- The receipt, both executed gate records, and the exact artifact modification
  time must all be within the validator's 72-hour freshness window. Rerunning
  signature or obfuscation gates does not refresh an old binary.
- Every target remains bound to the current release input index, platform input
  fingerprint, exact build receipt and toolchain, producer hash, artifact hash
  and byte count, signature gate, and obfuscation/privacy gate.
- Apple `owner_signoff.json` keeps top-level schema 1 decision-tracking fields,
  but submission authorization additionally requires the nested schema 2
  authorization contract. That authorization is valid only when its exact
  release, candidate, artifact hashes, required targets, evidence timestamps,
  signer identity, and Apple team binding all validate. The current file remains
  pending and cannot authorize submission until the owner issues that complete
  bound authorization.
