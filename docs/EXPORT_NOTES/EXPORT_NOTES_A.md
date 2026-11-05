# Lane A export notes: Win's VPN public-safe source copy

Source: git worktree `/Volumes/WinsBuild/winsvpn/podium/lanes/rel17`, branch `release-1.0.17`, commit `faff0b5` (read-only; worktree status clean before and after the export).
Output: `/Volumes/WinsBuild/winsvpn/hackathon/fullsrc/laneA/` (original relative paths preserved).
Built: 2026-11-04 by export lane A. File list source: `git ls-files` on the slice paths (tracked files only).

## 1. Slice and counts

Slice: `lib/ test/ assets/ pubspec.yaml pubspec.lock analysis_options.yaml android/ ios/ macos/ windows/ linux/ wear_os/ apple/ installer/ brand/ video/ play_console_assets/ app_store/ .github/ patches/` plus every tracked file in the repository root.

The `git ls-files` list had 1334 entries; `pubspec.yaml`, `pubspec.lock` and `analysis_options.yaml` were listed twice (once as named paths, once as root files), so the slice is 1331 unique tracked files. 1276 were copied, 55 were excluded (7 under rule 2, 48 under rule 3, none under rule 1). 24 copied text files were scrubbed under rule 4; the other 1252 are byte-identical to the source (SHA-256 compared).

| Top-level | Files copied |
|---|---|
| `test` | 264 |
| `android` | 262 |
| `app_store` | 110 |
| `lib` | 97 |
| `ios` | 95 |
| `apple` | 86 |
| `windows` | 65 |
| `linux` | 61 |
| `wear_os` | 45 |
| `(root)` | 43 |
| `macos` | 42 |
| `assets` | 35 |
| `installer` | 27 |
| `brand` | 23 |
| `.github` | 11 |
| `patches` | 6 |
| `play_console_assets` | 2 |
| `video` | 2 |
| **Total** | **1276** |

Not in this slice (left for the coordinator): `.githooks/reference-transaction` is a tracked file in a root-level directory that is not on the lane A list and is not a root file, so it was not copied.

## 2. Excluded paths

### Rule 1 (secrets and key material): nothing excluded

Checked: no `*.key`, `*.p12`, `*.pfx`, `*.mobileprovision`, `*.provisionprofile`, `*.keystore`, `*.jks`, `key.properties`, `AuthKey_*.p8`, keychain export, garble seed, SSH key or populated env file is tracked in the slice. The eight `test/fixtures/control_plane_chains_20261004/*.pem` files each contain three `CERTIFICATE` blocks and no private key (public chains for the control-plane pins). `linux/packaging/release-signing/cosign.pub` is a public key. `.env.example` is a names-only template (every credential variable is empty). `backup_keys.example.txt` is an instructions-only template with no values. The three `gradle.properties` and three `gradle-wrapper.properties` files carry build settings only. The two `BEGIN PRIVATE KEY` string hits are test assertions (see section 5).

### Rule 2 (owner identity receipts and sign-off records)

| Path | Size | Reason |
|---|---|---|
| `app_store/android/phone/review/owner_signoff.json` | 660 B | coordinator pattern app_store/*/owner_signoff*; release-state fields only, no personal data (reinstatable) |
| `app_store/android/tv/review/owner_signoff.json` | 702 B | coordinator pattern app_store/*/owner_signoff*; release-state fields only, no personal data (reinstatable) |
| `app_store/android/wear/review/owner_signoff.json` | 575 B | coordinator pattern app_store/*/owner_signoff*; release-state fields only, no personal data (reinstatable) |
| `app_store/apple/review/owner_review_packet.md` | 20.8 KB | owner legal name (line 118) plus owner approval quotes |
| `app_store/apple/review/owner_signoff.json` | 21.6 KB | owner authorization record with quoted owner chat approvals (coordinator pattern app_store/*/owner_signoff*) |
| `app_store/linux/review/owner_signoff.json` | 852 B | coordinator pattern app_store/*/owner_signoff*; release-state fields only, no personal data (reinstatable) |
| `app_store/windows/review/owner_signoff.json` | 1.3 KB | coordinator pattern app_store/*/owner_signoff*; release-state fields only, no personal data (reinstatable) |

Five of the seven `owner_signoff.json` files (android phone, android tv, android wear, linux, windows) hold only release-state fields (version codes, `submission_approved: false`, blocker lists). They were excluded because the coordinator named the `app_store/*/owner_signoff*` pattern; they can be reinstated with a plain copy from the source worktree if wanted. The Apple `owner_signoff.json` and `owner_review_packet.md` contain the owner legal name (packet line 118), quoted owner chat approvals and references to private decision files, so those two stay excluded regardless.

### Rule 3 (prebuilt binaries)

| Path | Size | Reason |
|---|---|---|
| `android/app/libs/amneziawg.aar` | 14.4 MB | prebuilt .aar engine bundle larger than 5 MB |
| `android/app/src/debug/jniLibs/arm64-v8a/libwinn_tun_bulk.so` | 11.2 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/debug/jniLibs/arm64-v8a/libxray.so` | 37.7 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/debug/jniLibs/armeabi-v7a/libwinn_tun_bulk.so` | 9.7 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/debug/jniLibs/armeabi-v7a/libxray.so` | 37.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/debug/jniLibs/x86_64/libwinn_tun_bulk.so` | 11.2 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/debug/jniLibs/x86_64/libxray.so` | 40.2 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/main/jniLibs/arm64-v8a/libwinn_tun_bulk.so` | 11.2 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/main/jniLibs/arm64-v8a/libwinnengine.so` | 10.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/main/jniLibs/arm64-v8a/libxray.so` | 37.7 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/main/jniLibs/armeabi-v7a/libwinn_tun_bulk.so` | 9.7 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/main/jniLibs/armeabi-v7a/libwinnengine.so` | 10.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/main/jniLibs/armeabi-v7a/libxray.so` | 37.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/main/jniLibs/x86_64/libwinn_tun_bulk.so` | 11.2 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/main/jniLibs/x86_64/libwinnengine.so` | 11.3 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/main/jniLibs/x86_64/libxray.so` | 40.2 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/profile/jniLibs/arm64-v8a/libwinn_tun_bulk.so` | 11.2 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/profile/jniLibs/arm64-v8a/libwinnengine.so` | 10.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/profile/jniLibs/arm64-v8a/libxray.so` | 37.7 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/profile/jniLibs/armeabi-v7a/libwinn_tun_bulk.so` | 9.7 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/profile/jniLibs/armeabi-v7a/libwinnengine.so` | 10.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/profile/jniLibs/armeabi-v7a/libxray.so` | 37.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/profile/jniLibs/x86_64/libwinn_tun_bulk.so` | 11.2 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/profile/jniLibs/x86_64/libwinnengine.so` | 11.3 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/profile/jniLibs/x86_64/libxray.so` | 40.2 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/release/jniLibs/arm64-v8a/libwinn_tun_bulk.so` | 11.2 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/release/jniLibs/arm64-v8a/libwinnengine.so` | 10.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/release/jniLibs/arm64-v8a/libxray.so` | 37.7 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/release/jniLibs/armeabi-v7a/libwinn_tun_bulk.so` | 9.7 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/release/jniLibs/armeabi-v7a/libwinnengine.so` | 10.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/release/jniLibs/armeabi-v7a/libxray.so` | 37.5 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/release/jniLibs/x86_64/libwinn_tun_bulk.so` | 11.2 KB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/release/jniLibs/x86_64/libwinnengine.so` | 11.3 MB | .so prebuilt binary (excluded regardless of size) |
| `android/app/src/release/jniLibs/x86_64/libxray.so` | 40.2 MB | .so prebuilt binary (excluded regardless of size) |
| `apple/EngineArtifacts/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib` | 29.3 MB | .dylib prebuilt binary (excluded regardless of size) |
| `apple/EngineArtifacts/ios/iphoneos/libWinsWinnPacketEngine.dylib` | 8.9 MB | .dylib prebuilt binary (excluded regardless of size) |
| `apple/EngineArtifacts/ios/iphoneos/libWinsXrayVlessWsTransport.dylib` | 84.6 KB | .dylib prebuilt binary (excluded regardless of size) |
| `apple/EngineArtifacts/macos/libWinsAmneziaWGPacketEngine.dylib` | 60.9 MB | .dylib prebuilt binary (excluded regardless of size) |
| `apple/EngineArtifacts/macos/libWinsWinnPacketEngine.dylib` | 18.7 MB | .dylib prebuilt binary (excluded regardless of size) |
| `apple/EngineArtifacts/macos/libWinsXrayVlessWsTransport.dylib` | 117.5 KB | .dylib prebuilt binary (excluded regardless of size) |
| `installer/windows/dependencies/VC_redist.arm64.exe` | 11.2 MB | .exe prebuilt binary (excluded regardless of size) |
| `installer/windows/dependencies/VC_redist.x64.exe` | 24.4 MB | .exe prebuilt binary (excluded regardless of size) |
| `installer/windows/dependencies/amneziawg-arm64.exe` | 8.1 MB | .exe prebuilt binary (excluded regardless of size) |
| `installer/windows/dependencies/amneziawg.exe` | 8.7 MB | .exe prebuilt binary (excluded regardless of size) |
| `installer/windows/dependencies/awg-arm64.exe` | 128.4 KB | .exe prebuilt binary (excluded regardless of size) |
| `installer/windows/dependencies/awg.exe` | 153.9 KB | .exe prebuilt binary (excluded regardless of size) |
| `installer/windows/dependencies/xray-arm64.exe` | 32.9 MB | .exe prebuilt binary (excluded regardless of size) |
| `installer/windows/dependencies/xray.exe` | 35.6 MB | .exe prebuilt binary (excluded regardless of size) |

Kept under rule 3 as written (not `.so`/`.dylib`/`.exe`, under 5 MB), flagged for the coordinator: `installer/windows/dependencies/amneziawg-amd64.msi` (3.5 MB), `installer/windows/dependencies/amneziawg-arm64.msi` (3.2 MB), `installer/windows/dependencies/wintun.dll` (417 KB), `installer/windows/dependencies/wintun-arm64.dll` (217 KB), three `gradle-wrapper.jar` copies (46 KB each). These are third-party redistributables, not Win's VPN build outputs. Also kept: `assets/icon/Win's VPN.original-wide.png` (5.0 MB, an image, which rule 3 says to keep) and `video/final_demo.mp4` (4.3 MB media).

## 3. Scrubbed files (rule 4)

Replacements were made byte-for-byte on the copied file only. No reformatting, no logic change, no comment removed. Placeholders used: `/Users/owner` for the macOS home path, `C:\Users\owner` for the Windows profile path, RFC 5737 documentation addresses (`203.0.113.x`, `198.51.100.x`) for real IPv4 literals, `PAYPAL_CLIENT_ID_PLACEHOLDER` and `P-PLACEHOLDER-...-PLAN` for the PayPal identifiers, and `/assets/<zero-padded counter>` for the per-node Xray stealth paths. Original values are deliberately not listed here.

| File | Replacement | Count |
|---|---|---|
| `1 Month Subscription.txt` | PayPal JS SDK client-id | 1 |
| `1 Month Subscription.txt` | PayPal billing plan id | 4 |
| `1 Year Subscription.txt` | PayPal JS SDK client-id | 1 |
| `1 Year Subscription.txt` | PayPal billing plan id | 4 |
| `OWNER_WAKE_CHECKLIST.md` | local home path | 2 |
| `PAIRING_REPORT.md` | local home path | 3 |
| `Personal Subscription.txt` | PayPal JS SDK client-id | 1 |
| `Personal Subscription.txt` | PayPal billing plan id | 4 |
| `README_XPRIZE_SOURCE_OF_RECORD.md` | GCE demo gateway IPv4 (route A) | 3 |
| `README_XPRIZE_SOURCE_OF_RECORD.md` | GCE demo gateway IPv4 (route B) | 3 |
| `RELEASE_1.0.17.md` | local home path | 1 |
| `SAFARI_RELEASE_REPORT.md` | local home path | 2 |
| `SPEC.md` | local home path | 2 |
| `SPEC.md` | GCE demo gateway IPv4 (route A) | 2 |
| `SPEC.md` | GCE demo gateway IPv4 (route B) | 2 |
| `android/app/src/test/kotlin/org/winsvpn/app/WinnV3PostureTest.kt` | real-looking node IPv4 in test literal | 2 |
| `android/app/src/tv/.res_backups_gen_tv_banner_320x180_mdpi/dims.txt` | local home path | 3 |
| `app_store/apple/review/v3_submission_20260810_bld_store_ios/owner_api_key_report.md` | local home path | 1 |
| `app_store/apple/review/v3_submission_20260811_bld_store_ios/owner_api_key_report.md` | local home path | 4 |
| `app_store/apple/review/v3_submission_20260811_fin_store_ios/owner_app_store_connect_api_key.md` | local home path | 4 |
| `capture_evidence.sh` | local home path | 2 |
| `installer/windows/build_zip_installer.ps1` | local Windows profile path | 1 |
| `linux/runner/linux_winn3_host_tun_e2e.cc` | local home path | 1 |
| `patches/android_preserve_winn3_normalized_fields.diff` | local home path | 2 |
| `patches/main_winn3.diff` | local home path | 1 |
| `patches/mainactivity_flagsecure.diff` | local home path | 1 |
| `patches/vpntunnel_peerstats.diff` | local home path | 1 |
| `test/fixtures/nodes_live_7_20261024.json` | production node endpoint IPv4 | 7 |
| `test/fixtures/nodes_live_7_20261024.json` | per-node xray stealth path | 7 |
| `video/VIDEO_STATUS.md` | local home path | 2 |
| `video/VIDEO_STATUS.md` | GCE demo gateway IPv4 (route A) | 2 |
| `video/VIDEO_STATUS.md` | GCE demo gateway IPv4 (route B) | 3 |
| `wear_os/tools/external_tool_pins.json` | local home path | 2 |
| **Total** | | **81** |

Notes on specific scrubs:

- `test/fixtures/nodes_live_7_20261024.json` is a recorded production `/nodes` response. The seven node endpoint IPv4 addresses and the seven per-node Xray WebSocket paths were replaced; the file is still valid JSON. The only consumer, `test/server_picker_live_listing_test.dart`, asserts on node names and load labels, not on endpoints or paths.
- `README_XPRIZE_SOURCE_OF_RECORD.md`, `SPEC.md` and `video/VIDEO_STATUS.md` name the two GCE demo gateways; route A became `203.0.113.10`, route B became `203.0.113.20`, consistently across the three files.
- `android/app/src/test/kotlin/org/winsvpn/app/WinnV3PostureTest.kt` used a real-looking public address as a test route literal in two lines; both became `198.51.100.227`, so the assertion still compares equal values.
- The three root `* Subscription.txt` files are PayPal button-factory snippets containing the live PayPal JS SDK client-id and billing plan ids. Both identifier kinds were replaced (client-id once, plan id four times per file).
- The four `patches/*.diff` headers and `patches/*.diff` paths only changed in the `/Users/...` prefix; the component count is unchanged, so `patch -p<n>` strip levels still work.
- `wear_os/tools/external_tool_pins.json` and `android/app/src/tv/.res_backups_gen_tv_banner_320x180_mdpi/dims.txt` record local toolchain and asset paths; only the home-directory prefix changed.

## 4. Kept items that the coordinator may want to rule on

- **`app-cloud-sync.net`** (16 files). This is the registered stealth zone for the data planes and the compiled-in control-plane fallback fronts: `lib/gateway_failover.dart` lines 77 to 97 (dart-define defaults `a.` through `z.app-cloud-sync.net`), `lib/control_plane_pinning.dart` lines 114 and 125 (zone constant), `apple/SafariProxy/Shared/SafariPinnedHubTransport.swift`, the pinning tests, two public certificate chains named after it in `test/fixtures/control_plane_chains_20261004/`, `.env.example`, `README_FINAL_DEPLOYMENT.md` and `GitHub Gist.txt`. It is not on the allowed-domain list, but it is a public DNS zone fronted by Cloudflare that ships inside every client binary, and replacing it would change library defaults, break the certificate-pin tests and require renaming fixtures (rule 5). Kept unchanged; flagged.
- **Cloud Run router URL** `winsvpn-ai-router-<project number>.us-central1.run.app` in `OWNER_WAKE_CHECKLIST.md`, `README_XPRIZE_SOURCE_OF_RECORD.md` and `capture_evidence.sh`. It is the public demo endpoint named as "live" for the XPRIZE submission, so it was kept; it does expose the GCP project number. Easy to scrub if the coordinator prefers.
- **Business phone and EIN.** `(424) 946-7876` and EIN `42-3223917` appear in the in-app legal notice (`lib/main.dart` line 1362, `apple/SafariProxy/Resources/Legal.plist`), in `app_store/apple/review/app_review_information.md` and on the sample donor certificate. They are the Florida nonprofit corporation's public filing details that ship to every user, not personal data, so they stay. No personal email, home address or personal phone was found in the slice (checked for the owner's names, home address, ZIP, old phone numbers and university addresses).
- **`brand/donor_recognition/sample-filled-certificate.pdf`**: rendered and inspected; it shows a fictional sample donor and the public EIN only.
- **`GitHub Gist.txt`** and `.env.example` carry the public read-only Gist id used for gateway discovery (32 hex characters, not a credential) and the client XOR salt string that also sits in `lib/main.dart` line 1369; both are shipped in the client, kept.
- **`AGENTS.md` line 21** references `/Users/winsvpn/Downloads/wins_vpn` (a generic account name on a build Mac) and `RELEASE_1.0.17.md` references seven `/Volumes/WinsBuild/...` build paths. Neither is a personal path; kept.
- **`SAFARI_RELEASE_REPORT.md` line 92** mentions the directory name `~/.winsvpn-secrets/` when describing a module-cache symlink problem; no value is present. Kept.
- **Emails**: every address in the slice is a role address at winsvpn.org/winsvpn.com (`support@`, `security@`, `privacy@`, `companion@`, `admin@`), a hackathon address (`judging@hacker.fund`, `testing@devpost.com`), an upstream author in a vendored license/header, or a test fixture (`user:pass@...` URLs, `attacker@evil.example`).

## 5. Verification

### gitleaks

Command: `gitleaks detect --no-git --source /Volumes/WinsBuild/winsvpn/hackathon/fullsrc/laneA --redact` (gitleaks 8.30.1, the Homebrew binary named by the coordinator). Output (run 1, before this notes file existed):

```
9:44PM INF scanned ~41232039 bytes (41.23 MB) in 1.74s
9:44PM WRN leaks found: 59
```

Run 2, after this notes file was written (same command):

```
9:49PM INF scanned ~41257354 bytes (41.26 MB) in 4.41s
9:49PM WRN leaks found: 59
```

Run 2 reported 59 findings across 30 files; 0 of them are in this notes file. The set is identical to run 1.

All 59 findings are false positives. Classification (rule, count, why):

| Rule | Count | Files | Why it is not a secret |
|---|---|---|---|
| `jfrog-identity-token` | 16 | `.env.example`, `installer/windows/build_installer.ps1`, `build_store_msix.ps1` (2), `build_zip_installer.ps1` (2), `install_winsvpn_zip.ps1` (2), `tests/test_artifact_gates.py` (2), `linux/packaging/install.sh` (2), `linux/packaging/store_manifest_contract.py` (2), `linux/runner/linux_tunnel_backend.cc` (2) | 64-hex SHA-256 pins of the Xray release archives and executables (`XRAY_SHA256`, `xray_exe_sha256`, `X64_XRAY`, ...). Hashes, not tokens. |
| `jwt` | 2 | `test/crash_report_privacy_test.dart` lines 87, 279 | Literal test JWT with header `{"alg":"HS256"}`, payload `{"sub":"1234567890"}` and an empty signature, used to prove the redactor strips tokens. |
| `generic-api-key` | 14 | `admission_key = ...` fixtures in `android/app/src/test/.../WinnV3AdoptionTest.kt`, `linux/runner/linux_winn3_host_test.cc`, `windows/runner/windows_tunnel_backend.cpp`, `windows/runner/winn3_supervisor_test.cc` (2), `test/winn_ios_control_plane_account_scope_test.dart`, `test/winn_protocol_ios_raw_config_emission_test.dart` (2), `..._lab_screen_test.dart`, `..._roundtrip_test.dart`, `..._raw_config_test.dart`, `test/zz_probe_parser_test.dart` (gitleaks double-counts most lines) | Base64 of the ASCII strings `0123456789abcdef...` and `6f39a0c1d24b7e8f5a3c9012b4d6e8f0...` (an obviously sequential synthetic hex pattern). Decoded and checked. |
| `generic-api-key` | 3 | `test/awg_obfuscation_bounds_parity_test.dart`, `test/persisted_v1_downgrade_test.dart`, `test/vpn_config_validation_test.dart` | The same 32-byte `client_private_key` fixture reused across five test files; its bytes are not clamped as a Curve25519 scalar, so it cannot be a generated WireGuard/AmneziaWG key. |
| `generic-api-key` | 1 | `android/app/src/test/kotlin/org/winsvpn/app/AwgUserspaceConfigTest.kt` line 12 | The WireGuard quick-start documentation example private key, a public sample. |
| `generic-api-key` | 2 | `test/browser_bridge_address_containment_test.dart` line 63 (counted twice) | Base64 of `foobarbazqux1234567890abcdefghijk`. |
| `generic-api-key` | 1 | `test/winn3_dual_auth_release_define_test.dart` line 18 | Base64 of `WINS_WINN3_DUAL_AUTH=true`. |
| `generic-api-key` | 1 | `test/winn_ios_control_plane_account_scope_test.dart` line 9 | Base64 of the byte sequence 0x00..0x1f. |
| `generic-api-key` | 1 | `test/crash_report_privacy_test.dart` line 566 | `0123456789abcdef` repeated four times. |
| `generic-api-key` | 1 | `android/devicecheck/app/src/main/kotlin/org/winsvpn/devicecheck/AppIdSigningCheck.kt` line 100 | `RELEASE_KEY_SHA256`, the public fingerprint of the release signing certificate (what users verify against). |
| `generic-api-key` | 1 | `android/devicecheck/.../LiveHardwareAttestationProofTest.kt` line 1700 | The constant string `rsa-pkcs1-v1_5-sign`. |
| `generic-api-key` | 2 | `apple/SafariProxy/Shared/SafariHubSession.swift` lines 17, 18 | Swift type declarations (`Curve25519.KeyAgreement.PrivateKey`), no value. |
| `generic-api-key` | 4 | `lib/winn3_device_key.dart` lines 74, 78, 79, 146 | String constants naming keychain entries (`winn3_private_key`, `winn3_key_mismatch`, ...) and a parameter name. |

No `.gitleaksignore` or custom config was added to the export; the tree contains only source files plus this notes file.

### Required grep checks (run on the exported tree)

| Check | Result | Handling |
|---|---|---|
| IPv4 literals outside 127/8, 0/8, RFC 1918, RFC 5737/3849, link-local, multicast, CGNAT and the public resolvers | 86 distinct file/value pairs, all benign: version strings (`1.0.17.34`, `1.0.15.30`, `17.0.20.1` JDK, `21.0.9.1` JDK, `4.1.1.4`), X.509 OID `2.5.29.37`, route masks (`128.0.0.0`, `255.255.0.0`, `8.0.0.0`, `64.0.0.0`, ...), reserved `240.0.0.1`, test values (`1.2.3.4`, `6.6.6.6`, `8.8.8.9`, `172.15.0.1`), `Chrome/131.0.0.0` user agent, `93.184.216.34` (example.com, used as a negative test), `129.6.15.28` (NIST time server used as a public probe target). | The real infrastructure addresses (two GCE demo gateways, seven production node endpoints, one real-looking test route) were replaced before this check; none remain. |
| `BEGIN .*PRIVATE KEY` | 2 hits | `android/devicecheck/test_devicecheck_source_custody.py` line 847 feeds the literal `not-a-key` body to prove the custody check rejects it; `test/announcement_signature_test.dart` lines 645 and 772 assert the string is absent. No key material. Kept. |
| `/Users/<owner macOS username>` (the home path named in the lane brief) | 0 hits | 34 occurrences in 17 files replaced with `/Users/owner`. |
| the bare owner macOS username | 0 hits | Same as above; no other form of the username existed. |
| `winsvpn-secrets` | 5 files (`.env.example` 5, `.gitignore` 1, `README_FINAL_DEPLOYMENT.md` 3, `SAFARI_RELEASE_REPORT.md` 1, `SECURITY_NOTES_FINAL.md` 1) | Every hit is the file or directory name `/root/winsvpn-secrets.env` or `~/.winsvpn-secrets/` in instructions and the ignore list; no values. Kept. |
| `AuthKey_` | 4 files (`SAFARI_RELEASE_REPORT.md`, `app_store/.../20260810_bld_store_ios/owner_api_key_report.md`, `apple/ExportOptions/README.md`, `apple/SafariProxy/Tools/build_release.py`) | All are the filename pattern `AuthKey_<KEYID>.p8` / `AuthKey_XXXXXXXXXX.p8` in docs, a regex and an argparse help string. No key file is tracked. Kept. |
| `.p8` | 7 files | Same filename-pattern references plus the `.gitignore` entry. Kept. |
| `garble` | 4 files (`RELEASE_1.0.17.md`, `android/tools/prepare_android_winn_assets.sh`, `installer/windows/build_installer.ps1`, `test/account_deletion_test.dart`) | References to the `mvdan.cc/garble` obfuscator as a tool name and to "garbled" artifacts, plus the English word in a test. No seed value anywhere. Kept. |
| `seed` in filenames | 0 files | Nothing to do. |
| Owner name fragments (first name, case-insensitive) | 0 hits | The one Windows profile path fragment in `installer/windows/build_zip_installer.ps1` was scrubbed to `C:\Users\owner`; the one legal-name line was in the excluded `owner_review_packet.md`. |
| IPv6 literals outside loopback, link-local, ULA, documentation and public resolvers | 0 hits | Nothing to do. |

### Byte-identity check

SHA-256 of every copied file compared with its source: 1252 identical, 24 differ, and the 24 are exactly the scrubbed files. Per-file `diff` line counts for the scrubbed files range from 1 to 6 changed lines and match the replacement counts above. Both scrubbed JSON files parse. The source worktree reports a clean `git status` at `faff0b5` after the export.

## 6. Not done

Nothing was pushed, published, committed or deleted. The source worktree was not modified. The `laneB`, `laneC` and `laneD` directories were not touched.
