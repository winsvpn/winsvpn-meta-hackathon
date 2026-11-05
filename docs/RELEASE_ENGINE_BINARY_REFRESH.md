# Embedded engine binary refresh (M-12 follow-up / M-1 / M-11 remediation)

Status: **SOURCE/TOOLCHAIN RESOLVED 2026-07-24; EXACT GO 1.27.1 GATE
2026-10-06 (committed binaries still embed go1.27.0 until rebuilt).** Every embedded Go binary this repo ships (Xray on
Windows/Android/Linux, AmneziaWG's Android AAR, and the Windows AmneziaWG
maintenance helper) was rebuilt from source against a pinned Go toolchain
in the 2026-07-24 pass. On 2026-08-24 the owner latest-stable policy froze
the reviewed runtime at exact Go 1.27.0 (released 2026-08-19). On
2026-10-06 the owner bump-everything-to-latest decision moved it to exact
Go 1.27.1: official go.dev lists Go 1.27.1 as the current stable release
(released 2026-09-01).
`tools/verify_embedded_engine_runtime_versions.py` now fails closed unless
every inspected Windows, Android, and Apple embedded Go engine reports
exactly `go1.27.1`, so it stays red until the binaries below are rebuilt.
Older 1.27.0 / 1.26.5 / 1.25.12 builds are historical, not
accepted. Official go.dev documents macOS 13 Ventura or later for Go 1.27
(https://go.dev/doc/go1.27). WinsVPN also uses macOS 13 as the Apple app
deployment floor; that floor remains project policy even though it matches
the current Go toolchain minimum. This document
originally tracked the unresolved finding; it now records what was
actually done, so a future reader does not have to reverse-engineer
intent from the diff alone.

The Windows helper's reproducible repository artifact is deliberately
unsigned and hash/provenance pinned. `installer/windows/build_installer.ps1`
signs its staged release copy with the mandatory Win's VPN Authenticode
identity, timestamps it, verifies the public trust chain, and binds the
post-signing hash into the installer. The Samsung build host used for this
refresh had no public-trust certificate or Microsoft Artifact Signing
configuration, so no signed release was fabricated; production packaging
continues to fail closed until an approved signing identity is configured.

## What was verified (2026-07-22), and how

The CVE facts in this section are historical. They were checked directly
against `pkg.go.dev/vuln`, NVD, and `go.dev/doc/devel/release` on
2026-07-22, and against this repo's then-committed binaries -- not copied
from any AI-generated audit report. They motivated the 2026-07-24 rebuild.
They are not the 2026-08-24 acceptance rule.

Go stdlib CVEs affecting old toolchains (historical, 2026-07-22):

| Advisory | CVE | Package | Fixed in |
|---|---|---|---|
| GO-2026-4866 | CVE-2026-33810 | crypto/x509 (DNS-constraint bypass) | 1.26.2 |
| GO-2026-4870 | CVE-2026-32283 | crypto/tls (KeyUpdate DoS) | 1.25.9 / 1.26.2 |
| GO-2026-4981 | CVE-2026-33811 | net (cgo resolver double-free) | 1.25.10 / 1.26.3 |
| GO-2026-5037 | CVE-2026-27145 | crypto/x509 (VerifyHostname DoS) | 1.25.11 / 1.26.4 |
| (1.26.5/1.25.12 release) | CVE-2026-39822, CVE-2026-42505 | os.Root escape, TLS ECH leak | 1.26.5 / 1.25.12 |

On 2026-07-22, Go 1.26.5 and 1.25.12 were the then-current patch releases
on their branches. That "latest on branch" fact is historical. Official
go.dev later shipped Go 1.27.1 as the current stable release; 1.26.5 is
not latest and is not accepted for shipped engines.

Embedded Go versions **before** this remediation (the vulnerable state this
document originally flagged):

| Artifact | Path | Embedded Go | Status |
|---|---|---|---|
| Xray (Windows) | `installer/windows/dependencies/xray.exe` | go1.26.1 | Vulnerable to all 4 CVEs above |
| Xray (Android) | `android/app/src/main/jniLibs/*/libxray.so` | go1.26.1 | Vulnerable to all 4 CVEs above |
| Xray (Linux) | fetched at build time by `tools/build_linux_release.sh` | go1.26.1 (same upstream release) | Vulnerable to all 4 CVEs above |
| AmneziaWG (Android AAR) | `android/app/libs/amneziawg.aar` (`jni/*/libam-go.so`) | go1.24.4 | EOL branch; vulnerable to 3 of 4 (not the 1.26-only x509 bypass) |
| AmneziaWG maintenance helper (Windows) | `installer/windows/dependencies/amneziawg.exe` | go1.24.4 | M-11: EOL branch; extracted from the upstream MSI and silently overwritten on refresh |

Embedded Go versions **after** the 2026-07-24 rebuild, then frozen to exact
Go 1.27.0 on 2026-08-24 (the committed/present state; the gate in
`tools/verify_embedded_engine_runtime_versions.py` now requires exact
Go 1.27.1 on every build path, so these rows await the go1.27.1 rebuild):

| Artifact | Path | Embedded Go | How it's built now |
|---|---|---|---|
| Xray (Windows) | `installer/windows/dependencies/xray.exe` | go1.27.0 | Built from source by `tools/build_xray_engine.sh`; unsigned SHA-256 `fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224`; hash pinned as `WINDOWS_XRAY_EXE_SHA256` |
| Xray (Android) | `android/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/libxray.so` | go1.27.0 | Built from source by `tools/build_xray_engine.sh`; hash pinned per-ABI as `ANDROID_XRAY_BINARY_SHA256` |
| Xray (Linux) | built at release time by `tools/build_linux_release.sh` | not a committed binary this gate inspects | `tools/build_linux_release.sh` calls `tools/build_xray_engine.sh` instead of downloading a prebuilt archive. Historical 2026-07-24 Linux rebuilds used then-current Go 1.26.5; that pin is not an acceptance rule here. |
| AmneziaWG (Android AAR) | `android/app/libs/amneziawg.aar` (`jni/*/libam-go.so`, all 4 ABIs) | go1.27.1 | `tools/build_amneziawg_android_engine.sh` builds official `amnezia-vpn/amneziawg-android` `v3.1.20260814` / commit `5c16489e2cd9ed3a0a7a27c7445bba5238132f86` with `amneziawg-go/v3` overridden to `v3.1.20260828` / commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`; AAR SHA-256 `e4cc912ec3f1e63e9d46c47063fefb908837253c888bb771ee11a5115df274d6` (rebuilt 2026-10-09 with NDK 30.0.16248370), pinned as `ANDROID_AWG_AAR_SHA256` |
| AmneziaWG maintenance helper (Windows) | `installer/windows/dependencies/amneziawg.exe` | go1.27.1 | `tools/build_windows_amneziawg_client.ps1` rebuilds tag `3.1.0` / commit `ca5dd3b983bd19c335ab095ccd21fc2f804ec968`; unsigned SHA-256 `12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41` (rebuilt 2026-10-09 on a Windows 11 x64 host with Go 1.27.1 under PowerShell 7; two clean builds byte-identical); the release producer signs only the staged copy and binds its resulting hash |
| Apple WireGuard/Xray Go bridge | `.artifacts/apple-wg-go/{macosx,iphoneos,iphonesimulator}/libwg-go.a` when present | go1.27.1 exact | Gitignored build output from `tools/build_apple_wg_go_bridge.sh`. Official go.dev requires macOS 13 Ventura or later for Go 1.27; WinsVPN also keeps a macOS 13 Apple app deployment floor as project policy. |

All three Xray artifacts are built from the **same pinned upstream source
commit**, `XRAY_ENGINE_TAG="v26.9.30"` / `XRAY_ENGINE_COMMIT` in
`tools/verify_deployment_supply_chain.py` (mirrored into
`tools/build_xray_engine.sh`) -- so this was one rebuild recipe shared by
Windows/Android/Linux, not three independent ones. The AmneziaWG Android
engine is built from the official `amnezia-vpn/amneziawg-android`
`v3.1.20260814` tag and exact commit recorded above. Its userspace engine is
the official `github.com/amnezia-vpn/amneziawg-go/v3` module at
`v3.1.20260828` (commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`). The wrapper's own
go.mod still requires v3.1.20260814, so the build overrides that requirement.

This repo's own from-source AmneziaWG-go userspace fallback builders (not
Xray, not the Android AAR) keep their own toolchain pins outside this
gate. Those builder pins are not a substitute for the shipped-binary check:
this gate independently requires exact `go1.27.1` in the Windows/Android
binaries it inspects and in any Apple `libwg-go.a` slice already on disk.

The Windows maintenance helper is a different program from the product-owned
`winsvpn_awg_engine.exe`: it retains upstream's
`/uninstalltunnelservice TUNNEL_NAME` command for safe upgrade/uninstall
cleanup. The rebuilt helper is bound to official Windows client 3.1.0, commit
`ca5dd3b983bd19c335ab095ccd21fc2f804ec968`, and the matching
`amneziawg-go/v3` v3.1.20260828 engine. A high-integrity probe against a randomized
nonexistent tunnel returned the expected Windows service-not-found error and
left the complete Windows service-name set unchanged.

## Xray's upstream version: owner decision 2026-10-06 (bump to the newest tag)

Until 2026-10-06 this tree held Xray-core at **v26.3.27**, the only tag that
GitHub `/releases/latest` designates stable (non-draft, non-prerelease). Every
later tag (v26.4.13 through v26.9.30) is a GitHub pre-release: upstream ships a
stream of pre-releases, each body points at the next ("See <next tag>"), and
promotes one with full notes only occasionally. The 2026-07-24 remediation
fixed the *Go toolchain* embedded in the binary (M-1) without changing the
Xray protocol/config version.

**Owner decision 2026-10-06** (`.agent/debates/_decisions/owner_decision_bump_xray_latest_20261006.md`):
"bump Xray to the latest too". Every Xray pin now tracks the newest upstream
tag, **v26.9.30** (published 2026-09-30, commit
`b26a91de4f3294e26a0ad0a970b81a386a41f789`), even though upstream flags it
pre-release. Consequences recorded here so a future reader does not mistake
this for a stable-channel pin:

- `/releases/latest` still returns v26.3.27, so
  `tools/verify_deployment_supply_chain.py` verifies Xray against the newest
  non-draft release in the `/releases` listing (`OWNER_APPROVED_PRERELEASE_TRACKING`)
  instead of `/releases/latest`.
- The server archive digest is the upstream-published `.dgst` SHA2-256
  `f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e`
  (identical to the GitHub API asset digest). The extracted-binary SHA-256
  is not published upstream; it was computed on 2026-10-07 in the server build
  lane from the verified zip (`unzip -p Xray-linux-64.zip xray | sha256sum`)
  and is `96efb28b8b2086275598dc46e73b5dc340da948b4e1ccc4f1719f83f67b793a7`
  (xray 38088828 bytes, ELF x86-64, statically linked). The linux-arm64 zip
  (`.dgst` SHA2-256 `9886f077f9fd8e6713b84c377c1c7db4e53b9bfa8c276a5bd12561139522b473`)
  holds an `xray` of 35586172 bytes with SHA-256
  `d16ca768110de6ed098dfc2e9068cbdadf886c9b9715671ee252b1339a50452d`; the
  server installers pin only the linux-64 binary.
- Upstream v26.9.30 changes server-visible defaults (Freedom outbound
  `finalRules` default safety policy, refusal of plain VLESS/Trojan outbounds
  to public addresses, `trustedXForwardedFor`). The generated Xray configs
  need the changes listed in the Xray config change set that accompanies this
  bump; the pin alone is not sufficient.
- The embedded Go version of the official v26.9.30 zip is not verified here
  (its `go.mod` declares `go 1.27`); the shipped client engines continue to be
  rebuilt from source with exact Go 1.27.1.

Apple PacketTunnel Xray is a separate owner-controlled pin, not this XTLS
tag: `amnezia-xray-core` `v1.260924.0` commit
`77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3` with a hostname-safe ech.go
patch, called through `amnezia-libxray v1.0.3` (commit
`e8cc06d7427251fa549093e7cc32c28b0f5fbafa`). That mixed pairing is
owner-blocked (not an upstream-equivalent or stable match). Do not
treat Apple v1.260924.0 as the XTLS tag. The Apple fork does not follow the
2026-10-06 bump to v26.9.30: owner decision 2026-10-06 moved the Apple pins to
the newest available fork pairing instead. `amnezia-xray-core` `v1.260924.0`
(2026-09-24) still merges upstream only up to Xray-core v26.7.28, and
`amnezia-libxray` `v1.0.3` (2026-08-21) itself still replaces core with
`v1.260728.0`. No Apple fork release based on v26.9.30 exists.

## Gate: `tools/verify_embedded_engine_runtime_versions.py`

This script inspects the Go version actually embedded in the committed
Windows/Android Xray and AmneziaWG binaries (via `go version -m` / string
scan) and in any present Apple `libwg-go.a` slices. It fails non-zero unless
every inspected engine is exactly `go1.27.1`. It rejects 1.27.0, 1.26.7,
1.26.5, 1.27rc, 1.27.2, missing files, missing version strings, and
malformed tokens. Discovery date for the current stable pin: 2026-10-06,
from official go.dev. Official go.dev documents macOS 13 Ventura or later for Go
1.27; WinsVPN also uses macOS 13 as the Apple app deployment floor. That
floor remains project policy even though it matches the current Go toolchain
minimum.

The gate is wired into every release path so an old or unreviewed engine
binary cannot ship silently:

| Release path | Wired at |
|---|---|
| `tools/local_release_gate.ps1` (Windows+Android local coordinator) | `Invoke-Gate "Embedded engine (Xray/AmneziaWG) Go runtime freshness"`, immediately after the supply-chain-pins gate and before the Android/Windows build gates |
| `tools/public_release_gate.ps1` (pre-publish evidence gate) | Immediately after the release-input-index/website-fingerprint passes, before the QUERY_ALL_PACKAGES check |
| `tools/build_linux_release.sh` (both the direct entry point and the WSL neutral-stage delegate, `run_from_neutral_wsl_stage`) | Right after acquiring the build lock, before `release_dependency_freeze.py verify-index` |
| `tools/build_android_release.ps1` (Windows-native Android producer) | Inside `Initialize-FormalBuildReceipts`, before its `verify-index` call |
| `tools/build_android_release_macos.sh` (macOS Android producer, also invoked by `build_android_release.ps1` when running on macOS) | Inside `initialize_receipts`, before its `verify-index` call |
| `installer/windows/build_installer.ps1` (canonical Windows installer producer) | `Assert-EmbeddedEngineRuntimeFreshness`, called right after `Assert-ReleaseInputIndexUnchanged` inside the build-lock-held main flow |
| `tools/build_apple_release_candidates.sh` (Apple release-candidate coordinator) | Inside `begin_receipts`, before its `verify-index` call |

Also independently verified by `tools/verify_deployment_supply_chain.py`,
which checks (in addition to the runtime-version gate above) that the
from-source build scripts themselves have not drifted from their reviewed
commit/tag/Go-version pins, and that the committed
`android/app/libs/amneziawg.aar` matches `ANDROID_AWG_AAR_SHA256`.

## Action items

1. **Done 2026-10-06 by owner decision, build lane pending:** Xray moved to
   the newest tag v26.9.30 (a GitHub pre-release). Remaining build-lane work:
   rebuild the Windows/Android/Linux client engines from the new pinned
   commit and refill `WINDOWS_XRAY_EXE_SHA256`, `ANDROID_XRAY_BINARY_SHA256`,
   the Linux `XRAY_SHA256_AMD64`/`XRAY_SHA256_ARM64` literals (the server
   extracted-binary SHA-256 was filled 2026-10-07 by the server build lane).
   Re-evaluate when
   upstream promotes a non-prerelease.
2. **Recurring:** before each release freeze, verify that official
   `amnezia-vpn/amneziawg-android` and `amneziawg-go/v3` still resolve to the
   reviewed stable generation, then rebuild and re-run the pinned-source and
   JNI conformance gates if either selected tag changes.
3. **Recurring:** whenever the reviewed Go toolchain version pinned across
   `tools/build_xray_engine.sh`, `tools/build_amneziawg_android_engine.sh`,
   `tools/build_windows_awg_engine.ps1`,
   `tools/build_windows_amneziawg_client.ps1`, and the Apple native-engine
   builder is bumped, re-run the applicable source builder, update the
   corresponding `*_SHA256` pins, and confirm
   `tools/verify_embedded_engine_runtime_versions.py` still passes against
   exact reviewed `go1.27.1` or the newly reviewed exact version.
4. **Release-signing prerequisite:** configure either Microsoft Artifact
   Signing metadata/identity or a current public-trust code-signing
   certificate in the Windows certificate store. Do not use a self-signed
   certificate or pass a PFX password on the command line. The release
   producer intentionally refuses to publish without this prerequisite.
