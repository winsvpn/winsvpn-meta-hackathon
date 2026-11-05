# AmneziaWG engine provenance

Live-verified 2026-08-25 against official GitHub tags, releases, and
commit refs. Latest means the newest version identity discovered now;
tag, commit, archive, and hashes below are then frozen. Builders must
not float dependencies at build time.

Update 2026-10-06 (owner decision: move everything to 0828 together): every
amneziawg-go producer moves to v3.1.20260828 / b5928efb6ca19f0153958460c3d141f04abc5c2e,
committed 2026-08-28T15:48:27Z. amneziawg-tools stays v3.1.20260812. The wrapper
tags (amneziawg-android, amneziawg-apple, amneziawg-windows v3.1.20260814 and
windows-client 3.1.0) stay, because upstream has no wrapper tag that consumes
0828; their go.mod files still require amneziawg-go v3.1.20260814, so wrapper
builds must override that requirement to 0828. Upstream data used: tag and commit
from the GitHub tags API, `git ls-remote`, and sum.golang.org (module zip h1
`D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c=`; go.mod h1
`YoPc6qcOZqD7TXZ1xpedD8Sx3aSKsxN05ZqEFmXDNHk=` is unchanged from 0814). The
0814 to 0828 compare touches only device/receive.go and device/send.go, so the
LF go.mod, go.sum and constants.go hashes below still hold. The archive sha256 was measured on 2026-10-07 (see below); the binary and AAR
hashes that depend on a build are still pending and are listed under BUILD-LANE
in the bump record, except the two server-image binaries recorded in
`server/build_amneziawg_go_server_image.sh`.

Stability is taken only from GitHub Releases. A non-draft, non-prerelease
GitHub Release is a latest stable release. A GitHub tag with no Releases
has no upstream stable or prerelease designation; it is the latest
upstream tag with stability designation unavailable. A version-shaped tag
name is not a stability claim.

## Frozen latest identities

| Component | Official repo | Tag | Commit | Designation | Notes |
| --- | --- | --- | --- | --- | --- |
| amneziawg-go | amnezia-vpn/amneziawg-go | v3.1.20260828 | b5928efb6ca19f0153958460c3d141f04abc5c2e | latest upstream tag; stability designation unavailable | Go engine. No GitHub Releases. Lightweight tag to that commit. Moved 0814 to 0828 on 2026-10-06. |
| amneziawg-tools | amnezia-vpn/amneziawg-tools | v3.1.20260812 | ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 | latest stable GitHub Release | CLI/tools. Different date tag from the Go engine. |
| amneziawg-android | amnezia-vpn/amneziawg-android | v3.1.20260814 | 5c16489e2cd9ed3a0a7a27c7445bba5238132f86 | latest stable GitHub Release | Android wrapper. Its go.mod requires amneziawg-go v3.1.20260814; builds override it to the 0828 engine. |
| amneziawg-apple | amnezia-vpn/amneziawg-apple | v3.1.20260814 | fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d | latest upstream tag; stability designation unavailable | Apple wrapper. No GitHub Releases. Tree 24183de0cc22b957ff9e34ac3494a80f515ac565. |
| amneziawg-windows | amnezia-vpn/amneziawg-windows | v3.1.20260814 | e90531d15802cb976773f3b63443bc281f738ca3 | latest upstream tag; stability designation unavailable | Windows library. Its go.mod requires amneziawg-go v3.1.20260814; builds consume the 0828 engine. No GitHub Releases. |
| amneziawg-windows-client | amnezia-vpn/amneziawg-windows-client | 3.1.0 | ca5dd3b983bd19c335ab095ccd21fc2f804ec968 | latest stable GitHub Release | Windows GUI client. Not the Go engine tag. |

Do not copy a tag, commit, or hash from one row onto another row.

## Frozen archives and hashes

Go engine GitHub archive
`https://github.com/amnezia-vpn/amneziawg-go/archive/b5928efb6ca19f0153958460c3d141f04abc5c2e.tar.gz`

- sha256 `10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4`, measured 2026-10-07 by the server build lane from both `github.com/amnezia-vpn/amneziawg-go/archive/<commit>.tar.gz` and `codeload.github.com/amnezia-vpn/amneziawg-go/tar.gz/<commit>` (identical bytes, 132779 bytes; the tar pax comment is the commit). Upstream publishes no digest for source archives; the commit itself is cross-checked against `proxy.golang.org/.../@v/v3.1.20260828.info` (Origin.Hash). The previous commit 1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1 (0814) archive hash was `bd49bf8ea693b8799d0fd291794bb4e2c8f2c18187ae182c155d8ff3743c1a1c`.
- LF git-blob go.mod `9fd0084da2acc4f96225daee85c0f866a0ec1079d5bdc4cf98c50e8a8fa0baf6`
- LF git-blob go.sum `eab202288b6f879fe1f6b0d9da0c528cfb310d74a7a4d409c7268c2b26b98a0a`
- Windows CRLF go.mod `e447b49513d1fc452fa7cb2f87b15c40b88ab6f0656e22b4eccdfe238fa623e4`
- Windows CRLF go.sum `fbec66bcbe1cf3603eb5b0f6c7c2041aea6749dc8c1d36b91726a7a479df4719`
- LF device/constants.go `5989645bff55a3ce3f21271a6942361050eff078d17a87c718136bebf156714a`

amneziawg-tools GitHub source tarball
`https://github.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/v3.1.20260812.tar.gz`

- sha256 `dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493`

ubuntu-22.04-amneziawg-tools.zip from the same tools tag (not the source tarball):

- sha256 `919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56`

Windows client 3.1.0 amd64 MSI (release 374470280, asset 523857174):

- sha256 `a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b`

## Platform map

Windows Go engine
`tools/build_windows_awg_engine.ps1` and `windows/awg_engine/go.mod`
clone and require amneziawg-go v3.1.20260828 / b5928efb6ca19f0153958460c3d141f04abc5c2e.
The Windows builder verifies CRLF go.mod/go.sum bytes.

Windows client and library
`tools/build_windows_amneziawg_client.ps1` freezes client 3.1.0 /
ca5dd3b983bd19c335ab095ccd21fc2f804ec968 and library v3.1.20260814 /
e90531d15802cb976773f3b63443bc281f738ca3. The client tag is a different
upstream release from the Go engine tag. The library tag stays aligned
with the Go engine tag. Organization-name matching is only a secondary
Authenticode check. Frozen leaf certificate SHA-1 thumbprints:

- Privacy Technologies OU: `141D90A1BA8F61863FBEDDF7DD1D66C1D1E0B128`
- WireGuard LLC: `DF98E075A012ED8C86FBCF14854B8F9555CB3D45`

The official MSI, official awg.exe, official wintun.dll, reproducibly
rebuilt unsigned product-maintenance amneziawg.exe, and schema-v2
provenance publish as one generation. The upstream MSI GUI amneziawg.exe
is verified but not published. The committed x64 cache holds the official 3.1.0 MSI
(`a1b48ea8...de8b`) and awg.exe (`272badac...ed12`) from the same 2026-10-09
producer run as the helper. The rejected 2.0.1 MSI/awg.exe identities stay
pinned as blockers, never as 3.1 inputs.

Linux tools (linux-arm64 CLI)
`tools/build_linux_arm64_awg.sh` builds awg/awg-quick from tools
v3.1.20260812 source. It does not build amneziawg-go. Companion Go
engine pins are recorded so the Ubuntu zip hash and the Go archive hash
cannot be mistaken for the tools source tarball.

Linux/server Go engine
`server/build_amneziawg_go_server_image.sh` already freezes Go
v3.1.20260828 / b5928efb6ca19f0153958460c3d141f04abc5c2e and tools
v3.1.20260812. That producer file is hashed by the GCP/server installers
and is not rewritten when its pins already match the frozen latest Go tag.

Apple wrappers
`tools/build_apple_wg_go_bridge.sh` freezes amneziawg-apple v3.1.20260814 /
fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d and the companion Go engine
v3.1.20260828 / b5928efb6ca19f0153958460c3d141f04abc5c2e. The Apple
wrapper commit is not the Go engine commit. The owner-selected pair (decision of 2026-10-06)
is amnezia-libxray v1.0.3 / e8cc06d7427251fa549093e7cc32c28b0f5fbafa and
amnezia-xray-core v1.260924.0 / 77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3.
The Apple source itself pins amnezia-libxray v1.0.2 with
amnezia-xray-core v1.260724.0, so the pair stays owner-blocked until the
closure is rebuilt and attested.
The hostname-safe core carries the reviewed ech.go example-URI patch.
Non-Apple Xray stays XTLS/Xray-core v26.9.30. Delivered iOS/macos/simulator
`libWinsXrayVlessWsTransport.dylib` files are fail-closed bound to the
SHA-256 of `apple/EngineWrappers/WinsXrayVlessWsTransport.m` and to
`LibXraySetSockCallback` / `dup2` / `getifaddrs` / `setsockopt` by
`apple/EngineArtifacts/apple_xray_vless_ws_engine_provenance.json`.
Compiling the wrapper source in a test harness does not bind a staged
dylib. Mutating that source after artifact creation is rebuild-required.

Android
Official `amnezia-vpn/amneziawg-android` v3.1.20260814 /
5c16489e2cd9ed3a0a7a27c7445bba5238132f86, plus the in-tree JNI overlay
under `tools/amneziawg_android_official_jni/`. Go 1.27.1. App pin NDK r30
`30.0.16248370`. The wrapper's own go.mod requires amneziawg-go v3.1.20260814;
the builder raises that one requirement to v3.1.20260828
(b5928efb6ca19f0153958460c3d141f04abc5c2e), and every committed
`libam-go.so` slice links it (`go version -m`: go1.27.1, dep
`h1:D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c=`). Under NDK r30 the
builder also adds `-Wno-error=deprecated-declarations` to the official
CMake compile options, because r30 bionic deprecates `strtok()` and the
unchanged amneziawg-tools `wg-quick/android.c` otherwise fails `-Werror`.
Rebuilt 2026-10-09 twice from separate work roots; both AARs byte-identical.
Official source does not ship
`awgUpdateTunnelPeers` or four-arg `awgTurnOn(..., uapiPath)`. Those are
ported onto official api-android.go / jni.c. Official IpcSet is UAPI-only,
so INI is adapted in uapi_adapt.go and AwgUserspaceConfig. Committed AAR
`android/app/libs/amneziawg.aar` sha256
`e4cc912ec3f1e63e9d46c47063fefb908837253c888bb771ee11a5115df274d6`.
The archived zaneschepke/wgtunnel v2.3.7 fork is historical only.

Winn experimental userspace engine
`winn_protocol_experimental/scripts/build_winn_awg_engine.sh` consumes
the same frozen latest upstream Go engine tag/commit as shipping
Windows/Linux/Apple paths, then applies
`patches/amneziawg-go-fast-handshake-v1.patch`. That
patch still applies to v3.1.20260828 constants.go (DefaultUdpWindow is
unchanged by the patch). The retired pre-v3 commit
c1e9bb3758e71bb1adc402598465565bfc9663fd is refused.

## Android keepalive note

Official amneziawg-go/v3 marks keepalives with elem.isKeepalive and still
runs them through RoutineEncryption, which applies elem.padding (S4) to
every outbound element. The old wgtunnel fork skipped S4 on
keepalive-sized packets. Shipping profiles still use S4 = 0, so the two
paths agree until a nonzero S4 is served.

## Re-derive it yourself

```bash
# Official tags and releases (read-only). Go has tags and no Releases.
curl -fsSL https://api.github.com/repos/amnezia-vpn/amneziawg-go/tags?per_page=5
curl -fsSL https://api.github.com/repos/amnezia-vpn/amneziawg-go/releases?per_page=5
curl -fsSL https://api.github.com/repos/amnezia-vpn/amneziawg-tools/releases/latest
curl -fsSL https://api.github.com/repos/amnezia-vpn/amneziawg-windows-client/releases/latest

# Recipe pins
grep -n 'AWG_GO_TAG\|engineVersion\|upstream_tag\|AMNEZIAWG_GO_TAG\|AWG_ANDROID_TAG' \
  tools/build_amneziawg_android_engine.sh \
  tools/build_windows_awg_engine.ps1 \
  tools/build_linux_arm64_awg.sh \
  tools/build_apple_wg_go_bridge.sh \
  winn_protocol_experimental/scripts/build_winn_awg_engine.sh \
  server/build_amneziawg_go_server_image.sh

python3 tools/test_latest_awg_release.py
```
