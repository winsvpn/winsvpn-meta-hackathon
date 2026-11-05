# Win's VPN Third-Party Notices And Component Inventory

Version: 2026-08-25.v3
Owner: Win's VPN Inc engineering

This inventory is a release-review starting point. It must be updated with exact versions, hashes, source URLs, and license text before each public release.

Shipped Windows, Android, and Apple embedded Go engines must embed exact
reviewed Go 1.27.1. Official go.dev lists Go 1.27.1 as the current stable
release on 2026-10-06 (released 2026-09-01; the previous stable branch is
go1.26.8). Official go.dev documents macOS 13 Ventura or later for Go 1.27.
WinsVPN also uses macOS 13 as the Apple app deployment floor; that floor
remains project policy even though it matches the current Go toolchain
minimum. Historical Go 1.27.0, 1.26.5 and 1.25.12 patch releases are not
current latest-stable, nor an accepted shipped runtime. The component rows
below that quote Go 1.27.0 or a binary SHA-256 describe the currently
committed builds; they are updated when the go1.27.1 rebuild lands.

## Core Components

| Component | Use | Current License Evidence | Release Action |
| --- | --- | --- | --- |
| Win's VPN application code | Cross-platform application, browser companion, packaging, and service orchestration | Proprietary code owned by or licensed to Win Empire LLC, subject to the customer terms operated by Win's VPN Inc. This does not include separately licensed components. | Ship `WINS_VPN_SOFTWARE_LICENSE.txt`, the controlling master terms, and the app privacy policy. Counsel must approve the proprietary license and company-rights chain before public distribution. |
| Winn Protocol v3 | Primary tunnel engine on Android phone/TV, Apple, Windows, Linux, and the service | First-party code offered under AGPL-3.0-or-later with a separate commercial license. The client currently elects the AGPL notice in its in-app Open source licenses screen. | Ship the full AGPL text and a no-charge Corresponding Source path for the exact build. Bind the source archive URL and SHA-256 in release evidence. A commercial-only binary requires a deliberate, counsel-approved license election and matching in-app text; it cannot silently replace the present AGPL election. |
| Xray-core (Windows/Android/Linux) | TCP/WebSocket stealth fallback runtime | Upstream license file is Mozilla Public License 2.0. Windows `xray.exe` and Android `libxray.so` (arm64-v8a, armeabi-v7a, x86_64) are XTLS/Xray-core **v26.9.30** embedding exact reviewed Go 1.27.0, discovered as the current stable Go release on 2026-08-24. This pin is not the Apple PacketTunnel runtime. | Preserve MPL 2.0 notice and track exact binary/source version. Non-Apple path has no MPL-covered source patch. |
| amnezia-xray-core (Apple PacketTunnel) | In-appex VLESS-WS stealth transport via `WinsXrayVlessWsTransport` / `libwg-go.a` | Mozilla Public License 2.0. Owner-controlled source is `github.com/amnezia-vpn/amnezia-xray-core` **v1.260924.0**, commit `77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3` (module ZIP SHA-256 not yet recorded for this version), plus one hostname-safe patch to MPL-covered `transport/internet/tls/ech.go`. The C API wrapper is **amnezia-libxray v1.0.3**, commit `e8cc06d7427251fa549093e7cc32c28b0f5fbafa`, under MIT. The Apple PacketTunnel source-level pair selected by the owner decision of 2026-10-06 is **amnezia-libxray v1.0.3** with amnezia-xray-core v1.260924.0 (the Apple tag `v3.1.20260814` itself pins v1.0.2 with v1.260724.0; see `apple/EngineArtifacts/README.md` and `tools/test_apple_xray_runtime_hardening.py` for the version-mixed tag evidence). This mixed pairing is **owner-blocked** because it is not an upstream-equivalent stable match. It is not release-verified without exact artifact provenance. MIT attribution applies to the v1.0.3 source compiled for Apple. | Preserve the MPL 2.0 and MIT notices, name the Apple core commit and `ech.go` patch in the in-app source offer, publish the exact modified Source Code Form, and keep XTLS v26.9.30 separate. |
| amneziawg-android `v3.1.20260814` commit `5c16489e2cd9ed3a0a7a27c7445bba5238132f86` | Android phone/TV AWG wrapper and AAR classes/JNI integration | Apache License 2.0. The embedded userspace engine remains the separately licensed amneziawg-go v3.1.20260828 below. | Ship Apache-2.0 and amneziawg-go MIT texts and make the in-app identity match the exact AAR provenance. |
| amneziawg-apple `v3.1.20260814` commit `fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d` | iOS/macOS AWG wrapper v3.1.20260814 embedding amneziawg-go v3.1.20260828 | MIT, copyright WireGuard LLC. The wrapper tag and commit are distinct from the Go engine tag and commit. | Ship the wrapper MIT notice and the separate amneziawg-go MIT notice. Bind both exact identities in the produced-package receipt. |
| AmneziaWG tools `v3.1.20260812` | Bundled Linux `awg` and `awg-quick`; release archive SHA-256 `919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56` | Upstream `COPYING` is GNU GPL v2. The full verified notice is bundled with the Linux archive. | Preserve GPLv2 notice and corresponding-source obligations. Track the exact release archive and executable hashes. |
| AmneziaWG-Go `v3.1.20260828` commit `b5928efb6ca19f0153958460c3d141f04abc5c2e` | Statically linked Linux userspace fallback and user-space server runtime/container | Upstream license file grants broad MIT-style permission and requires preserving copyright/permission notice. The Linux binary is reproducibly built with exact reviewed Go 1.27.0 (current stable on 2026-08-24 per go.dev; official go.dev requires macOS 13 Ventura or later for Go 1.27, and WinsVPN keeps a macOS 13 Apple app deployment floor as project policy) and SHA-256 `5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f`. | Preserve copyright and permission notice. Track exact image/binary/source version. |
| AmneziaWG Windows client `3.1.0`, commit `ca5dd3b983bd19c335ab095ccd21fc2f804ec968` | Windows maintenance helper used for `/uninstalltunnelservice` cleanup; rebuilt with exact reviewed Go 1.27.1, unsigned source-artifact SHA-256 `12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41` | Upstream `COPYING` is MIT. Exact source/module/toolchain provenance is stored beside the vendored helper. The release producer Authenticode-signs and timestamps only its staged copy, then binds the resulting signed hash into the installer. | Preserve the MIT notice and exact source/provenance record. Never replace the rebuilt helper with a Go 1.24.4 copy extracted from an upstream MSI. Require public-trust Authenticode for the shipped copy. |
| AmneziaWG Linux kernel module | Kernel module option where used | Upstream COPYING file is GNU GPL v2. | If distributed or modified, preserve GPLv2 notices and source-offer obligations. Avoid bundling into proprietary installers without counsel review. |
| WireGuard tools | Key/tunnel tooling | Track exact package/source and license for installed distribution package. | Preserve notices where redistributed. Config-only use still needs release inventory. |
| Flutter SDK and Dart packages | App UI/networking/crypto | Track through `pubspec.lock`. | Generate dependency inventory and preserve package licenses in release evidence. |
| `country_flags` 4.1.2 | Cross-platform country-flag image widget; direct Flutter dependency. The package contributes 266 compiled `.si` flag assets and declares `jovial_svg` for rendering. | MIT; copyright Arturo Grau. `pubspec.lock` package SHA-256 `f022d18337f3861f1f4e319b936cb53920de9259f38cb09e169eace9942e2b79`; installed `LICENSE` SHA-256 `cd0268576305886aa32fa26c31787a434761efb0bd0740d20e0434574d66362f`. The installed README credits `jovial_svg`, bgoncharuck, and `flag-icons`. | Preserve the installed MIT notice and the `flag-icons` attribution below in release documentation. Confirm Flutter's generated license registry includes the package notice in each final artifact. |
| `flag-icons` country SVG assets (embedded by `country_flags` 4.1.2) | Source artwork for the compiled flag assets bundled inside `country_flags`. It is asset provenance, not a separately resolved Dart dependency. | MIT; copyright 2013 Panayiotis Lipiridis. `country_flags` 4.1.2 does not declare the upstream `flag-icons` version or commit, so no unsupported upstream revision is asserted; the exact redistributed asset set is bound by the enclosing pub package checksum above. | Preserve the full MIT notice and attribution below. Treat any future `country_flags` upgrade as a new asset-provenance review. |
| `jovial_svg` 1.1.30 | Transitive Flutter dependency used by `country_flags` to render its compiled scalable-image assets. | BSD 3-Clause; copyright 2021, 2022 William Foote. `pubspec.lock` package SHA-256 `53d5ef08fafb28c56131bfd83894221597f522c324fb0f0e6fcbfdcae3b0867d`; installed `LICENSE` SHA-256 `434937a8f39cfc6f12c90c67084eb06be76e4783f6c6f2339bb61741ec64c533`. | Reproduce the BSD notice below in binary documentation/materials and do not imply endorsement. |
| `jovial_misc` 0.10.0 | Transitive utility dependency of `jovial_svg`. | MIT; copyright 2020 Bill Foote. `pubspec.lock` package SHA-256 `065b5240badae6b13472efdea28fffe8baf914a7831361469a95c6456d9b8dc8`; installed `LICENSE` SHA-256 `9504916cb773c5f340870a92fbc1e2d7e634fb83bb2eccb7273b9c893f6a445c`. | Preserve the installed MIT notice through Flutter's license registry and generated release notices. |
| `convert` 3.1.2 | Transitive data-conversion dependency introduced through `jovial_misc`. | BSD 3-Clause; copyright 2015 the Dart project authors. `pubspec.lock` package SHA-256 `b30acd5944035672bc15c6b7a8b47d773e41e2f17de064350988c5d02adb1c68`; installed `LICENSE` SHA-256 `ad6a71997da90924b2cfb1fb47ec46537f70faf469efe016168794ae45ed6888`. | Preserve the installed BSD notice through Flutter's license registry and generated release notices. |
| `flutter_map` 8.3.2 | Interactive labeled map on Android, Windows, and Linux | BSD 3-Clause; copyright 2018-2026 the `flutter_map` authors and maintainers. | Reproduce the BSD notice in binary documentation/materials, keep a distinct application user agent, use normal native HTTP caching, and do not bulk-download or prefetch tiles. |
| `latlong2` 0.10.1 | Geographic coordinate model used by `flutter_map` | Apache License 2.0; upstream package license names Michael Mitterer. | Include the Apache 2.0 license/notice with distributed third-party notices and track the exact resolved version in `pubspec.lock`. |
| OpenStreetMap Standard raster tiles | Labeled city/place map on Android, Windows, and Linux | OpenStreetMap data is licensed under ODbL; the Standard tile service is governed by the OpenStreetMap Foundation tile-usage policy and is not an SLA-backed production service. | Preserve visible `© OpenStreetMap contributors` attribution linked to the copyright page. The Cloudflare Pages Worker exposes a bounded first-party tile route, sends a stable contactable Win's VPN user agent upstream, and caches successful tiles for seven days. Clients never bypass the Worker with direct community-tile requests: a managed provider may fall back to the first-party route, and the first-party route fails closed to the bundled Natural Earth map. Never prefetch or bulk-download. `MAP_TILE_UPSTREAM_URL_TEMPLATE` can select a commercial or self-hosted upstream without exposing its query credential to the app. |
| Apple MapKit | Native iOS and macOS 50-mile IP-area map | Apple system framework and standard Apple map service; no separately redistributed map SDK is bundled. | Keep Apple Maps attribution visible, use only coarse IP-derived centers, and do not request Location Services unless privacy answers and purpose strings are deliberately updated. |
| Cloudflare speed/metadata service | Coarse network map center and user-invoked throughput measurement | HTTPS endpoints at `speed.cloudflare.com`; the app parses only coarse map-center fields and measures transferred bytes. | Disclose Coarse Location, do not retain returned IP/city/postal fields, and retain non-Cloudflare fallbacks where appropriate. |
| Natural Earth II raster | Non-Apple and no-coordinate real-world map fallback | The bundled Natural Earth II shaded-relief raster is public domain and is rendered locally with Flutter's standard image and transformation widgets. | Keep `assets/wallpaper/offline_world_map.webp` bundled and preserve visible Natural Earth attribution wherever this fallback is rendered. |
| Windows native dependencies | Installer runtime support | Track local dependency files under `installer/windows/dependencies`. | Save SHA-256 hashes, vendor URL, license, and redistribution permission. |
| Wintun prebuilt binaries | Windows TUN adapter DLL used through the permitted API | Proprietary Wintun Prebuilt Binaries License. The distributed DLL must remain unmodified and its upstream notices must remain intact. | Ship the exact Wintun terms, preserve the signed binary identity, and do not describe the DLL as GPL or open source. |
| Microsoft Visual C++ Redistributable | Signed Windows prerequisite installer | Microsoft proprietary redistributable. It is a prerequisite, not Win's VPN or open-source code. | Bind publisher, architecture, version, and exact bytes in the Windows artifact gate. Retain owner/counsel evidence that the applicable Visual Studio terms authorize redistribution. |
| Mullvad Windows split-tunnel driver (parked, not distributed) | Historical Windows per-app VPN exclusion implementation | Version 1.3.0.0 is excluded from every release artifact while upstream issue #10738 remains unresolved. The controller source remains for future evaluation, but SYS/CAT/INF and its runtime feature are not shipped or advertised. | Reintroduction requires a newer fixed signed upstream package, exact provenance, and a passing long-duration nonpaged-pool stress test. Destination-based Windows split tunneling remains available. |

## Produced Legal Bundle Contract

`legal/release/LEGAL_BUNDLE_MANIFEST.json` is the canonical package contract.
Every produced package must embed that exact manifest and the platform-specific
file set it selects. The package verifier compares each embedded file with its
repository source byte for byte, validates every recorded SHA-256, and binds the
artifact, legal files, component identities, Flutter notices, contract, and
verifier identity into one deterministic receipt.

Flutter phone, TV, iOS, macOS, Windows, and Linux packages must contain one
valid `flutter_assets/NOTICES.Z`. Its decompressed license registry must name
all direct runtime packages resolved by `pubspec.lock`. Native component
notices are separately registered through the in-app Open source licenses
screen and must identify Winn v3 as primary, Winn v1 as AWG then Xray, and the
exact current component versions in this inventory.

Wear OS contains no VPN engine. Browser packages contain no Winn, AWG, Xray,
or esbuild runtime. Their legal manifests are intentionally narrower; claiming
one of those absent runtimes is a release failure, not harmless over-inclusion.

The canonical source offer for release 1.0.15+30 is
`legal/release/SOURCE_OFFER.txt`. The advertised source archive must be live and
must hash to the exact source identity recorded with the release before any
binary is published. A support mailbox alone is not a substitute for the
AGPL network-source path or MPL executable-form source notice.

## Country Flag Rendering Notices

The following notices are reproduced because the app redistributes the
`country_flags` image assets and renderer. The `country_flags` 4.1.2 package
README specifically acknowledges `jovial_svg`, bgoncharuck, and the
`flag-icons` project as the source of the necessary SVG flags.

### `country_flags` 4.1.2 — MIT

Copyright (c) Arturo Grau.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

### `flag-icons` assets — MIT

Copyright (c) 2013 Panayiotis Lipiridis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

### `jovial_svg` 1.1.30 — BSD 3-Clause

Copyright (c) 2021, 2022 William Foote

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Required Release Checklist

1. Generate SHA-256 hashes for redistributed binaries and installers.
2. Save dependency list from `pubspec.lock`.
3. Save Docker image names/tags/digests used by data-plane setup.
4. Save package versions installed by deployment scripts when practical.
5. Confirm whether any upstream source code was modified.
6. If modified, record the modified files and license obligations.
7. Include third-party notices in the website/download package where practical.
8. Block release if a component license is unknown or conflicts with distribution.
9. Run `tools/verify_release_legal_compliance.py` against the exact produced package and retain its deterministic receipt.
10. Verify the public source archive URL and digest before release; do not publish a source offer that resolves to missing, stale, or different bytes.
11. Confirm the compiled in-app notice strings match the exact component identities selected by the package manifest.

## Trademark And Attribution Notes

- Do not imply AmneziaWG, Xray, WireGuard, Flutter, Google, Apple, Microsoft, Cloudflare, Netlify, PayPal, or other vendors endorse Win's VPN.
- Use vendor names only for factual compatibility, dependency, or attribution statements.
- Use Win's VPN® and Winn Protocol® in customer-facing materials per owner direction while filings are in process; keep trademark filing evidence and counsel or owner approval with release records.
