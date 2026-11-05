# Win's VPN

Win's VPN is a privacy and anti-censorship VPN from a US 501(c)(3) nonprofit (Win's VPN, part of Winthos AI), built for people on censored and monitored networks. One Flutter codebase ships to Android (phone, TV, Wear OS), iOS, watchOS, macOS, Windows and Linux, with companion extensions for Chrome, Edge and Firefox and a Safari proxy.

This repository is the project's full source tree at release 1.0.17+34, published for the Meta Global AI Developer Hackathon. Only secrets were removed; see [What was removed](#what-was-removed).

**Demo (real app, screen recorded):** https://youtu.be/LkYicl1zkx4
**Downloads:** https://winsvpn.org and https://github.com/winsvpn/winsvpn-downloads

## Built with Meta's Muse Wonder Full

We built Win's VPN with Meta's Muse Wonder Full. The Win's VPN code was audited with Muse Wonder Full, which found and fixed vulnerabilities and bugs that we and other AI models had missed.

## Winn Protocol v3

Our own censorship-resistant transport, written from scratch in Go (`winn_protocol_experimental/`):

- Hybrid post-quantum key agreement: X25519 + NIST ML-KEM-768. Traffic protection: ChaCha20-Poly1305. Signatures: ML-DSA, verified alongside ECDSA P-384 so both must pass.
- The inner session rides over interchangeable outer transports (HTTP/2, HTTP/3, MASQUE with Encrypted Client Hello), so the observable traffic shape can change without changing the session.
- Stateful migration between gateways, admission tags and per-session demux tokens, all ephemeral and cleared at disconnect.
- Winn Protocol v1 remains as a fallback path inside the apps.

Traffic contents, DNS queries and destinations are not collected. The privacy policy ships inside the app and at https://www.winsvpn.org/privacy/.

## Repository map

| Path | What it is |
|---|---|
| `lib/`, `test/`, `assets/`, `pubspec.yaml` | The Flutter app shared by every platform |
| `android/`, `wear_os/` | Android phone, TV and Wear OS runners, tunnel service, Winn engine host |
| `ios/`, `macos/`, `apple/` | iOS, watchOS and macOS runners, packet tunnel extension, Safari proxy (`apple/SafariProxy`) |
| `windows/`, `installer/windows/` | Windows runner, tunnel service, Inno Setup installer |
| `linux/` | Linux runner, tunnel backend, packaging |
| `winn_protocol_experimental/` | Winn Protocol v3 engine, gateways, conformance suite and red-team corpus (Go) |
| `extension/` | Chrome, Edge and Firefox companion extension and its build and leak gates |
| `tools/native_messaging/` | Native messaging host that pairs the extension with the desktop app (6-digit code, per-browser credential, revoke) |
| `server/`, `deploy/`, `router/`, `staging-hub/`, `winn3-nodes/` | Control plane and data plane installers, edge router, staging hub, node records |
| `web/`, `cloudflare/`, `netlify/` | winsvpn.org, its Worker, headers and release manifest |
| `tools/` | Release producers, upload gates, security scanners, store readiness checks and their tests |
| `app_store/`, `play_console_assets/`, `brand/` | Store listings, screenshots, review packets, brand assets |
| `legal/` | License texts, source offer, third-party notices |
| `docs/` | Design records, audits, rulings, evidence, and the project notes that used to live at the root (`docs/project-notes/`, `docs/release-records/`, `docs/billing/`) |
| `docs/EXPORT_NOTES/` | Exactly what was removed or redacted before publishing, per area |
| `evidence/`, `video/`, `patches/`, `localization/`, `models/` | XPRIZE evidence, video scripts, kept patches, website localization contract, support-agent training corpus |

## Building

Toolchains the tree was released with: Flutter (Dart SDK >= 3.2), Go 1.27, Python 3.12 or later for the tooling.

| Component | Command |
|---|---|
| Flutter app | `flutter pub get` then `flutter build apk`, `flutter build ios`, `flutter build macos`, `flutter build windows` or `flutter build linux` |
| Winn Protocol | `cd winn_protocol_experimental && go build ./... && go vet ./... && go test $(go list ./... | grep -v '/cmd/winn3-gateway$') && go test ./cmd/winn3-gateway -run 'TestDerivePublic'` |
| Browser extension | `python3 extension/build.py` (writes Chrome, Edge and Firefox zips under `extension/dist/`) |
| Native messaging host | `cd tools/native_messaging/host && dart pub get && dart test` |
| Windows installer | `installer/windows/winsvpn.iss` with Inno Setup, after a Windows Flutter build |
| Servers | `server/wins_control_plane_setup_ONETOUCH.sh` and `server/wins_core_server_setup_ONETOUCH.sh` (operator values are read from the environment; placeholders mark where they go) |

Prebuilt engine binaries (`.so`, `.dylib`, `.exe`, `.aar`) are build outputs and are not in this repository. The platform runners expect them at the paths named in `docs/EXPORT_NOTES/EXPORT_NOTES_A.md`; build or fetch them before a full platform build. The release gates in `tools/` and `.github/workflows/` reference the private release environment and will not pass unchanged outside it.

## What was removed

This is the real tree, not a sample. Every difference from the private repository is listed in `docs/EXPORT_NOTES/`:

- key material, env files with values, signing and notarization material, owner identity and sign-off records;
- prebuilt engine binaries and a few live-infrastructure console screenshots and raw device logs;
- inside kept files, real server addresses, internal hostnames, SSH aliases, cloud resource ids and local paths were replaced with placeholders such as `NODE_IP_1`, `HUB_IP`, `AI_ROUTER_HOST` and `/Users/owner`. Code logic was not changed.

Every area was scanned with gitleaks and a custom sweep for addresses, keys and paths; the notes list each remaining scanner hit and why it is a false positive.

## Licensing

- Winn Protocol v3 (`winn_protocol_experimental/`): GNU AGPL-3.0-or-later, with a commercial option. See `winn_protocol_experimental/LICENSE` and `legal/release/SOURCE_OFFER.txt`.
- The Win's VPN apps: the end-user license in `legal/release/WINS_VPN_SOFTWARE_LICENSE.txt`.
- Third-party notices: `legal/release/licenses/`.

Publishing this tree for the hackathon does not change those terms. See `LICENSE` at the root for the pointer.

## Security

Report vulnerabilities to security@winsvpn.org. The trusted-contact notice is at https://www.winsvpn.org/trusted-contact/.
