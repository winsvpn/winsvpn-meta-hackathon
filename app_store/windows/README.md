# Win's VPN Microsoft Store / website Win32 package

Last reviewed: 2026-08-25

This folder is Windows x64 store metadata for release `1.0.17+34`
(product `1.0.17`, four-part `1.0.17.34`). Identity is bound to
`pubspec.yaml` and `docs/rulings/RELEASE_IDENTITY_MAP_20260824.json`.
It contains no credentials, PFX files, Azure signing metadata, Partner
Center tokens, account numbers, or node addresses.

The production Store route is the Authenticode-signed offline Inno Setup
EXE, not Store-signed MSIX. The required Windows upload matrix is four
distinct candidates: website x64 `WinsVPN-Setup.exe`, Partner Center x64
`WinsVPN-PartnerCenter.exe`, website ARM64 `WinsVPN-Setup-arm64.exe`, and
Partner Center ARM64 `WinsVPN-PartnerCenter-arm64.exe`. This folder holds
x64 listing copy. Native ARM64 remains `pending-owner-evidence` and is
not satisfied by an x64 EXE. Production MSIX packaging stays fail-closed;
a development identity is not a `1.0.17+34` upload target.

Current owner state is `OWNER-BLOCKED: ABSENT` for Authenticode leaf,
Partner Center enrollment, reviewer account, reviewer routes, versioned
HTTPS URL, installer SHA-256, listing screenshots, export-compliance
answers, and IARC/age-rating answers. There is no current signed
`1.0.17+34` candidate. Producer output paths are not candidate bytes.

Authoritative Windows producers:

- `installer/windows/build_installer.ps1`
- `tools/windows_cross_store_artifact_gate.py`
- `installer/windows/store/certification-notes.md`

Native Winn v3 is primary. Winn v1 AWG then Xray fallback is the ordered
compatibility path after a served Winn v3 attempt. Those engines must
ship in the x64 installer.

Private Flutter split-debug symbols stay under
`.artifacts/private-release-symbols/windows/x64/1.0.17+34` with distinct
`manifest-website.json` and `manifest-partner-center.json` receipts and
are not uploaded. `submission_approved` and `upload_authorized` stay
false until the owner supplies a current signed x64 receipt. This
package never uploads.
