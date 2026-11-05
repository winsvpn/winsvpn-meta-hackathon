# Win's VPN Desktop Store Release Readiness

Last reviewed: 2026-08-25

This note tracks the Windows and Linux store-facing release posture for the current desktop builds. It is an engineering checklist, not legal advice.

## Shared Store Build Behavior

- The desktop app label is `Win's VPN`.
- `Buy Premium Access` opens the official public purchase section at `https://winsvpn.org/#get` by default instead of listing direct PayPal plan buttons inside the app.
- Direct in-app plan links remain available only for intentional sideload builds compiled with `--dart-define=WINS_ENABLE_EXTERNAL_PAYMENT_LINKS=true`.
- The app should not collect card data directly. Payment pages should identify PayPal or any future processor as the payment provider.
- VPN transport, legal acceptance, no-log disclosure, power-management messaging, free-server gating, referral sharing, and split-tunnel UI are shared with the Android release code where the platform supports them.
- Windows and Linux remain separate freeze platforms. A complete `RELEASE_INPUT_INDEX.json` also binds Wear OS and browser-extension source inputs so a desktop-only native change cannot be used as Wear or extension release evidence. See `docs/CROSS_STORE_RELEASE_CHECKLIST.md`.

## Microsoft Store

Current source used for this pass: Microsoft Store Policies version 7.19, section 10.8 Financial Transactions.

Release posture for this version:

- This is a non-game PC product. Microsoft policy currently allows non-game PC products to use either a secure third-party purchase API or Microsoft Store in-product purchase APIs for in-app purchases of digital goods or services.
- If Win's VPN keeps the website/PayPal purchase path in the Windows Store build, disclose the secure third-party payment flow in Partner Center and in the product description.
- If Microsoft certification treats the VPN subscription as requiring Microsoft commerce for the submitted package, build a Microsoft Store commerce variant before submission rather than enabling direct PayPal plan buttons.
- The intended direct website installer is an Inno Setup Win32 installer, but no current signed website candidate is retained. For Store submission, prepare the package type accepted by Partner Center for the chosen listing path, and perform a clean install, connect, disconnect, update, and uninstall test on a fresh Windows 11 VM.

Windows submission checklist:

- Company developer account in Partner Center.
- Valid privacy policy, support URL, legal terms URL, and no-refund disclosure.
- Accurate age rating and category.
- Clear disclosure that payment is handled by PayPal or future processor and that Microsoft is not the donation fundraiser when donations are shown.
- Code signing or Store packaging requirements completed for the selected package type.
- Admin privilege need is explained because setup installs VPN tunnel
  dependencies and a narrow privileged service; the Flutter UI remains an
  ordinary `asInvoker` process.
- Clean-machine tests cover direct Winn Protocol, fallback transport, disconnect cleanup, uninstall cleanup, and network-change recovery.

### Live account evidence (2026-07-18)

The authenticated Partner Center session currently exposes only account
settings. Under **Programs**, Windows appears under **Other programs** with
**Get started**; there is no Windows workspace or existing Store developer
enrollment. The Microsoft Store developer portal states that company
registration is now free but requires Microsoft Entra work-account sign-in and
company verification. Its sign-in flow presents a saved personal Microsoft
account and an unrelated school work account; neither proves a Win's VPN
organization tenant or completed company verification.

The browser was left at the Microsoft account chooser. No account was selected,
no enrollment was created, and no legal, identity, or payment form was
submitted. Account selection/authentication and organization identity
verification remain user-held actions. Even completed Store enrollment would
not waive the public-trust signature requirement for the feature-complete
Win32 EXE described below.

### Production decision: signed Win32 EXE

Windows per-application exclusions are disabled consistently across all Windows
release formats. The previously reviewed Mullvad 1.3.0.0 kernel driver is not
shipped while upstream issue #10738 remains unresolved. Destination-based split
tunneling remains available without a kernel split-tunnel driver.

The production route is therefore the existing standalone/offline Inno Setup
EXE, signed with Azure Artifact Signing or an OV certificate whose chain reaches
the Microsoft Trusted Root Program. The same exact signed installer may be used
for the website and listed through Partner Center's non-gaming Win32-installer
path. Microsoft does not re-sign EXE/MSI submissions. Partner Center requires an
immutable versioned HTTPS direct URL, a silent install (UAC is allowed), no
downloader stub, and valid signatures on the installer and all contained PE
files. Use `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-` for certification.

The builder preserves the exact pinned upstream dependency bytes, signs a staged
copy of the otherwise unsigned Xray PE, signs every application EXE/DLL, and
uses Inno's SignTool integration so both Setup and its generated uninstaller are
signed and timestamped. It also extracts the pinned AmneziaWG MSI and verifies
the signatures on `amneziawg.exe`, `awg.exe`, and `wintun.dll`. The final
payload manifest is release-eligible only when all loose PE signatures validate,
self-signed/private roots are rejected, and each chain terminates in Windows
AuthRoot or the explicitly pinned Microsoft 2010/2011 system roots.

The Windows producer fails if Mullvad split-tunnel SYS/CAT/INF files enter its
release or staged dependency directories. Store submission remains blocked
until a public-trust signing identity exists and the exact installer and every
contained PE pass signature verification.

Example production website/Store installer build with Artifact Signing after
identity validation and certificate-profile creation:

```powershell
$env:WINS_WINDOWS_ARTIFACT_SIGNING_METADATA = '<absolute path outside the repo>'
.\installer\windows\build_installer.ps1
```

`installer/windows/build_store_msix.ps1 -DevelopmentIdentity` is retained only
as an explicitly blocked compatibility experiment. Its output must never be
submitted or distributed. Calling it without `-DevelopmentIdentity` fails
closed and explains why the signed Win32 route is required. For freeze
`1.0.15+30` the MSIX identity version is `1.0.15.30`; a development publisher
cannot use the production Store name. Partner Center listing copy lives in
`app_store/windows/` and does not authorize upload.

Windows ARM64 uses the same production Win32 route as x64, with distinct exact
artifacts and receipts. Flutter 3.47.6 must run on a Windows ARM64 host, where
it selects `windows-arm64`; stable has no supported x64-to-ARM64 target flag.
The ARM64 dependency producer verifies AmneziaWG Windows client 3.1.0 ARM64,
rebuilds the maintenance helper twice with Go 1.27.1, and requires identical
bytes. The installer then requires PE32+ ARM64 for the Flutter runner, service,
native messaging host, AWG, Xray, Wintun, and both Winn v3 processes. The Store
candidate is `WinsVPN-PartnerCenter-arm64.exe`. It is not an x64 compatibility
build and an x64 artifact or receipt cannot satisfy its cross-store target. The
ARM64 installer starts with Inno Setup's x64 loader and therefore needs Windows 11
(see the ARM64 notes in `docs/CROSS_STORE_RELEASE_CHECKLIST.md`).

The exact signed EXE must then pass a clean Windows 11 silent install,
direct AWG, every advertised Xray route, destination split tunnel, leak, update,
disconnect, uninstall, and residual-service/driver test before its immutable
versioned URL is submitted or linked from the website.

### Windows-first dependency freeze status (2026-07-19)

The current Windows engineering candidate is intentionally unsigned and
nonpublishable. It is immutably preserved with a verified dependency-scoped
build receipt at SHA-256
`76F5F9A86D333AE73EB1EE6425D4868BCFED92E8830734606F0FCA6F044A2513`.
Its preservation metadata explicitly records `production_signed=false` and
`publication_authorized=false`. Historical v13 live evidence remains useful,
but the exact v13 installer bytes were not preserved and cannot be rebound to a
current public receipt.

The official signing prerequisites are installed: Azure CLI 2.88.0, Artifact
Signing CLI extension 1.0.0, Microsoft Artifact Signing Client Tools, and the
Windows 10.0.26100 x64 SignTool. The redacted preflight currently reports zero
authenticated Azure subscriptions, no configured Public Trust profile metadata,
and no production authorization. `tools/windows_artifact_signing_prepare.ps1`
now writes this fail-closed status outside Git under
`%LOCALAPPDATA%\WinsVPN\Signing\artifact-signing-status.json` without recording
account identifiers or secrets. Microsoft requires Public Trust identity
validation to be completed in the Azure portal; it cannot be synthesized by the
CLI. After validation, the signing identity also needs the Artifact Signing
Certificate Profile Signer role on the exact profile.

A separate `%ProgramData%\WinsVPN\LabEvidence\<UUID>` harness now permits
physical-machine testing without weakening the public collector. It requires
the exact candidate, payload-manifest, rollback-artifact, dependency-manifest,
build-receipt, producer, and nine-file collector-closure hashes. Every emitted
document is permanently marked `nonpublishable_lab`, `lab_only=true`,
`publication_authorized=false`, `public_release_gate_eligible=false`, and
`unsigned_local_candidate=true`. A SYSTEM watchdog must prove its exact
baseline and closure before any network transition; emergency cleanup can
never produce a pass. The public release collector has no unsigned override.

The complete isolated lab bundle passes 42 of 42 tests: 22 compiler/receipt/
schema fixtures and 20 fixed-path harness/watchdog security tests. The unchanged
public release/security regression passes 30 of 30 tests, all PowerShell files
parse, both strict JSON schemas load, Python byte-compilation passes, and the
lab compiler self-test passes. The preparer is idempotent across consecutive
runs and verifies exact owner/access ACLs without requesting SACL privilege.
DPAPI-protected current-user inputs were prepared against the exact hashes. On
AICORE, physical Ethernet and Wi-Fi are both up and a post-change HTTPS
management-continuity probe passes. The elevated clean-install/direct/Double/
split/fallback/network-change/leak/teardown/rollback run is the next gate; its
first UAC launch expired without approval and caused no network transition.

Only after Windows shared code and native behavior are stable may the shared
revision be frozen. Final Android, Linux, macOS, and iOS artifacts must then be
rebuilt from dependency-scoped input manifests. A later native-only fix
invalidates only that platform; a genuine shared-input change deliberately
creates a new shared revision and rebuilds all affected artifacts.

## Linux Stores

Current sources used for this pass: Flathub Requirements and Snap security policy documentation.

Release posture for this version:

- AppImage is not a `1.0.15+30` upload target. The x64 packet identity is
  AppStream `1.0.15` / Debian `1.0.15-30`. The website/manual tarball
  `wins-vpn-linux-x64.tar.gz` is the required package; the derived Debian
  package is `wins-vpn_1.0.15-30_amd64.deb` and is not a separate
  cross-store target. Store copy lives in `app_store/linux/`.
- The website/manual route has two exact candidates:
  `wins-vpn-linux-x64.tar.gz` and `wins-vpn-linux-arm64.tar.gz`. Neither is
  release-qualified merely because its source producer exists. Each requires a
  native matching-architecture build, current signature and build receipt,
  clean install/upgrade/remove evidence, and live VPN qualification on that
  architecture.
- Flutter 3.47.6 selects `linux-arm64` on a Linux ARM64 host but explicitly
  refuses Linux x64-host to ARM64-target builds. The producer therefore builds
  each candidate natively and records its exact ELF machine.
- The tarball and Debian producers reject mixed-architecture bundles by
  inspecting every packaged ELF64 object. The required Winn v3 datapath,
  AWG/Xray fallback engines, privileged helper, and browser native host must
  all match the candidate architecture.
- Local/offline signing requires a current-user-owned private cosign key with
  mode `0600` or stricter, a current-user-owned non-executable public key that
  is not writable by group or other, and the explicit installer trust-anchor
  route `/etc/winsvpn/release-signing/cosign.pub`. Before installation, provision
  that public key at the route as a root-owned, non-writable trust anchor. Invoke
  the bootstrap with
  `WINS_LINUX_COSIGN_PUBKEY=/etc/winsvpn/release-signing/cosign.pub`; arbitrary
  adjacent or user-writable public-key paths are refused. Current x64 owner
  blockers: no signed tarball/Debian/Flathub/Snap receipt, listing/screenshot
  inventory owner-blocked, unpublished private symbols, and ARM64 pending.
- Flathub expects a stable reverse-DNS application ID, complete metadata, clear monetization disclosure when the app unlocks paid functionality, and a reviewable Flatpak manifest.
- Flathub's published requirements restrict AI-generated or AI-assisted submissions in the Flathub submission itself. Prepare that store submission manually and keep generated helper text out of the Flathub pull request.
- Snap packages that require broad host networking or classic confinement need explicit justification and store review. A VPN app that creates interfaces will likely need a careful confinement design or a classic confinement request.

Linux submission checklist:

- Keep package ID/domain consistent with the public domain.
- Prepare Flatpak metainfo and a Snap manifest separately from this tarball.
- Document why VPN interface creation requires elevated privileges.
- Prefer narrow permissions where possible; justify any classic confinement or broad network/system access.
- Test the one-touch
  `WINS_LINUX_COSIGN_PUBKEY=/etc/winsvpn/release-signing/cosign.pub install-winsvpn-linux.sh ARCHIVE BUNDLE`
  cosign-verified bootstrap separately on clean x86_64 and ARM64 Linux desktops.
  Verify the
  bundled hash-pinned AmneziaWG tools, kernel-first/userspace fallback, bundled
  Xray, standalone Winn Protocol v3, every advertised Winn v1 fallback
  transport, disconnect cleanup, upgrade rollback, and uninstall cleanup.

## References

- Microsoft Store Policies: https://learn.microsoft.com/en-us/windows/apps/publish/store-policies
- Microsoft Store publishing overview: https://learn.microsoft.com/en-us/windows/apps/publish/
- MSIX preparation limitations: https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-prepare
- MSI/EXE package requirements: https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msi/app-package-requirements
- Windows code-signing options: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options
- Artifact Signing setup and identity validation: https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart
- Artifact Signing roles: https://learn.microsoft.com/en-us/azure/artifact-signing/tutorial-assign-roles
- Artifact Signing trust models: https://learn.microsoft.com/en-us/azure/artifact-signing/concept-trust-models
- Flathub Requirements: https://docs.flathub.org/docs/for-app-authors/requirements
- Snap security policies: https://snapcraft.io/docs/explanation/security/security-policies/
