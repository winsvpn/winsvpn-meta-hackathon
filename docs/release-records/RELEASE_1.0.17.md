# Win's VPN 1.0.17+34 release record

Lane rel17, 2026-11-02/03. Worktree `/Volumes/WinsBuild/winsvpn/podium/lanes/rel17`,
branch `release-1.0.17` (off `integ-unfinished-17` 6f0c0c7). Lane scripts, logs and
evidence: `/Volumes/WinsBuild/winsvpn/podium/lanes/rel17-lane`. Website branch
`website-1.0.17` (worktree `/Volumes/WinsBuild/winsvpn/podium/lanes/rel17-web`).
Nothing was uploaded, published, deployed or changed on any server.

Approval basis for the Apple texts, the legal source offer, the store texts and the
website preparation: the owner's standing instruction of 2026-11-02 ("Finish all of
those like that you haven't finished building... You don't need any permission from
me"), relayed by the release coordinator on 2026-11-03.

## Status

| Target | Result | Source | File | sha256 | Bytes |
|---|---|---|---|---|---|
| Chrome extension | PASS | 4db1e43 | `wins-vpn-companion-chrome.zip` | `0d32c7d15af1751acac2c32fb60dea48c422880442d332bddf4203f5b146e057` | 57902 |
| Edge extension | PASS | 4db1e43 | `wins-vpn-companion-edge.zip` | `765614c3bae2f5ba8204b15cabdc46f97d38eb95faa82acb266a2eefde23b956` | 57908 |
| Firefox extension | PASS | 4db1e43 | `wins-vpn-companion-firefox.zip` | `900b00788c7c33e416d5a01afbb5445269e32f0191ae59f859bdd15faece8c32` | 57986 |
| macOS App Store PKG (1.0.17 build 34, universal app) | PASS | 63e7199 | `Win's VPN.pkg` | `5c4dc85c01cd1b414efe59b2aa1979c881b5239b524fcfd50e6797737068d323` | 74579356 |
| macOS browser helper PKG (Developer ID, arm64) | PASS | tree at 87e1eb6 (host closure 65cd7fd1, unchanged since) | `WinsVPN-Native-Messaging-Host-1.0.17-arm64.pkg` | `2ef52255e89ebeeadb41189d46e352330c0258e9d89621c4c83766a3ab19ae7d` | 2719965 |
| Windows x64 installer (unsigned, plain engines) | PASS | 4db1e43 | `WinsVPN-UNSIGNED-LOCAL-Setup.exe` | `1856d87528bb04deb516fa90a4315213d36601f66419c9137be5485ae9bbf0fe` | 69493844 |
| Windows ARM64 installer (unsigned, garbled release c) | PASS | 4db1e43 | `WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe` | `34f901ab51e3702487d76fd83187b013d1066766b36feedeed738bdb1ef4facf` | 63110028 |
| Linux x64 tarball (garbled release c) | PASS | 4db1e43 | `wins-vpn-linux-x64.tar.gz` | `6c77013aa08388486a1e0362a07dfa8ea728f1134bb830a1246a3969362cdcaf` | 56451989 |
| Linux arm64 tarball (garbled release c) | PASS | 4db1e43 | `wins-vpn-linux-arm64.tar.gz` | `314f2d0625b8434787949c7e770105fdba7da98c3cf9209f4334ad4f997967f3` | 53089419 |

- Store uploads with `SHA256SUMS`: `/Users/owner/Desktop/WinsVPN 1.0.17 uploads/`
  (three extension zips, the App Store PKG, the browser helper PKG).
- Website artifacts with their own `SHA256SUMS`:
  `/Volumes/WinsBuild/winsvpn/podium/lanes/rel17-lane/website-artifacts/` (both Windows
  installers, both Linux tarballs and their `.sigstore.json` bundles, `cosign.pub` 7b66c6fe).
- Evidence: `rel17-lane/evidence/final-4db1e43/<run>/<target>/` (`r17f` extensions,
  Linux, Windows ARM64; `r17z` Windows x64), `rel17-lane/evidence/apple-a17g/` (macOS
  PKG, iOS and macOS build receipts, candidate verification log, release input index).
- The Apple producer also exported an iOS IPA (sha256 `9a6b5976...`); iOS is not shipped
  in 1.0.17 and the IPA was not kept.
- The desktop targets were built at 4db1e43 and the macOS PKG at 63e7199. The commits in
  between change Apple/store/legal texts, test fixtures, Apple reviewed-source pins and
  the Apple readiness script; none of them is a desktop or extension build input.

## Gates

- Extensions: release build receipts, 29-case bridge contract, independent
  `verify-receipt` x3; byte-identical at 87e1eb6, 98ba01c and 4db1e43.
- Linux: remote attested builds (aicore confined, aione), Mac cosign signing (key by
  path), independent `verify-receipt`, `cosign verify-blob` Verified OK (re-checked on the
  staged copies), Mac real-inventory privacy scan pass (56 labels). Shipped x64
  `winn-datapath` is `01000740...`, the garbled release c artifact.
- Windows: remote attested builds (aicore QEMU x64, lenovo ARM64 175 min), unsigned per
  ruling, `verify-receipt` with the real inventory path, worker secret scan pass (56).
- macOS App Store PKG: `APPLE RELEASE CANDIDATE BUILD: PASS` (readiness, XCTest iOS 63 /
  macOS / watchOS, archive privacy inventory, dual-stack and Winn ring artifact gates,
  cross-store gate, frozen macOS sha256 5c4dc85c). Signed "3rd Party Mac Developer
  Installer: Win's VPN Inc (5YT8H4U72M)"; app 1.0.17 (34), org.winsvpn.app, entitlements
  app-sandbox, application-groups, network.client, network.server; x86_64+arm64.
- Companion PKG: Developer ID Installer, notarized `517c1e5c-...` Accepted, stapled,
  `spctl` accepted, verifier PASS; native-host closure 65cd7fd1 bound.

## Source changes on release-1.0.17

- `18806c7` merge companion-17. `d052382` version 1.0.17+34 everywhere the tooling pins
  it; fixed-environment Windows PowerShell probes; arm64-only companion ruling carried to
  1.0.17; native-host closure pins. `330e5b2..87e1eb6` the reviewed garble commits.
- `98ba01c` winsvpn.iss brace comment closing at `{tmp}` (ISCC error); Apple candidate
  identity. `bee0b5d` Apple validators name 1.0.17+34; website template binding.
- `4db1e43` **every Windows install failed since ee48a2f**: the prerequisite verifier
  PowerShell did not parse; fixed with a parser test.
- `49ff9f1` Apple submission texts at 1.0.17+34, ten owner decisions re-approved under
  the standing instruction, review-note and release-notes pins refreshed.
- `6f98e78` legal source offer and manifest (designated archive
  `https://downloads.winsvpn.org/source/wins-vpn-1.0.17.tar.gz`), Windows/Linux store
  packets, extension listings and cross-store gates at 1.0.17+34.
- `7093bab`, `f803fa1` Apple and cross-store upload-readiness test fixtures follow.
- `bc79261` Apple reviewed-source pins left stale by R20 A1 (held-artifact verifier,
  gate helper) and the scanner-closure/freeze-client digest chain refreshed; the first
  Apple run stopped on the stale pin.
- `63e7199` Apple readiness runs the iOS XCTest on the booted simulator
  (`-parallel-testing-enabled NO`): fresh parallel clones refused the app launch
  ("Busy, Application failed preflight checks") in 3 of 5 runs.

## Website release (staged, not published)

- Branch `website-1.0.17` = garble-website-engines + release-1.0.17 (head 7de166d). Each
  manifest entry binds its own release: the four desktop entries are 1.0.17+34 assets
  of the new immutable GitHub release `v1.0.17-34`; Android is not rebuilt, so the
  unchanged 1.0.16+33 APK keeps its identity and its `v1.0.16-33-r3` URL and is never
  re-hosted. Custody, publication, final and live gates, security audit, Worker,
  homepage and CSP hash updated; tests follow, with new per-entry cases.
- Fresh clone `/Volumes/WinsBuild/winsvpn/garble-stage/rel17/pubclone`: challenge,
  `prepare --delivery github`, audit 57 pass / 0 fail, `stage` final gate **READY**
  ("available windows-x64, windows-arm64, android, linux-x64, linux-arm64; not
  published macos=store_pending, ios=store_pending"), manifest `b9fef67f`, issuance
  2026-11-03T08:18:15Z. That issuance expired unpublished; re-staged 2026-11-05 from the
  same commit 7de166d and the same reviewed artifacts: audit 57 pass / 0 fail, final gate
  READY, manifest `b283fc1c`, issuance 2026-11-05T01:46:51Z, expiry 2026-11-06T01:46:51Z
  (24 h). Only the five publication receipts and their manifest digests changed; every
  GitHub asset, SHA256SUMS and the release notes are byte-identical to the first stage.
- Stage `/Volumes/WinsBuild/winsvpn/garble-stage/rel17/stage`: `github/` (4 binaries, 2
  bundles, cosign.pub, SHA256SUMS), `pages/`, `github-release-notes.md`,
  `r2-upload-plan.json`. Staged bytes equal the reviewed artifacts; cosign Verified OK x2.
- Read-only prechecks: immutable releases enabled, tag `v1.0.17-34` absent, the `-r3` APK
  digest `d0507c36` intact.
- Publish steps (not run): `/Volumes/WinsBuild/winsvpn/garble-stage/rel17/publish_v1.0.17-34.sh`
  `precheck`, `release` (gh release create, `--latest=false`), `verify`, `pages`
  (`npx wrangler pages deploy .../stage/pages --project-name winsvpn --branch main`),
  `live` (post-publish live gate). Rollback: Pages to the previous production deployment.

## Functional checks (Windows 11 x64 guest)

- PowerShell probes with the fixed environment: all three commands exit 0; Get-Acl from
  System32.
- The published **1.0.16+33 x64 installer `5331fbbf` cannot install** (same
  PrepareToInstall failure); the 4db1e43 installer installs; bridge identity created with
  owner Administrators, protected DACL, SYSTEM/Administrators full, Users read; native
  messaging keys for Chrome/Edge/Firefox; ProductVersion 1.0.17 / FileVersion 1.0.17.34;
  installed host fails closed without an app (`app_not_running`, pairing refused).
  Uninstalled afterwards and the AmneziaWG prerequisite removed.

## Not verified

- End-to-end pairing on Windows and the host accepting the installed unsigned app: the
  guest has no interactive desktop; `wins_vpn.exe` in session 0 never starts its IPC
  server. Needs an interactive Windows logon. Store extensions cannot be used before the
  stores publish 1.0.17.
- macOS App Store app with the browser helper on a real Mac (install needs an admin
  password).
- Windows cross-store and extension listing suites that need the `cryptography` module
  (absent on this Mac, as at baseline).

## Open items

1. Website publication: Codex BEFORE notice, then the publish script above.
2. The source archive `wins-vpn-1.0.17.tar.gz` named by the legal source offer is not
   published yet.
3. Android is not rebuilt: its store packets and signer/Wear gates stay on 1.0.16+33 and
   need a 1.0.17 refresh with the next Android build (`test_verify_android_aab_signers`,
   `test_android_wear_cross_store_gate_adapters`, `test_wear_os_*`,
   `test_r3_release_pipeline_regression`).
4. Windows installers are not byte-reproducible; the ruling names 1.0.16+33 only.
5. Pre-existing baseline failures unchanged: linux gate adapters (39+3), snapshot
   basename contract, reviewed helper, toolchain pin scan, macOS obfuscation binding,
   dependency freeze `/private` path test.
