# Win's VPN Launch Completion Audit

Last reviewed: 2026-07-20

> Historical evidence only. The current fail-closed release manifests and
> `web/releases/downloads.json` supersede every artifact, URL, publication,
> and readiness claim in this July snapshot. As of the current working tree,
> there is no authorized public download candidate for Android, Windows,
> Linux, Apple, or the browser extensions.

This file consolidates unfinished work from the working thread so launch decisions are based on repo state instead of memory. It should be updated after each successful app, website, script, or infrastructure milestone.

## Authoritative 2026-07-20 Corrective Snapshot

This snapshot supersedes every readiness and publication statement below. The
release remains **not publishable** until the current Core client-return-path
failure and the remaining platform/external authorization gates are cleared.

- The newest unpublished Windows candidate installer is SHA-256
  `007A0C07E61F197515FC767EB3C8A80A26867C78107C3C28BB9910BBD5CB0212`;
  its installed GUI is
  `0ADDF29827457EFE5D426F3743CB91C91CDE82BD3BB7B383BD6853C408F3BBEA`
  and its privileged tunnel service is
  `404C7E3F818764909BD6071E4B2B0C841234DE67E0D7C886C74E14ACC982D8C6`.
  The candidate clean-installs on the Samsung laptop, and its tri-state stop
  settlement no longer treats a transient native-status error as proof that a
  previous tunnel is active. The 2026-07-20 exact physical rerun again passed
  clean install but correctly failed after one bounded attempt because the
  Spain egress never returned. The Windows route was briefly up, then reported
  the physical/Core public egress before fail-closed teardown. Correlated
  privileged observations prove client `10.9.1.23` entered Core during the
  attempt, matched the expected policy table, advanced Core FORWARD and
  MASQUERADE counters, and enqueued encrypted data on `corex3`. Spain retained
  a fresh Core-peer handshake but its decrypted AWG link, WAN FORWARD, and NAT
  counters did not move. Every required Core policy, FORWARD, NAT, reverse
  route, identity, and persistence rule is present; a missing client-return
  firewall rule is therefore disproven. The remaining boundary is the live
  Core-to-Spain Xray/AWG carrier after `corex3` enqueue and before Spain IP
  decryption. The sanitized Windows status SHA-256 is
  `89D4F288A3DFEBF0694D9394340061674838F29D3562F64D7271DF66EB44AEC8`;
  the privileged Core diagnosis SHA-256 is
  `ED0C625790507E191F4FBE1A36D19041699CDEB91141BACD492497F449C7D372`.
  Settings were restored, the scheduled harness is Ready, and its canonical
  runner was restored to SHA-256
  `90E06E153D84A128A29634DD57C236C68F67652BD82F9BDDC563DE7395F8EF1C`.
  Windows is improved but not sealed, and the shared Dart revision is not yet
  frozen.

- The most recent sealed dependency-scoped index is now historical preliminary
  evidence because the Windows settlement repair changed shared Dart inputs:
  `.artifacts/release-freeze-1.0.14-r2-linux-r1-windows-r1-apple-native-r1-20260720/RELEASE_INPUT_INDEX.json`,
  SHA-256
  `E63A6308FDF4F35C7C31B22C6113A8D7A1BBCA9E1FA631D570176709F50F4663`.
  The complete local release gate passes against the current unsealed source:
  tool and active-secret checks, formatting and analysis, all 152 Flutter
  tests, deployment validation, root-level deployment/runtime simulation,
  Smart Boost stress, map-worker checks, and the 47/47 website security suite.
  Do not rebind the older Android/Linux/Apple artifacts to these shared inputs.
  A new shared revision and five affected artifact manifests may be sealed only
  after Windows passes its exact physical Double-VPN and transition matrix.
- The preserved Windows engineering installer is SHA-256
  `76F5F9A86D333AE73EB1EE6425D4868BCFED92E8830734606F0FCA6F044A2513`.
  On the Samsung physical laptop, its exact elevated clean install and direct
  VPN tests pass. The earlier relocated-`curl.exe` split failures were a TLS
  canary false negative: two exact-candidate cycles with signed Chrome prove
  that the excluded browser keeps the original physical egress while the
  protected route remains tunneled. The exact browser Double VPN cycle also
  proves `double_vpn_active=true`, protected Core egress, Xray fallback, clean
  disconnect, exact route restoration and settings restoration; its evidence
  SHA-256 is
  `30B2A778E3EDBE5FDFEDF28E1ED51FFE6BEC86E09683B120F4DAC4177A8FCC0E`.
  A later non-split exact Double cycle connected briefly but then tore itself
  down before reaching the expected Core egress, so Double reliability remains
  a release blocker rather than being inferred from the split-enabled pass.
  Independent exact-candidate fault-isolation runs prove Xray TCP/80 and
  TCP/443, clean teardown, and removal of every temporary firewall rule; their
  status SHA-256 is
  `1C96D43BEBE0452FF05FDDF1C4B4CACA4AB7DCA077EA8EF3847E24A90F04F84A`.
  AICORE's four network transitions pass on behaviorally identical binaries,
  but the same-byte final rebuild has not repeated them because Samsung lacks
  active Ethernet and AICORE currently contains the timestamp-only predecessor.
  Publication is blocked independently by the missing public-trust
  Authenticode identity pending Microsoft approval.
- The exact Android APK passed uninstall-first install, signature/version,
  launch and fatal-log inspection on physical device `REDACTED_SERIAL`. The later
  exact physical TCP/80 and TCP/443 Xray lanes both passed protected traffic,
  DNS, teardown, Nginx restoration, and zero persistent observer logging; the
  sanitized result SHA-256 is
  `2EAD09245B5B84FD62A73BECB2FE1882B33D091918DD4827EC4977F5B54BAE9F`.
  This remains preliminary rather than final because shared Dart inputs changed
  afterward. The phone is currently authorized, awake, verified-boot green,
  and in a safe disconnected state. Samsung already has a separate clean
  Flutter 3.44.6 SDK. The identical upload keystore was migrated from a legacy
  source copy into an owner-only current-user DPAPI store; both the status and
  round-trip self-test pass, and 13 redundant plaintext signing-property or
  keystore files were removed from the enumerated old source copies. The final
  Android lane must still perform the mandatory uninstall-first exact APK
  install, launch, logcat, direct, Double, split, and both fallback smokes only
  after the shared revision is frozen.
- The Apple-native-r1 submission package passes 71/71 static submission checks.
  The exact iOS IPA SHA-256 is
  `41ACC41A2F2D767E3DD09D569AB6F933A20499E94CBA5536B7246C13B3ED3CA4`;
  the exact macOS PKG SHA-256 is
  `944ADAC41B0F786FE356367F2892AE2C43AB55F5332A302289481ADF38135E51`.
  A clean Tart VM passed install, strict signature, byte-identical payload,
  uninstall, receipt cleanup and profile cleanup. Direct local launch is still
  blocked before process creation by Apple `taskgated` because the clean VM has
  no eligible App Store provisioning authorization. Owner/legal approval is
  unchanged at `submission_approved=false` with three decisions pending. No
  upload or publication was attempted.
- The Core installers are byte-identical at SHA-256
  `C2D64D3ADA0DA09C7F0317FF33D359DACF38A2D4EBFFAF1BCA5E7DA48BE2B508`.
  Their ordered fresh-install path and root simulation pass with official OISF
  Suricata 8.0.6 or newer, ET Open alert-only rules, five local high-confidence
  drop rules, fail-closed NFQUEUE inspection, bounded memory/thread settings,
  and preserved UDP/9210 plus Xray 80/443 ordering. The data-plane installer
  now explicitly installs `conntrack`, which its live route guard requires.
  Package operations use noninteractive `dpkg` repair and `--force-confold`
  before service/firewall activation, preventing fresh-install prompts from
  changing command order.
  The deployment validator now also fails if the ordered Core client
  forwarding, fixed/dynamic exit MASQUERADE, default-drop, or MSS-clamp
  sequence is removed or reordered. Its SHA-256 is
  `660E9036D05887D5CB05392EB3C01056981E5C273EC2C859619FB7DE7614430A`.
- A new 2026-07-20 mutation-free probe of the working IONOS Control Hub
  confirms Ubuntu 24.04, two CPUs, approximately 4 GB RAM, one RAM-backed zram
  device, zero unprotected swap, key-only SSH, IPv4 forwarding off, IPv6
  disabled/drop, restrictive INPUT/FORWARD policies, and no public hub web or
  unrestricted SSH accept. Hub, Nginx, Cloudflare tunnel, Suricata, Fail2Ban,
  security/triage, update, maintenance, canary, PayPal and encrypted-backup
  paths are active with no failed inspected unit. Suricata 8.0.6 passes its
  config test, has queue-0 inspection without bypass, and loads 52,046 alerts
  plus exactly the five intended hub drop SIDs. The database integrity check,
  one online data plane, one runtime-ready Core, and the owner-only complete
  SMTP2GO/PayPal/Cloudflare one-touch material contract all pass. No live
  service, firewall, secret or customer record was changed by the comparison.
- Google Play's July 17 rejection said the policy was not clearly labeled. The
  website now presents a prominent anchored `Privacy Policy` H2 instead of
  burying it under `Legal Terms`; the regression test is part of the website
  audit. The expired July 13 maintenance banner and an ignored `.DS_Store`
  deployment artifact were also removed, and the audit now passes 47/47. The
  corrected page is live and returns HTTP 200 on the
  Pages domain and all `winsvpn.org`, `www.winsvpn.org`, and `www.winsvpn.com`
  production hosts, including `/privacy/`.
- The Grok, Gemini and Claude handoff trees contain diagnostic or preliminary
  work, not a safer releasable replacement. None is merged. The current
  comparison is
  `.artifacts/ai-handoff-20260719/HANDOFF_REVIEW_20260719.md`, SHA-256
  `0539B15BE5B08A4A94A76AD24B194EE0E404647051CCCAF25DEE583EDC83562D`.
  A fresh independent-review prompt will be generated only after the stable
  platform candidates are sealed, so it cannot direct reviewers to obsolete
  artifacts.
- Honeypot/honeynet work is deliberately deferred. The standalone source is not
  installed by any production role, and the Control Hub installer keeps its
  legacy honeypot path disabled and rejects attempts to enable it on the hidden
  origin.

## Authoritative 2026-07-19 Snapshot

This snapshot supersedes readiness and artifact statements in the dated history
below. Publication remains disabled until every release-critical gate is green.

- The dependency-based `1.0.14+29` freeze is sealed at shared revision
  `winsvpn-1.0.14-r2-20260719`. The Linux-native stale-launcher repair and the
  Windows artifact-preservation producer change are isolated by
  `.artifacts/release-freeze-1.0.14-r2-linux-r1-windows-r1-20260719/RELEASE_INPUT_INDEX.json`,
  SHA-256
  `3DE5C6049B40B70C19615C38AED2EA5B17A9F9313304FCAC78C7EE44294A9877`.
  The shared, Android, iOS, and macOS fingerprints remain unchanged; their old
  receipts verify by dependency-scoped carry-forward. Linux also remains
  unchanged from its native revision. The full local release gate passes
  against this exact index, and building or testing does not mutate the sealed
  inputs.
- Windows historical v13 evidence is live-green. The elevated exact
  clean-install probe verified the AWG runtime query, current handshake,
  bidirectional adapter and server counters, protected HTTPS with a changed
  exit, TCP Xray fallback, and clean teardown. The broader Windows matrix also
  covers direct, Double VPN, per-app split selection and enforcement,
  Wi-Fi/Ethernet/DHCP/IPv6 changes, TCP 80/443 fault injection, leak protection,
  rollback, and uninstall. The installer remains deliberately unpublished
  because no trusted Authenticode identity is available. A preservation audit
  on 2026-07-19 found that the receipt-bound installer SHA-256
  `5C5685B699CDEFD1ED718DD896EBEF093B8B86E726B79883DCBCCCAC4C06BB98`
  is no longer present in the workspace or handoff copies. The installed
  binary identities and their live evidence remain intact, but that missing
  installer cannot be rebound to a public receipt. A fresh unsigned engineering
  candidate has now been rebuilt from the current Windows inputs, automatically
  preserved, and receipt-verified at SHA-256
  `76F5F9A86D333AE73EB1EE6425D4868BCFED92E8830734606F0FCA6F044A2513`.
  Its preservation metadata correctly records `production_signed=false` and
  `publication_authorized=false`. Windows therefore still needs one trusted
  production-signed build followed by the same-bytes exact clean-install/live
  matrix before publication. The free Store-signed
  MSIX route is not an equivalent workaround because the feature-complete app
  requires the per-app split-tunnel kernel driver, which MSIX cannot install.
- The isolated Grok and Claude handoff trees were rechecked through 2026-07-19
  19:54 local time. Grok's XUDP/re-pinning/port experiments never advanced the
  server handshake or produced bidirectional payload; its remaining uncommitted
  change only hardens a diagnostic against transient `awg show` permission
  errors. Claude stopped at architecture review, 148/148 Dart tests, and a
  disconnected UI. Neither tree contains a releasable transport repair, so
  neither is merged into the frozen source. The exact review is recorded in
  `.artifacts/ai-handoff-20260719/HANDOFF_REVIEW_20260719.md`, SHA-256
  `8BF26ADB69D5C0BE35C55763A520090D1A62D33CF857B33D502413266F75C8AD`.
- The Android native engine is not an unidentified binary. Its bytes exactly
  match Maven Central coordinate
  `com.zaneschepke:amneziawg-android:2.3.7`, SHA-256
  `B08C96190D34244626CAD1DB79618F1658481974A829A2C42527D7A6989C3429`.
  Version 2.3.7 is the upstream fork's latest stable release and supplies the
  peer-update JNI API required by the app's Xray/AWG carrier. Amnezia's official
  application AAR uses an incompatible JNI contract and must not replace it
  without a native rewrite. Two mandatory uninstall-first physical cycles
  passed exact APK hash/signature/install, launch, startup, activation, Double
  preference persistence and VPN permission. Single-hop Xray, validated
  `tun0`, DNS and OS-routed per-app UID selection passed. The apparent Double
  failure was then resolved without changing app inputs: the release UI driver
  was appending its PIN to stale calculator-camouflage digits instead of first
  pressing AC, leaving later automation locked out of the VPN screen. With that
  test-tool fix, the same exact clean-installed APK kept Double checked, crossed
  the native method-channel boundary, started `VpnTunnelService`, established
  `tun0`, and reached `SECURED` with full IPv4/IPv6 tunnel routes and live
  traffic. A sanitized Android-schema API probe independently returned an
  authenticated active Double assignment on UDP/9210 and cleaned it up. The
  two-browser split test now passes in both directions: excluded Chrome and
  protected Samsung Internet, followed by protected Chrome and excluded Samsung
  Internet, with distinct matching baseline/protected egress hashes. Both app
  selections and the tunnel were restored after the test. Supplemental evidence
  is in
  `.artifacts/android-core-recovered-physical-samsung/ANDROID_DOUBLE_AND_SPLIT_RECOVERY_20260719.json`.
- The frozen macOS candidate passed a fresh installed Double VPN run through
  the Core to Spain, including AWG traffic, protected internet/leak canaries,
  disconnect, and local-network restoration. A later retry of the already
  installed frozen iPhone Profile candidate required no further permission
  prompt and passed the same Core-to-Spain Double path. The Network Extension,
  provider engine and executable identity, full-tunnel IPv4/IPv6/DNS leak
  configuration, Internet probe, two external HTTPS/DNS canaries, disconnect,
  and local-state restoration all passed. The sanitized iPhone log SHA-256 is
  `53C6979A4116423D969F33287A6785DF289A9F9AD8532206E23EFDD828D26938`.
  The stricter current public collectors have not converted this supplemental
  evidence into a release pass. The iOS frozen source lacks the required
  deterministic route-forcing and provider/counter/egress bridge. Its current
  semantic XCTest toggles direct and Double VPN but deliberately does not claim
  route evidence. Adding the missing bridge would be a shared-input change and
  therefore requires a deliberate new shared revision and affected-platform
  rebuilds. The macOS collector driver now quarantines exact bundle-ID
  candidates, discovers real `/Users` homes, compares the installed payload
  byte-for-byte, and preserves/restores the prior app and PackageKit receipts
  outside temporary storage. Its 13 driver tests pass on Windows, WSL, and the
  Mac; 19 collector protocol tests pass with one intentional environment skip.
  The strict host collector still fails closed because ssh-root TCC cannot
  traverse historical registered apps under `~/Downloads/.artifacts`, so
  PackageKit relocates upgrades rather than installing at `/Applications` on
  that heavily used development host. This environment-specific clean-install
  blocker is now independently cleared without changing the artifact: the exact
  receipt-bound PKG SHA-256
  `2A7C7FD2342301460AF595D7A663795FD8C2329E066DE3FD42628D5EE34240CA`
  passed on a new macOS 26.5 arm64 VM with zero prior bundles or receipts. It
  installed only at `/Applications/Win's VPN.app`; the extracted payload and
  installed bundle manifests both equal
  `A0EEFB5EB1294806D802CD44AB93980CACF9A1AAFCD53778C8CB0B5A468EF616`,
  strict code-signature verification passed, and the bundle/Team/version/build
  were `org.winsvpn.app`, `5YT8H4U72M`, `1.0.14`, and `29`. Evidence is in
  `.artifacts/macos-clean-pkg-vm-20260719/MACOS_CLEAN_PKG_VM_EVIDENCE.json`.
  The preserved VM is stopped. The exact candidate still needs the strict live
  route/split/leak/network-change/teardown/rollback/map matrix after UDP/9110 is
  restored. The signed Profile macOS app on the host was restored and left
  disconnected. App Store
  Connect upload is also blocked: the historical FDWK857N95 private key is no
  longer present, current tooling has no supported replacement team-key
  credentials, build 29 has no local upload proof, and owner submission approval
  remains false. No upload or submission was attempted.
- Linux's apparent transport failure was a stale split-tunnel launcher that had
  been removed after selection; the old backend aborted before starting AWG or
  Xray. A Linux-native fail-closed fix now skips only unavailable launchers,
  while every replacement or new app remains protected. The receipt-anchored
  final archive SHA-256 is
  `13727C53E2903697263FC88D01C5B03F5F7F4872EC243C013CAF37DCE79B9533`.
  Its byte-exact clean install, Double direct UDP/9210, forced TCP/80 Xray
  fallback, three-way protected egress, DNS/IPv6 leak checks, live
  launcher-scoped split behavior, stale-launcher reconnect, disconnect and
  teardown all pass on AICORE WSLg. Sanitized evidence is under
  `.artifacts/linux-final/20260719T214200Z-aicore-wslg-exact-13727c`.
  The exact installed executable also passes a forced `GDK_BACKEND=x11` launch
  against WSLg's X.Org 24.1.6 XWayland server with Wayland removed from its
  process environment and one valid visible window. That adds X11 backend
  coverage. The exact installed executable now also passes a separate native
  X.Org 21.1.12 Xvfb launch with `GDK_BACKEND=x11`, no `WAYLAND_DISPLAY`, an
  empty app stderr, a visible 1280x720 window and a captured 50-mile map. This
  removes XWayland as the only X11 implementation tested, but it is still a
  headless WSL2 framebuffer rather than a separately booted Linux desktop with
  a physical display. Protected Linux Sigstore publication is complete: the
  exact tested archive was staged privately, SHA-256 checked before signing by
  GitHub Actions run `29706533971`, and independently verified with official
  Cosign 3.0.6 against the exact
  `build-linux-release.yml@refs/heads/main` GitHub OIDC identity. The adjacent
  bundle SHA-256 is
  `D8D023A1070028620546791B37930CA29A02920CA96C8DD1C9B93B7E77655415`.
  The temporary private prerelease and tag were removed after the bundle was
  downloaded. A later run of the stricter schema-v3 public evidence collector
  passed the exact clean install and payload binding, then failed closed on its
  required single-hop direct-AWG lane: UDP/9110 did not establish and the app
  correctly transitioned to Xray. This does not contradict the existing green
  Double VPN UDP/9210 and TCP/80 evidence. It proves that the deferred IONOS
  data-plane UDP/9110 provider-firewall rule must be applied and retested before
  the five-platform public evidence can be assembled. The exact one-rule
  provider change, ordered validation, and rollback sequence is frozen in
  `docs/IONOS_EXTERNAL_FIREWALL_FINAL_HANDOFF_20260719.md`.
- Live hub/data-plane parity is healthy: hidden hub origin, one online Core,
  inline Suricata 8.0.6 without queue bypass, fail-closed firewalling, current
  Xray 26.3.27, capacity admission, encrypted backup services, and required
  AdGuard loopback/AWG resolvers all pass read-only checks. Candidate AdGuard
  adds exact per-client rate-limit subnet lengths missing from the older live
  node. No public honeypot is installed on the hidden hub; a meaningful decoy
  must use a separate public IP/VPS so the hub origin is not disclosed.
- The website remains PayPal-only and all unverified platform downloads stay
  disabled. External IONOS UDP/9110 firewall work, trusted Windows signing,
  live provisioning of the now-tested sanctioned release-only route-guard
  accounts, Apple authentication/collector repairs, and physical-Xorg
  qualification must pass before release. The local guard workflow is complete:
  it uses a locked `winsroute` account, Ed25519-only keys, root-owned forced
  commands, a four-action sudo allowlist, isolated pinned SSH aliases, and a
  redacted hub inventory younger than one hour. Its 19 combined tests pass;
  live provisioning correctly remains withheld until a privileged key-only
  management path exists.

## Authoritative 2026-07-16 Snapshot

This snapshot supersedes older hashes and readiness statements retained later
in this file for audit history.

- Control/data/Core fresh-install scripts pass the complete local release gate,
  deployment structure validator, pinned supply-chain verification, provider
  preflight, and root Ubuntu 24.04 runtime simulation. The read-only live hub
  comparison matches the candidate on hidden-origin routing, Suricata 8.0.6
  NFQUEUE, capacity admission, PayPal/SMTP2GO provisioning, encrypted backups,
  and the `amnezia-awg2` container with in-container `awg0` interface. Live root
  password SSH is intentionally left for the fresh-replacement sequence; the
  candidate is key-first.
- Windows now uses an ordinary `asInvoker` Flutter UI plus an authenticated,
  local-only privileged tunnel service. The service enforces strict config and
  IPC bounds, verifies the co-installed UI and Xray carrier processes, removes
  privileged routing if Xray exits, and handles fail-closed upgrade/uninstall
  cleanup. The obfuscated local installer, native build, privacy scan, pinned
  dependency/driver checks, self-tests, Inno compile, and medium-UI startup
  smoke pass. It remains unpublished pending trusted Authenticode signing and
  the exact elevated live route matrix.
- Linux current-source packaging and live direct/Xray fallback rehearsal have
  passed; public distribution still requires the exact protected GitHub OIDC
  Sigstore bundle and current five-platform release evidence.
- Current Apple 1.0.14+29 IPA and PKG package/source gates pass. Candidate-bound
  macOS live direct/fallback validation passes. Physical iOS accepted the VPN
  prompt but the latest bounded run was canceled at Local Authentication; a
  person must complete Face ID/passcode. Clean macOS PKG installation remains
  pending because PackageKit relocates the system target on the development
  Mac.
- The current Android candidate has prior source/native/package evidence, but
  the required final uninstall-first physical run cannot be refreshed while
  the Samsung laptop exposes no USB ADB/MTP device and no wireless-debugging
  service. Historical phone evidence must not be rebound to a newer APK hash.
- The website remains PayPal-only. No current unsigned/unproven app artifact or
  Apple build has been published, and no IONOS external-firewall rule was
  changed.

## Completed And Locally Verified

- Website: Leadership section now has four public board cards plus a separate three-card continuity row.
- Website: Winn Protocol®, Verified No Log, IDPS, cyber insurance, donation, demo-link, language-menu, and local dynamic hero changes are in `web/index.html`.
- Website AI Help: production `/api/site/ai-chat` is served by the Cloudflare Pages worker. It uses a guarded public-support knowledge base with secret/infrastructure redaction, and can use Gemini through Cloudflare Pages environment variables when configured.
- Give.org: accreditation readiness package created at `docs/GIVE_ORG_ACCREDITATION_READINESS.md`.
- Translation runtime: `web/index.html` now supplements incomplete local translations with the `/api/site/translate` endpoint instead of leaving partially translated pages when a provider key is available, and skips intentional constants such as brand names, platform names, prices, and board names.
- Translation tooling: `tools/audit_website_translations.py` reports missing or English fallback strings; `tools/fill_website_translations.py` can pre-fill `web/i18n/major.json` using the official Google API key or an explicit local public-endpoint fallback.
- Major-language website translations: `tools/audit_website_translations.py --show 5` reports zero actual untranslated visible strings across the 39 configured major languages after intentional constants are excluded.
- Android: current stable-release source includes native VPN service, AWG/Xray transport, free-server path, legal acceptance, split tunneling, and release APK artifact under `web/downloads/wins-vpn-android.apk`. Wi-Fi + Mobile Data / Smart Boost is parked outside the compiled app source in `docs/SMART_BOOST_WIFI_MOBILE_PARKED.md` and `docs/parked_smart_boost/`.
- Windows: native tunnel backend exists in `windows/runner/windows_tunnel_backend.cpp`; installer packages Xray and installs AmneziaWG MSI through `installer/windows/build_installer.ps1`.
- Linux: first native `wins_vpn/tunnel` method-channel bridge is implemented in `linux/runner/linux_tunnel_backend.cc`; it can start direct AmneziaWG through `awg-quick`/`amneziawg-quick` and Xray stealth transport when Linux runtime tools are installed.
- Linux build packaging: `tools/build_linux_release.sh` provides the intended Ubuntu/WSL build order, bundles Xray by default, and packages `web/downloads/wins-vpn-linux-x64.tar.gz` plus a SHA-256 file after `flutter analyze`, `flutter test`, and `flutter build linux --release`.
- GitHub workflows: `.github/workflows/*.yml` remain in the repository as backup-only refusal sentinels. They must not build, test, sign, upload, or publish. Local producers and `tools/apple_runtime_smoke.sh` / `tools/build_linux_release.sh` are the compile authority.
- Apple platform plan: `docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md` documents the required Network Extension architecture, entitlements, method channel, signing, and done criteria.
- GitHub workflow helper: `tools/run_release_workflows.ps1` is retired and refuses to dispatch hosted jobs.
- Server scripts: local release gate runs shellcheck, Bash syntax checks, embedded hub Python syntax checks, and app tests.
- Website and deployment security: the local OWASP-oriented audit now scans the active and legacy Netlify functions plus control/data/core/home one-touch scripts. Hard-coded webhook, control-hub, Cloudflare, hub-admin, SPA, Xray, SMTP, and PayPal secret defaults were removed; fresh control hubs generate cryptographically random runtime values into the root-owned environment.

## Current Verification Status

- `tools/local_release_gate.ps1`: PASS on 2026-06-30 after the latest website and documentation changes.
- `flutter analyze`: PASS in release gate.
- `flutter test`: PASS in release gate.
- Deployment script shellcheck: PASS in release gate.
- Smart Boost stress profiles: PASS in release gate for clean, lossy, asymmetric, and bursty simulated paths.
- Cloudflare Pages worker syntax: PASS on 2026-07-04 with `node --check web/_worker.js`.
- Website/deployment OWASP local audit: PASS, 49/49 checks on 2026-07-10.
- LA control hub and data plane live reachability: PASS on 2026-06-30. Hub `/healthz` reports device limit 3, LA node is online, direct endpoint is `<HISTORICAL_NODE_IP>:9110`, and stealth endpoint is `united-states-los-angeles.app-cloud-sync.net:443`.
- Android USB phone fresh install smoke test: PASS on 2026-06-30 using connected device `365c61de`. The test uninstalled `org.winsvpn.app`, installed `build/app/outputs/flutter-apk/app-release.apk`, launched the release build, accepted the legal clickwrap, activated the free LA route, and verified VPN connectivity through the tunnel with `ping 208.67.222.222`.
- Android/Data-plane Smart Boost parking decision: COMPLETE on 2026-07-02. Direct Winn Protocol/AWG beat the Kotlin userspace Smart Boost path on the same connected Android phone and LA node, so the public stable release removes the Wi-Fi + Mobile Data UI, removes Smart Boost config/status/qualification calls, removes the experimental Kotlin engine and native bridge from compiled Android source, disables the C++ native build, removes boost storage/advertising from the control hub, and removes boost installation/firewall/heartbeat paths from the data-plane deployment. Data-plane reruns still disable and delete legacy `wins-boostd` files left from testing. The last safe-gated Smart Boost build remains documented with code snapshots under `docs/parked_smart_boost/` for future v2 work.
- Android stable release APK artifact tested on phone after Smart Boost removal: PASS on 2026-07-03 using connected device `365c61de`. The latest test uninstalled `org.winsvpn.app`, installed `build/app/outputs/flutter-apk/app-release.apk`, launched the release build, verified the app window was focused, confirmed the pre-activation free-server selector is hidden, confirmed the one-time battery prompt does not repeat after relaunch, activated the free route, verified Android reported the Win's VPN tunnel as connected and validated, verified ping through the tunnel to `9.9.9.9` and `winsvpn.org` with 0% loss, and confirmed disconnect removed the Android VPN network.
- Android release package ID: `org.winsvpn.app`.
- Android release APK SHA-256 after stable Smart Boost removal, free-selector gating, connected server switching, one-time battery prompt, shared store-safe premium access flow update, and permanent Play package rename: `ECDD556A5A2481B904787D26C7B7066245738F016568F38BDFAF555B002E0D5C`.
- Website Android APK artifact: refreshed from the release-signed APK on 2026-07-04 after fresh uninstall/install launch smoke on connected device `REDACTED_SERIAL`; SHA-256 `ECDD556A5A2481B904787D26C7B7066245738F016568F38BDFAF555B002E0D5C`.
- Website Windows installer artifact: rebuilt with Flutter Windows release and Inno Setup 6.7.3 on 2026-07-04 after the shared store-safe premium access flow update; SHA-256 `7480BBA8E08C9C712143BCEC53ADC33EBC477C9D37B1D482E5CD7D294CCE427F`.
- Website Linux x64 archive artifact: rebuilt under WSL Ubuntu 24.04 with Linux Flutter 3.44.4 on 2026-07-04 after `flutter analyze`, `flutter test`, and `flutter build linux --release`; Xray Linux x64, Linux desktop metadata, AppStream metadata, and the 512px app icon were bundled under desktop ID `org.winsvpn.app`; SHA-256 `EB56B5459B1C61651E9AC6CCC57C82BB545716F7267B2FE6C360AC140A46357F`.
- Desktop store-readiness note: `docs/DESKTOP_STORE_RELEASE_READINESS.md` documents the Windows/Microsoft Store and Linux store submission posture. The default desktop build opens `https://winsvpn.org/#get` for premium access instead of listing direct plan buttons inside the app.
- Production website deploy: PASS on 2026-07-04. Netlify was unavailable because the site account was paused/forbidden, so production was moved to Cloudflare Pages under the `winsvpn` project. Live checks returned HTTP 200 for `https://winsvpn.org/`, `https://www.winsvpn.org/`, and `https://www.winsvpn.com/`; `https://winsvpn.com/` redirects to `https://winsvpn.org/`. Cloudflare cache was purged for both zones. Large Android, Windows, and Linux app downloads are served from the public `winsvpn/winsvpn-downloads` GitHub Release because Cloudflare Pages has a 25 MiB per-file upload limit; `/downloads/...` routes on the website redirect to those current release assets.
- Double VPN core status: the private home Core host is online, LUKS-backed, and runs core ingress/exit containers, Nginx, Xray, Docker, and Fail2Ban. Its operator address does not currently expose TCP `80` or public ingress `9210`, and the current home server lacks the latest `wins-core-sync` systemd units, so the hub correctly advertises `double_vpn_available=false` until public ingress/reverse tunnel and core registration are completed.
- Control-hub IDS commodity-probe tuning: PASS on 2026-07-02. Common public-web scanner signatures and reputation-only Tor/IP-list alerts are disabled or pruned from Suricata where possible and no-record filtered in the Wins monitor as a second layer. Live hub validation reported zero enabled noisy rules for the latest /bin/sh, Apache path traversal, phpinfo, .htpasswd, /proc/self/environ, .php~ disclosure, /etc/passwd, /etc/hosts, sftp-config, VS Code sftp, PHP-CGI, and Tor signatures; 92 old noisy rows were removed from the security event database.
- VPS disk encryption support: READY FOR NEXT RESET on 2026-07-02. Live control hub and LA data plane are currently unencrypted ext4 roots, so the scripts now support `REQUIRE_LUKS_ROOT=1` as an early deployment gate after a provider reset/reinstall with LUKS2. Both one-touch scripts configure dropbear-initramfs remote unlock when LUKS root is present and abort before writing VPN secrets if encrypted root or encrypted swap requirements are not met.

## 2026-07-14 Cloudflare And Physical Route Verification

- Cloudflare automation: created an account-owned API token for the signed-in `app-cloud-sync.net` account with only DNS Write, Zone Read, Zone Settings Write, SSL and Certificates Write, and Dynamic URL Redirects Write. The one-time secret was passed over standard input, validated against all five APIs, stored only in the Windows DPAPI deployment preseed, and cleared from the browser and clipboard. The token value was never written to Git or printed in logs.
- Cloudflare HTTP fallback: the live Single Redirect rule now redirects ordinary plaintext HTTP to HTTPS while preserving `/wins-stealth-tunnel` on TCP 80. Cloudflare's live Rules parser requires the Boolean `ssl` field in this phase, so both the data-plane installer and repair action use `(not ssl and not (http.request.uri.path in {...}))`; `Always Use HTTPS` is disabled to avoid overriding the exception.
- Cloudflare route matrix: WebSocket upgrade returned HTTP 101 for `spain.app-cloud-sync.net`, `spain-madrid.app-cloud-sync.net`, and `madrid.app-cloud-sync.net` on plaintext TCP 80 and TLS TCP 443 (six of six routes).
- Android reference device: fresh uninstall/install tests used S26 Ultra `REDACTED_SERIAL`, package `org.winsvpn.app`, version `1.0.14+29`, and release APK SHA-256 `1e9205a87d24ec07e15784cbface9f0d7107a25d7b1fc7db98169ba49a07c0b6`.
- Android direct route: the production APK completed an AmneziaWG handshake, created `tun0` with MTU 1280 and full IPv4/IPv6 routes, and exited through Spain `<NODE_ES_IP>` with zero fatal/VPN log matches.
- Android TLS fallback: an otherwise identical obfuscated diagnostic build with `WINS_FORCE_XRAY=true` launched `libxray.so`, connected to Cloudflare on TCP 443, produced a validated Android VPN, and exited through Spain with zero fatal/VPN log matches.
- Android plaintext fallback: a temporary test-only port filter forced the same Xray app path to TCP 80. The physical phone established `192.168.50.134 -> 104.21.85.254:80`, produced a validated full-route VPN, and exited through Spain with zero fatal/VPN log matches. The temporary port filter was removed from source immediately afterward.
- Final phone state: the exact production APK was restored to the canonical build path, hash-verified on both PCs, freshly uninstalled/installed, and connected. On the final run the direct AWG handshake occurred and the smart protocol retained the viable Xray fallback, demonstrating failover rather than a false connected state.
- External IONOS firewall was intentionally not changed. The end-of-project firewall handoff still needs to allow data-plane UDP 9110, preserve the tested Cloudflare TCP 80/443 paths, avoid public control-hub SSH, and retain a separately proven recovery path before tightening provider rules.
- Remaining live-device gaps: the Core one-touch scheduled task is still running in its visible Samsung/Ubuntu window and has not reported completion; the MacBook cannot currently be resolved or reached from either Windows host on the LAN. These must be cleared before claiming final Double VPN and Apple runtime completion.

## Open Launch Blockers

1. Rotate every credential that was previously embedded in tracked source, including webhook/control-hub, Cloudflare, hub-admin, SPA, Xray, SMTP, and PayPal credentials. Update only root-owned deployment environments and provider secret stores. SPA/Xray rotation must be coordinated with server configuration and client rebuilds; removing literals from the current tree does not erase prior Git exposure.
2. Cloudflare Pages should have `GOOGLE_TRANSLATE_API_KEY` and an approved AI provider key configured only if paid usage limits are acceptable. The site works without those keys by using local major-language translations and the guarded support fallback.
3. Android must be re-tested on the USB-debugging phone after any future app-code change. The latest release APK smoke was re-tested on device `365c61de` on 2026-07-03 with fresh uninstall/install, app launch, focused-window verification, and logcat crash/error scan.
4. Windows needs a clean-machine administrator install/connect/uninstall test before Microsoft Store submission or broad public release.
5. Linux now builds locally under WSL Ubuntu 24.04, but still needs a real Ubuntu desktop tunnel smoke test with AmneziaWG tools installed before Flathub/Snap or broad public release.
6. The universal iOS candidate has passed physical iPhone live VPN testing. The universal macOS replacement still needs Xcode account re-authentication, signed rebuild/archive/export, clean package install, and live VPN rerun before App Store upload.
7. Demo videos are placeholders. Do not publish them as final until real screen recordings or verified realistic demos exist for Android, Windows, Linux, macOS, and iOS, covering activation, Calculator camouflage where supported, VPN connection, and malicious-link blocking.
8. Production website deploys should be batched to avoid unnecessary Cloudflare deploy churn and GitHub release asset replacement. Netlify is not part of the current public production path.
9. Give.org readiness has a governance blocker: BBB WGA expects at least five voting board members. Current public leadership list has four.
10. Win Empire LLC related-party vendor/license/sale arrangement must have written contract, conflict disclosure, disinterested board approval, and fair-market-value support before Give.org review.
11. LA data-plane server was reachable during the latest pass, but live tunnel tests should be re-run again after any provider maintenance, resize, or OS reset.
12. Android's `QUERY_ALL_PACKAGES` Play Console sensitive-permission declaration is still `PENDING` review (see `docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md` "Release gate" section). `tools/public_release_gate.ps1` now fails any public Android release while that status is not `APPROVED`, so update the status line the moment Play Console rules on it.

## Next Work Queue

1. When future website copy changes, update pretranslated major-language strings:

```powershell
$env:GOOGLE_TRANSLATE_API_KEY="..." # preferred official provider when available
python tools\fill_website_translations.py --provider auto --write
python tools\audit_website_translations.py --show 0
```

2. Rebuild and test Android only after the next app-code change:

```powershell
flutter clean
flutter pub get
bash tools/prepare_android_xray_assets.sh android/app
flutter analyze
flutter test
flutter build apk --release --obfuscate --split-debug-info=./debug-info --extra-gen-snapshot-options=--strip
adb uninstall org.winsvpn.app
adb install -r build/app/outputs/flutter-apk/app-release.apk
adb shell monkey -p org.winsvpn.app 1
adb logcat -d | Select-String -Pattern "WinsVpn|WinsVpnService|AndroidRuntime|FATAL|Exception"
```

For Google Play AAB uploads, build with:

```powershell
flutter build appbundle --release --obfuscate --split-debug-info=./debug-info
```

Keep `--extra-gen-snapshot-options=--strip` on APK release builds only. The current Flutter wrapper can fail AAB native-symbol stripping when that extra snapshot option is included, while the AAB above builds cleanly.

3. Windows clean install test:

```powershell
powershell -ExecutionPolicy Bypass -File installer/windows/build_installer.ps1
Start-Process .\build\windows-installer\WinsVPN-Setup.exe -Verb RunAs
```

Verify direct AWG, Xray fallback, disconnect, uninstall cleanup, and that Windows power saving does not throttle the process.

4. Linux build and tunnel test on Ubuntu or WSL/Linux:

```bash
export WINS_RELEASE_INPUT_INDEX='.artifacts/<frozen-release-set>/RELEASE_INPUT_INDEX.json'
bash tools/build_linux_release.sh
sudo apt install -y policykit-1
command -v awg-quick || command -v amneziawg-quick
command -v xray
```

Do not use GitHub Actions for the Linux archive. GitHub is backup storage only; its workflows refuse hosted builds and artifacts. Test activation, direct AWG, Xray fallback, disconnect cleanup, and uninstall cleanup on the local Linux host before publishing the archive.

5. After any LA VPS maintenance, resize, OS reset, or future Smart Boost engine change, re-run live tunnel tests for Android direct AWG, Xray fallback, rapid reconnects, locked-screen behavior, and leak checks using non-Cloudflare/non-Google DNS canaries because those can be blocked in Burma. If Smart Boost is resumed, add Wi-Fi to mobile handoff, mobile to Wi-Fi handoff, and qualification/fallback tests back to this checklist before exposing the UI.

6. Update the blueprint PDF after each verified milestone:

```powershell
python tools\generate_blueprint_pdf.py
```

7. Batch final website deploy through Netlify only after local checks and translation decisions:

```powershell
Invoke-WebRequest -Method POST -Body "{}" https://api.netlify.com/build_hooks/6a4257a7674caa2f63c7c814
```

8. Before final production website deployment, upload the verified app artifact and matching demo video for each supported OS to the website downloads/demo area. Do not publish final OS buttons for platforms that are not yet built and tested; keep them marked as coming soon until their app and demo are real.

9. For Apple platforms, follow `docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md`, then run `tools/apple_runtime_smoke.sh` locally as a compile check before any signed Xcode/TestFlight testing. Do not use GitHub Actions.

## Do Not Claim Yet

- Do not claim Linux, macOS, or iOS apps are ready.
- Do not claim demo videos are final or place final demo/download links on the production website until the corresponding OS app has been built, tested, and matched to that video.
- Do not claim Give.org accreditation until BBB WGA review is complete.
- Do not claim long-tail language coverage without Netlify `GOOGLE_TRANSLATE_API_KEY`; the 39 configured major languages are pretranslated locally, while other languages depend on the translation function.
- Do not claim Windows production readiness until the clean-machine administrator VPN test passes.
- Do not market Wi-Fi + Mobile Data or Smart Boost yet. The feature is parked and removed from the stable-release app UI/code path until a future native packet engine beats direct AWG in live phone tests.
