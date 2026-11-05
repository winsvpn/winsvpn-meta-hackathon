# Browser-extension pairing and VPN control (R20 A1, 1.0.17)

Branch `ext-pairing-control` from `landing-wave1` (5bf525c). Worktree
`/Users/owner/.podium/lanes/landing/pair-wt`. Nothing pushed, uploaded or deployed.

Status: APPLIED on the branch. Unit, integration and contract checks PASSED on
this Mac (counts below). Real-browser, real-app and Windows runtime checks are
NOT_RUN (section 6).

## 1. What changed, in one paragraph

1.0.16 shipped status and the browser proxy only (owner ruling 2026-10-16,
remedy A2) because the app IPC accepted connect and disconnect from any
same-user process that could read `ipc.json`, and disconnect releases the kill
switch (SF-SOL-03, R20 Issue A, A-NEW-01). Now the app grants control only to
a browser the user approved in the app. The first Connect or Disconnect click
in the extension starts a pairing: the app shows a confirmation with a
six-digit code, the popup shows the same code, and on Allow the app mints a
per-browser credential bound to that extension origin. The app keeps a salted
verifier; the extension keeps the credential and presents it on every new
native-messaging port. Unpaired, wrong-origin, revoked and denied callers get
status only. The app's dashboard has a new "Paired browsers" entry with Revoke.

## 2. Design

### Trust root and flow

```
popup click (unpaired)  -> controller: pair_begin
host: pair_begin(origin from argv, allowlisted)  -> app IPC pair_begin{origin}
app: registry.begin(origin) -> pending{pairing_id, 6-digit code, 120 s}
     shows dialog "Allow a browser to control the VPN?" + code + "turns off the kill switch"
host reply  -> extension `pairing{state:pending, code}` -> popup shows "042 917"
host polls pair_poll{origin, pairing_id} every 1 s
user presses Allow in the app (codes match)
app: credential = 32 CSPRNG bytes; stores verifier = SHA-256(domain|origin|credential)
host event -> extension `pairing{state:approved, credential}` (exactly once)
extension stores credential in storage.local; host presents it from then on
later ports: hello, set_pairing{credential}, subscribe, get_status
control: request_connect/request_disconnect -> app checks verifier for that origin
```

* The trust root is the user's Allow in the app UI, compared against the code in
  the popup. Not argv, not the discovery token, not a code signature of the caller.
* The app answers per request: `status.pairing` is `paired` or `unpaired` for the
  credential presented on that request, and `canRequestConnect` is true only for a
  paired caller (`BridgeStatus.copyWithPairing`).
* Disconnect needs exactly the same pairing as connect. A paired disconnect goes
  through the existing watch path (`_handleWatchCommand`), so all existing app gates
  still apply; the app shows "A paired browser disconnected the VPN and turned off
  the kill switch." through `_showFeedback` (never over the decoy).

### State machine (`BrowserBridgePairingRegistry`, pure Dart, clock-injected)

| Rule | Value |
|---|---|
| Pairable origins | exactly the store ids: `chrome-extension://lnehjdblendkagjbmdclepjalahdhbbn/` (Google Chrome), `chrome-extension://glgihadopbjoandhoihghddecoibcldf/` (Microsoft Edge), `companion@winsvpn.org` (Firefox). A test pins this to `store_ids.json` and `firefox.jsonc`. Unknown origin: `identity_mismatch`. |
| Pending pairings | one at a time; a second begin is `busy` (never queued) |
| Confirmation lifetime | 120 s; late Allow grants nothing |
| Cooldown after deny/expiry | 5 s (`rate_limited`) |
| Rate limit | 6 begins per minute |
| Availability | refused (`pairing_unavailable`) while the decoy shows, logged out, or during a local reset; an approval given and then followed by a lock or account change is a denial |
| Credential | 64 hex, delivered once on the first poll after approval; poll with a wrong id or origin reads `expired` |
| Stored | verifier only; one record per origin; re-approving replaces (revokes) the old credential; max 8 records |
| Store write failure | approval fails closed (denied, record rolled back); revoke removes in memory first, then reports a failed save |
| Store file | `<app documents>/browser_pairings.json`, atomic tmp+rename, 0600 on POSIX, strict exact-key parse; anything unexpected loads as empty |

### Wire changes

App IPC (v1, host and app ship together):
* commands `pair_begin`, `pair_poll`, `pair_revoke`; optional request keys `origin`,
  `credential`, `pairing_id` with per-command required/forbidden rules (anything
  misplaced is `malformed`; an unknown key still gets no reply).
* errors `not_paired`, `busy`, `rate_limited`, `pairing_unavailable`.
* status gains `pairing`; pairing replies carry a closed 5-key `pairing` object.
* `authorizeCommand` (the A2 hook) is replaced by the `pairing` registry. A server
  built without one is the A2 posture: status only, every control `not_paired`.

Extension protocol (v1, additive): requests `pair_begin`, `set_pairing`,
`pair_forget`; reply/event type `pairing`; status field `pairing`. An old host
(no `pairing` field) parses as `unsupported` and the popup shows no control.
Host maps app refusals to `not_permitted` / `rate_limited` instead of
`app_not_running`.

### Windows with unsigned builds

* Host to app identity: `kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject`
  stays null (owner ruling: unsigned). The host now accepts the advertised pid only
  if it runs exactly `%ProgramFiles%\WinsVPN\wins_vpn.exe`, not via a reparse point,
  and the file, its folder and every ancestor pass the existing owner-receipt ACL
  rules (privileged owner, no ordinary-user write on file or folder, no replace
  rights above). New `browserBridgeAppIpcWindowsProtectedInstalledExecutableAuthenticates`.
  If a subject is reviewed later, both the ACL anchor and Authenticode must hold.
  A same-user process cannot place a binary there without elevation, so this does
  not trust arbitrary same-user processes.
* Owner receipt: no Windows installer issued `%ProgramData%\wins_vpn\browser_bridge.identity`,
  so the bridge could not start on Windows at all. `installer/windows/winsvpn.iss`
  now runs `InstallBrowserBridgeIdentity` in post-install (non-fatal; failure leaves
  the bridge closed): protected DACL (SYSTEM, Administrators full; Users read),
  Administrators owner, reparse points refused, a valid receipt kept byte for byte,
  a new secret from `RandomNumberGenerator` in the exact Linux/app format, never
  printed or logged.

### macOS (coordinator additions from the companion lane)

* `macos/Runner/Release.entitlements` adds `com.apple.security.network.server`.
  The App Store sandbox refused `bind(127.0.0.1)` with EPERM without it (companion
  lane reproduction). Arbiter decision: add it. App Review note: "local
  browser-companion IPC bound to 127.0.0.1 only; no public listener".
  `tools/verify_macos_release_artifact.py` now expects it on the host app (exact map
  still enforced: missing or extra keys refused), and a new test
  (`test_app_listeners_bind_loopback_only`) fails if any `ServerSocket`/`HttpServer`
  bind in `lib/` uses anything but `InternetAddress.loopbackIPv4`.
* `_macosCodeSignatureForPid` now verifies Apple's own App Store designated
  requirement form: `anchor apple generic and identifier "org.winsvpn.app" and
  (MAS leaf marker 1.2.840.113635.100.6.1.9 or Developer ID CA + Developer ID leaf +
  leaf[subject.OU] = "5YT8H4U72M")`. App Store copies are re-signed by Apple and have
  no team OU in the leaf, so the old requirement refused them every time. Checked
  here with `csreq` (compiles) and `codesign --verify`: a real MAS app (Yubico
  Authenticator, its id and team substituted) exit 0, wrong identifier exit 3,
  Developer ID app (Firefox, its id and team) exit 0. The team stays pinned through
  `TeamIdentifier` and the DR text check. New Dart test with a MAS-style DR.
* The companion PKG (branch `macos-native-host-companion`, report
  `/Users/owner/.podium/lanes/landing/companion-wt/COMPANION_REPORT.md`) now creates
  `/Library/Application Support/wins_vpn/browser_bridge.identity` (root-owned,
  Linux format). That PKG must be rebuilt after this branch lands, because the host
  compiles `lib/browser_bridge_app_ipc.dart`.

### Safari

Unchanged. The Safari adapter reports no routing surface, so the popup's VPN card,
the options pairing section and every pairing request stay hidden and unsent.

## 3. Files changed

| Area | Files |
|---|---|
| App IPC, protocol | `lib/browser_bridge_app_ipc.dart` (registry, store I/O, server gate, client, Windows unsigned anchor, MAS requirement), `lib/browser_bridge_protocol.dart` (pairing enums, `BridgePairingReply`, `BridgeStatus.pairing`) |
| App UI | `lib/browser_bridge_pairing_dialog.dart` (new: confirmation with code, paired-browsers list with Revoke), `lib/main.dart` (registry wiring, store load before listen, availability, `canRequestConnect: !locked`, on-screen notice, "Paired browsers" tile) |
| Native host | `tools/native_messaging/host/bin/wins_bridge_host.dart` (pair_begin/set_pairing/pair_forget, poll loop, credential presentation, refusal mapping), `.../wins_bridge_host_harness.dart` (stubs) |
| Extension | `extension/src/core/protocol.js`, `constants.js`, `copy.js` (storage and erase notes now say the pairing is saved), `background/controller.js`, `background/background.js`, `ui/popup.{html,js}`, `ui/options.{html,js}` (pairing section, "cannot" list corrected), `ui/ui.css`, `tools/dev_bridge.py` (stand-in parity, 4 new contract cases) |
| Windows | `installer/windows/winsvpn.iss` |
| macOS | `macos/Runner/Release.entitlements`, `tools/verify_macos_release_artifact.py` |
| Pins | `tools/build_linux_release.sh` `NATIVE_HOST_SOURCE_CLOSURE_SHA256` 891aeb3f -> 3a5d994c (76d72e3) -> 98f04502ac3da10471c476aa272b4e944ec290f448cce6d84e91ce2b28f7493b (audit follow-up); `tools/apple_cross_store_artifact_gate.py` `MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256` bd170155 -> d45e1c2b (76d72e3) -> ae22f056a34f9ba98320b2aa139c460ba1d53c3d18b5469ba97b2f4c92763be5 (only the IPC/protocol files and the host sources changed in the closure) |
| Tests | new `test/browser_bridge_pairing_test.dart`, `tools/native_messaging/host/test/pairing_flow_test.dart`, `extension/tools/test_controller_pairing.py`, `tools/test_windows_browser_bridge_identity.py`; updated `test/browser_bridge_app_ipc_test.dart`, `test/browser_bridge_app_ipc_identity_test.dart`, `tools/test_verify_macos_release_artifact.py` |

## 4. Tests run (this Mac, Flutter 3.47.6 / Dart 3.13.5 from `~/.local/flutter-3.47.6`, the version pinned in `tools/toolchain-pins.json`)

Baselines were run on a clean detached checkout of 5bf525c.

| Check | Baseline 5bf525c | This branch |
|---|---|---|
| `flutter analyze --no-pub` | n/a | No issues |
| `dart analyze` (host package) | n/a | No issues |
| `flutter test test/browser_bridge_app_ipc_test.dart test/browser_bridge_app_ipc_identity_test.dart` | 54 passed | 55 passed (+1 MAS DR test) |
| `flutter test test/browser_bridge_pairing_test.dart` (new) | n/a | 30 passed |
| Full `flutter test --no-pub` | 3158 passed, 6 skipped | 3189 passed, 6 skipped (+31 new). A first run found 3 failures, all fixed: two tracked-reference checks (new files not yet in git) and the decoy test requiring every snack bar to go through `_showFeedback` |
| Host `dart run test/pairing_flow_test.dart` (new, real server + shipping host) | n/a | PASS |
| Host `r20_control_test`, `wins_bridge_host_identity_test`, `wins_bridge_host_origins_test` | PASS x3 | PASS x3 |
| Extension `build.py` (all four targets; includes the 29-case bridge contract, real host vs stand-in) | ok (25 cases) | ok (29 cases) |
| Extension `pytest tools` | 762 passed, 1 skipped, 1 failed (`test_safari_forwarding::test_real_stack_swift_abi_and_dns`) | 767 passed, 1 skipped, same 1 failed (+5 new) |
| `extension/tools/test_controller_pairing.py` (new) | n/a | 5 passed |
| `tools/test_verify_macos_release_artifact.py` | n/a | 95 passed (+2 new) |
| `tools/test_windows_browser_bridge_identity.py` (new, static) | n/a | 6 passed |
| `tools/test_linux_release_producer.py`, `tools/test_apple_cross_store_descriptor_custody.py` (closure pins) | pass | 99 passed, 2 skipped |
| `tools/test_windows_*.py` | 1 failed + 14 errors in `test_windows_native_async_lifecycle` / `test_windows_installer_dependency_witness` | same 1 failed + 14 errors, rest pass (758 passed) |
| `tools/native_messaging/test_app_ipc.py`, `test_native_host_registration.py` | 2 failures (companion lane: pre-existing, unsigned host) | same 2, 68 passed |
| `test/extension_website_agreed_test.py` | n/a | 4 passed |
| `tools/test_release_browser_archive_custody.py`, `tools/test_extension_store_listing_metadata.py` | 6 failed | same 6 failed |

Negative controls: removing the server's pairing gate makes the new Dart IPC tests
and the host pairing flow fail; removing the controller's pairing branch or the
revocation check makes 3 of the 5 extension controller tests fail. Both mutations
were reverted.

NOT_RUN: `extension/tools/core_tests.py` (needs the authenticated release browser
custody variables `WINS_RELEASE_BROWSER*`, absent here, same as baseline);
PowerShell execution of the installer script (no Windows host); any real browser,
real installed app, or real Windows/macOS/Linux end-to-end pairing.

## 5. What remains

1. Desktop rebuilds: app (macOS App Store, Windows x64/arm64, Linux x64/arm64),
   native host on every platform, extension zips (Chrome, Edge, Firefox), then the
   release freeze and cross-store receipts, since the closure pins moved.
2. Rebuild and re-notarize the macOS companion PKG from a tree containing this
   branch (the host compiles the changed IPC file). Reconcile the companion branch's
   closure/receipt pins with the ones moved here.
3. Target acceptance, per OS and browser: unpaired popup shows status only; first
   Connect shows the same code in the app and popup; Allow pairs; Deny, timeout,
   lock and decoy refuse; disconnect from a paired browser releases the kill switch
   and the app says so; Revoke in "Paired browsers" returns the browser to status
   only; Safari unchanged.
4. Windows: run the installer on a clean machine and confirm the receipt's ACL and
   that the host accepts the unsigned `Program Files` app (ACL probe on a real
   install).
5. App Review note for `network.server` (loopback browser companion).
6. Burmese for the new app strings: they go through `_t()` and fall back to English;
   no translation was invented. The extension strings are English like the rest of
   the popup.
7. Optional: clear pairings on account reset/duress purge (today they survive a
   logout; they grant control of the local VPN only).

## 6. Residual risks (honest)

* Same-user processes are not made untrusted. A process running as the user can
  read the stored credential from the browser profile (`storage.local`) and then
  control the VPN as that browser; can raise an unsolicited prompt (one at a time,
  rate limited, showing a code no popup shows); on Windows and Linux can rewrite
  the app's pairing store (on macOS the store is inside the app container); can
  inject into the app or the browser; and can drive the UI with synthetic input
  (macOS requires Accessibility permission for that). Pairing removes silent
  control through the IPC; it does not create isolation from same-user malware.
* The browser name in the app dialog is the extension's claim. The code
  comparison, not the name, is what ties the approval to the popup the user is
  looking at.
* Windows app identity rests on Program Files ACLs and the absence of reparse
  points, checked by a PowerShell probe per IPC call (also a small CPU cost per
  status poll). An administrator, or malware already elevated, can replace the
  binary.
* The pairing credential is now persisted in the browser profile; the extension's
  storage note and erase text say so. "Erase the site list" also asks the app to
  forget the pairing.
* Windows installer change and the macOS `network.server` entitlement are untested
  on target hardware in this lane.

## 7. Audit follow-up (`/Users/owner/.podium/lanes/landing/PAIRING_AUDIT.md`, verdict SHIP, 0 BLOCKING)

Applied as a second commit on top of 76d72e3. PAIR-06 (popup disconnect
confirmation) skipped by coordinator decision. The audit's PAIR-02 and PAIR-05
diffs did not apply as written; both were implemented against the tree.

| ID | Change | Tests (real, passing) |
|---|---|---|
| PAIR-01 | `ElevatedScriptPath()` in `winsvpn.iss` writes both elevated PowerShell scripts (browser-bridge receipt and the pre-existing prerequisite verifier) under `{app}` (Program Files, admin-only DACL; created with `ForceDirectories` when `PrepareToInstall` runs first), never `{tmp}`. Both scripts are deleted after they run. | `test_elevated_scripts_are_staged_under_app_never_tmp` (static). Runtime on Windows NOT_RUN. |
| PAIR-02 | Each pending approval remembers the record it minted. Expiry of the pickup window, `cancelPending()`, or a cancel while the store write is in flight removes that record from memory and the store if nobody collected the credential. A collected approval is untouched. | 4 new registry tests (uncollected expiry, uncollected re-pair, cancel during the store write, collected record kept). |
| PAIR-03 | `_revokeBrowserBridgePairings()` (memory first, then the store; a store failure is logged, control already stopped) runs before the local reset's account erase, before the duress sweep, and on logout (`_resetAccountUiAfterVerifiedCleanup`, `_forcePendingAccountCleanupUi`). | Source-contract test for all four sites; `revokeAll` behavior already covered. |
| PAIR-04 | The DR text check accepts exactly the team OU quoted or bare (csreq quotes a digit-leading OU only) and nothing longer; comment now states that `TeamIdentifier` from the signed CodeDirectory is the Mac App Store team pin (the MAS branch of the requirement passes any team). | MAS test extended: bare and quoted accepted; 6 wrong spellings and a mismatched CodeDirectory team refused. |
| PAIR-05 | The ACL probe now reports `VOLUME=<DriveType>|<DriveFormat>` and `PROGRAM_FILES=` from `Environment.GetFolderPath(ProgramFiles)` (the OS known folder, not the inherited `%ProgramFiles%`). The unsigned-app anchor requires `Fixed|NTFS` and compares against that known folder; the env-based `_windowsProgramFiles` helper is gone. The owner-receipt probe accepts output without the new lines. | Network/removable/exFAT/ReFS/missing-volume refused; forged `Z:` share whose ACL chain passes on its own is refused; moved or missing known folder refused; misplaced, duplicate or ill-formed lines are malformed; receipt probe still parses without them. Runtime on Windows NOT_RUN. |

Negative controls: disabling the uncollected-record rollback fails 2 PAIR-02
tests; dropping the `Fixed|NTFS` requirement fails the volume test; reverting
the OU regex to the quoted-only form fails the MAS test. All reverted.

Residual noted while doing PAIR-05 (not changed, pre-existing): the PowerShell
probes still inherit the host's environment, and `windowsSystemExecutable`
derives `System32` from `%SystemRoot%`. A same-user launcher that controls
the browser's environment could point `PSModulePath` at a module that shadows
`Get-Acl`. Running the probes with a minimal fixed environment (and a
known-folder System32) is the follow-up; it was not done blind, because it
needs a Windows host to verify that PowerShell still starts.

Verification after the follow-up (this Mac, Flutter 3.47.6):

| Check | Result |
|---|---|
| `flutter analyze --no-pub`, host `dart analyze` | No issues |
| Full `flutter test --no-pub` | 3197 passed, 6 skipped (was 3189; +8 new) |
| `browser_bridge_pairing_test`, `_app_ipc_test`, `_app_ipc_identity_test` | 93 passed |
| Host `pairing_flow_test`, `r20_control_test`, `wins_bridge_host_identity_test`, `wins_bridge_host_origins_test` | 4 of 4 exit 0 |
| `extension/tools/test_controller_pairing.py` + `tools/test_windows_browser_bridge_identity.py` | 12 passed (5 + 7) |
| `tools/test_windows_installer_*.py` + `test_windows_browser_bridge_identity.py` + `test_windows_cross_store_inno_inner_payload.py` | 101 passed, 14 errors (the pre-existing `test_windows_installer_dependency_witness` errors, same as baseline 5bf525c) |
| Closure pin tests (`test_linux_release_producer`, `test_apple_cross_store_descriptor_custody`) | 99 passed, 2 skipped |
