# Round 6 requested remediation

Date: 2026-09-13. Workspace: `/Users/owner/xprize/winsvpnv3`.

All requested source repairs are implemented, all seven mandatory verification
commands passed, and the Chrome ZIP was rebuilt and verified. Android phone
smoke remains blocked: the release producer requires a reviewed input index
that is absent from this checkout. This is source and local verification evidence,
not release acceptance or deployed-service proof.

The existing dirty worktree and staged files were preserved. No commit, push,
deployment, store submission, or release approval occurred. The saved
[production diff](round6_remediation/remediation.diff) compares the target files
with their bytes at the start of this task, including the pre-existing changes.
[Results and SHA-256 hashes](round6_remediation/results.json) identify the tested
source and rebuilt artifact. New regression files are present in the worktree.

| Defect | Result |
| --- | --- |
| SOL-02 | Android checks `xrayEnabled` before performance locks, DNS parsing and `startXrayTransportIfNeeded(config)`. It logs refusal, refuses the matching Winn3 start, clears restart state, tears down and returns `START_NOT_STICKY`. The late mode-dependent refusal is removed. |
| SOL-03 | `ACTION_CONNECT` returns `START_NOT_STICKY` when `awaitTeardown(2500L)` returns false, before loading/resetting replacement tunnel state. |
| LNX-01 / SOL-04 | Both successful native start paths mark the session committed. Both successful stop paths clear that flag; failures retain it for retry. Application shutdown calls `ShutdownLinuxTunnelBackend`. GLib handles SIGINT/SIGTERM by quitting the application, and signal sources are removed before the application is released. Existing SIGPIPE handling is preserved. |
| DB-01 | Both logout endpoints parse their bodies asynchronously and await their synchronous helpers through `asyncio.to_thread`. Database transactions, authorization, revocation scheduling and free-access audit ordering remain inside those helpers. |
| SOL-05 | BTCPay checkout navigation requires HTTPS, no user information, a valid host/port and the normalized configured origin. Host case, IDNA, trailing DNS dots, IPv6 and default port are normalized into the returned authority. Control characters, backslashes, malformed authorities and foreign origins are rejected. Invalid responses log a fixed warning and mark the order failed before any provider binding or pending transition. |
| SOL-07 | Both security-event writers use `closing(sqlite3.connect(...))` around the transaction context. Connections close after commit or rollback, including error paths. |
| Release/test assurance | `h3_receive_window_test.go` was already staged and tracked at task start. Its Git index blob remains `93e17c98e22accc7ba8193f054eeddd34ccef177`. The Chrome package was rebuilt from current extension sources. |

| Required command | Result |
| --- | --- |
| `flutter analyze --no-pub` | PASS, no issues, exit 0 |
| `flutter test --no-pub` | PASS, 1,926 tests passed, 2 existing opt-in live tests skipped, zero failures, exit 0 |
| `python3 server/test_control_plane_deepseek_round2.py` | PASS, 11 tests, exit 0 |
| `python3 server/test_control_plane_round4.py` | PASS, 8 tests, exit 0 |
| `python3 server/test_control_plane_round5.py` | PASS, 16 tests, exit 0 |
| `python3 server/test_winn3_descriptor_hub.py` | PASS, 117 tests, exit 0 |
| `python3 tools/website_security_audit.py` | PASS, 56 checks passed, 1 explicit skip, zero failures, exit 0. The skipped check references absent `drop_in/lib/spa_service.dart`. |

Additional verification:

- `python3 server/test_control_plane_round6.py`: 7 tests pass, including hostile
  URL variants, failed-order non-binding, valid-order binding, both logout paths
  under an actual SQLite writer lock, authenticated device deletion, and four
  security-event connection success/failure close cases. Against the saved
  original server source, the same suite produces the expected 4 failures and
  36 errors, including missing URL validation, blocked event-loop progress and
  unclosed event connections. These use the real generated hub and SQLite with
  the repository's FastAPI request stubs; they are not deployed HTTP load tests.
- `:app:lintPhoneDebug` and `:app:testPhoneDebugUnitTest` with the WinnV3 and
  ApiLevelGate selections: Kotlin compilation/lint pass and 283 JVM tests pass,
  no failures or skips. JDK 21.0.12 was used. Flutter and Gradle verification
  held the shared release-build lock sequentially.
- Linux arm64 and x64 builder containers: all three changed translation units
  pass C++17 syntax compilation with warnings treated as errors. On both
  architectures, `tools/test_linux_tunnel_shutdown.py` compiles the actual stop,
  shutdown and signal callback functions, exercises real GLib normal exit and
  SIGINT/SIGTERM dispatch, and checks cleanup retries and repeated shutdown.
  GLib warnings/criticals are fatal in the harness. Privileged resource operations
  are recording fakes, so this does not prove actual firewall, cgroup or route
  removal on a packaged desktop application.
- `go test -race ./internal/carrier`: PASS, including the tracked H3 window test.
- `python3 build.py chrome` from `extension`: PASS, including producer gates and
  bridge contract checks. `python3 build.py --verify chrome
  dist/wins-vpn-companion-chrome.zip`: PASS. ZIP CRC passes, and all 26 members
  match the newly generated package directory. Browser enforcement regressions:
  12 tests pass.
- `bash -n server/wins_control_plane_setup_ONETOUCH.sh`: PASS.
- `sh tools/verify_rulings.sh`: PASS, 59 general and 6 Apple invariant checks.
- Source review and diff checks: original line endings preserved; no new long
  dashes or trailing spaces. Git whitespace checking uses `cr-at-eol` for the
  existing CRLF Linux files.

Chrome artifact: `extension/dist/wins-vpn-companion-chrome.zip`, 93,362 bytes.
SHA-256: `fede386e2395d7db4ef3d4b7542e57e5c9e348ed488c76db7fc11e602631ef31`.

The test harness still emits SQLite ResourceWarnings from other existing
initialization/fixture connections. The new tests explicitly retain and probe
the two repaired writers' connections to prove they are closed, rather than
inferring that property from an absence of warnings.

Android device verification is blocked. The Motorola USB-debugging phone is
connected, but `build/app/outputs/flutter-apk/app-release.apk` is absent.
`pwsh -NoProfile -File tools/build_android_release.ps1` exits 1 with:
`ReleaseInputIndex is required for every Android release build.` The owner was
asked for the reviewed `RELEASE_INPUT_INDEX.json` path. No uninstall, APK install,
launch or VPN logcat smoke test was performed. Once the index is supplied, build
the fresh release APK through the producer, uninstall `org.winsvpn.app`, install
that APK, launch it and inspect logcat as required by `AGENTS.md`.

Three Cursor/Grok implementation lanes were attempted and each exited because
of account usage limits. Workspace delegation also failed to initialize. The
lead performed implementation and final source review locally; no independent
model review is claimed.

Implementation references checked live on 2026-09-13: Python documents
[worker offload](https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread),
[explicit resource closing](https://docs.python.org/3/library/contextlib.html#contextlib.closing)
and [URL parser validation limits](https://docs.python.org/3/library/urllib.parse.html#url-parsing-security).
GLib documents [Unix signal sources](https://docs.gtk.org/glib-unix/func.signal_add.html).
