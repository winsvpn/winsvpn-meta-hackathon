# Round 8 requested remediation

Date: 2026-09-13. Workspace: `/Users/owner/xprize/winsvpnv3`.

All 12 requested repair groups are implemented. All 12 mandatory verification
commands pass. This is local source and package verification. Android physical
acceptance remains blocked, and the broader Android JVM suite retains five
artifact failures described below.

The existing dirty working tree was preserved. No commit, push, publication,
deployment, or release authorization occurred. Task-specific changes and hashes
are recorded in [repairs.diff](round8_remediation/repairs.diff) and
[changed-files.json](round8_remediation/changed-files.json).

## Repairs

| Finding | Implemented behavior |
| --- | --- |
| SOL-H2 | Rebuilt and verified Edge and Firefox ZIPs from the current extension source. A second deterministic build produced identical verified bytes. |
| A01 | Core assignments, customer AWG/Core resynchronization, and customer v3 registry exports require a parsed expiration strictly after the current UTC time. Customer `not_after` comes directly from that timestamp. The separately configured canary remains distinct from customer authorization. |
| A02 | Both duplicate-device deletion branches, old-peer replacement, Hoppy device revoke, and Hoppy device-limit reset call `queue_peer_revocation` inside the mutation transaction. Background tasks drain committed records. |
| A03 | A duplicate capture must have a processed event and a fresh PayPal GET confirming COMPLETED. Unconfirmed legacy records become failed. Fresh non-COMPLETED or missing provider results become failed and return 409 or 502. |
| A06 | Added the durable per-node registry refresh table, device insert/delete/update triggers, account status/expiration triggers, initial v3-node reconciliation, and bounded retry/backoff drain. Publication acquires a SQLite writer lock before reading its snapshot and retains it through the caller's transaction. The existing `account_expiry_revocation_sweep_loop` runs the drain through `asyncio.to_thread`; that is the actual background-loop name in this checkout. |
| SOL-H3 | Converted exactly 70 routes with no asynchronous operations to synchronous `def`. The async heartbeat alias now awaits `asyncio.to_thread(heartbeat, ...)`. Direct route callers and declaration assertions in affected tests were adapted without changing their policy assertions. |
| A04 / SOL-M2 | Linux power protection resolves systemctl, systemd-run, systemd-inhibit, and sleep through `Which`, passes those paths to the runner, and returns when required tools are unavailable. Stop independently resolves systemctl. |
| DB-04 | Android acquires a 60-second startup wake lock. Watchdog renewal is removed; explicit teardown release is retained. |
| SOL-M4 | Unexpected Android split-tunnel exclusion errors log at error level and throw the required IllegalStateException. Missing, uninstalled packages retain their existing dedicated handling. |
| SOL-M1 | All three Dart request payloads advertise `supports_xray: !Platform.isAndroid`. |
| SOL-L3 | Android identity assertions now match phone 1.0.16+33 and TV 3302. The historical superseded TV evidence assertion remains historical. |
| A07 / A10 / DB-02 / DB-03 / index | The rulings parser removes multiline block comments, preserves quoted strings and Markdown headings, and fails closed on parser errors. Removed the obsolete readVpnConfig/deleteVpnConfig exemptions from the actual `PLATFORM_SPECIFIC_METHODS` mapping. Updated the Debian non-upload identity to 1.0.16+33. Replaced the tvOS claim with the exact requested out-of-scope wording. The H3 receive-window test was already staged and was verified present in the index. |

All changed source and test files use LF with zero CR bytes. Existing ruled
decisions and `RULINGS.lock` were not changed by this task.

## Mandatory verification

| Command | Final result |
| --- | --- |
| `flutter analyze --no-pub` | PASS, no issues |
| `flutter test --no-pub` | PASS, 1926 passed, 2 existing opt-in skips |
| `python3 server/test_control_plane_deepseek_round2.py` | PASS, 11 tests |
| `python3 server/test_control_plane_round4.py` | PASS, 8 tests |
| `python3 server/test_control_plane_round5.py` | PASS, 16 tests |
| `python3 server/test_control_plane_round6.py` | PASS, 7 tests |
| `python3 server/test_control_plane_round7.py` | PASS, 17 tests |
| `python3 server/test_winn3_descriptor_hub.py` | PASS, 117 tests |
| `python3 server/test_account_deletion_hub.py` | PASS, 20 tests |
| `python3 tools/website_security_audit.py` | PASS, 56 checks, 1 existing skip |
| `sh tools/verify_rulings.sh` | PASS, 59 general and 6 Apple checks |
| `python3 tools/verify_apple_method_channel_contract.py` | PASS, 9 remaining exemptions re-proved |

Exact commands, exit codes, and log filenames are in
[final-suites.json](round8_remediation/final-suites.json) and
[flutter-results.json](round8_remediation/flutter-results.json).
Flutter and Android Gradle commands ran sequentially under task-owned repository
build locks. No other process's lock was removed.

## Additional verification

- New [Round 8 server tests](../../server/test_control_plane_round8.py): 13 pass.
  Coverage includes missing/invalid/exact-boundary expiration, Core exports,
  duplicate hardware/model cleanup and key rotation, Hoppy durable revocation,
  registry migration and triggers, rollback, missing-node backoff, logout to an
  empty registry, failed publication retry, and concurrent writer serialization
  with both fresh and deferred transactions. PayPal provider outcomes and
  duplicate confirmation states are exercised without provider access.
- Five selected new tests fail against the saved pre-fix source: 18 assertion
  failures and one error. This is an expected negative control, recorded in
  [negative-control.log](round8_remediation/negative-control.log).
- A real FastAPI/HTTPX ASGI request to the converted device-list route returns
  HTTP 200 while its database operation is blocked on a worker thread. The
  event loop remains responsive. Network and subprocess operations were denied.
  See [asgi-result.json](round8_remediation/asgi-result.json).
- All affected route suites pass: v3 serving 49, install-time carrier 36, Core
  dark-start 15, path MTU 28, descriptor signing 30, data-plane dark-start 17,
  and Hoppy Tier 1 23 tests.
- Three [rulings parser regressions](../../tools/test_rulings_round8.py) pass,
  including nested multiline comments, live literals, quoted URLs, Markdown
  headings, and an unterminated-comment failure for both search directions.
- Linux runner C++17 syntax checks with warnings treated as errors pass for
  arm64 and x64. The extracted production inhibitor functions compile and run
  on both architectures, including missing-tool, repeated-start, failed-start,
  retry, and stop cases. Containers had no network and mounted source read-only.
  See [linux-results.json](round8_remediation/linux-results.json).
- Go `go test -race ./internal/carrier`, 12 extension enforcement regressions,
  and the control-plane shell syntax check pass.
- Edge and Firefox verification passes. SHA-256 values:
  Edge `22734014d0f1caa7dff0c851f6de99d371d2309e737667ba6c25d290e3d90875`;
  Firefox `e5a9a17bbb21ecb51231c2cd67964401eba72d6ede604e9224db120ce6b9ec58`.

The server harness still emits existing SQLite ResourceWarnings. The website
skip concerns the absent optional `drop_in/lib/spa_service.dart`. These results
do not establish production provider behavior, real browser lifecycle behavior,
or physical gateway/desktop routing acceptance.

## Android status and remaining work

Kotlin compilation and lint completed with zero lint errors and 77 warnings.
The full phone JVM suite ran 591 tests: 586 passed, five failed. The updated
release identity test passes. All five failures are in
`ShippedEngineFreshnessTest`, as detailed in
[android-jvm-summary.json](round8_remediation/android-jvm-summary.json):

- Three debug ABI `libwinnengine.so` files are absent, causing two staged-engine
  inventory checks to fail.
- The existing phone debug APK has no Winn engine, causing two APK checks to
  fail. It was not installed on the phone.
- Native source freshness reaches the existing refusal for stale Windows
  native consumer authority paths. The Debian identity correction is applied;
  the subsequent Windows gate remains intact.

A Motorola USB-debugging phone is connected. The actual Android release
producer exits 1 with `ReleaseInputIndex is required for every Android release
build.` No `RELEASE_INPUT_INDEX.json` exists under the repository `.artifacts`
tree, and `build/app/outputs/flutter-apk/app-release.apk` is absent. See
[android-release-result.json](round8_remediation/android-release-result.json).

Resume physical verification with a valid reviewed input index and release
artifact. Then perform the required uninstall, install, launch, and logcat
sequence. Startup wake-lock expiry after 60 seconds and continued screen-off
tunnel operation remain unverified on the device. No phone uninstall or
installation occurred during this task.

Six preferred Cursor/Grok 4.6 Extra High lanes were launched and all exited
before work with account usage-limit errors. Workspace-agent startup also
failed. The lead completed implementation and review locally; no independent
model review is claimed.

Technical references checked live on 2026-09-13:
[FastAPI synchronous route offload](https://fastapi.tiangolo.com/async/),
[SQLite writer transactions](https://www.sqlite.org/lang_transaction.html),
[PayPal Orders integration](https://developer.paypal.com/api/rest/integration/orders-api),
and [Android VPN package exclusions](https://developer.android.com/reference/android/net/VpnService.Builder).
