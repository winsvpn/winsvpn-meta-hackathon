# Round 7 requested remediation

Date: 2026-09-13. Workspace: `/Users/owner/xprize/winsvpnv3`.

All ten requested defect groups are repaired in source. All eight mandatory
verification commands pass. Android connected-phone smoke is blocked by the
missing reviewed release input index and fresh release APK. These results cover
local source and executable tests, not deployed-service or release acceptance.

The [remediation diff](round7_remediation/remediation.diff) compares the changed
files against their bytes at the start of this task, including pre-existing
working changes. [Results, source hashes and log hashes](round7_remediation/results.json)
identify the tested state. No commit, push, deployment or release approval occurred.

| Requested defect | Implemented behavior |
| --- | --- |
| F02, Monero consensus | One accepted quote per normalized hostname. Non-finite and non-positive prices are rejected. Independent max/min spread must satisfy `(max - min) / min <= MONERO_PRICE_MAX_DEVIATION`. Even counts average the middle pair; odd counts use the middle value. Single-origin fallback requires a finite positive baseline within the deviation bound. Consensus still checks the persisted baseline. Arithmetic overflow fails with a controlled error. |
| F03, stale peers | Cleanup calls `queue_peer_revocation` in the device-deletion transaction, including when no background-task runner exists. |
| F04, slot replacement | Enrollment always issues and stores the hash of a fresh device bearer, including an occupied slot. The response returns it; ordinary authenticated reconnects retain their existing bearer. |
| F05, failed node sync | Both direct-peer and Double VPN exit-peer synchronization failures roll back admission before persisting node-management failure. Activation consumption, replacement credentials and new assignments roll back. |
| F09 / deletion offload | All four existing `/account/deletion/{status,request,confirm,cancel}` routes read the request body on the event loop, then run database/authentication/mutation work through synchronous helpers awaited with `asyncio.to_thread`. These are the actual route names in this checkout. |
| DB-04, account status | A device ID and matching account/device bearer are required before reading account metadata. Paid Dart status calls send the stored token through `Authorization: Bearer`, and skip requests if the token is absent. An account-epoch check follows the asynchronous token read. |
| DB-05, expiration | Active accounts with missing, blank, invalid or past expiration are expired and their runtime state is revoked transactionally. Admission checks again after acquiring its writer lock. |
| DB-12, duration | `DurationParseError` rejects invalid syntax and bounds days to 3650, months to 120 and years to 10. Life/lifetime/10y remain accepted. Provision, renew and redemption-batch inputs return HTTP 400 before database mutation. Invalid stored redemption durations no longer silently become one month. |
| DB-07 / M-1, Linux inhibitor | PID-file creation and PID-based kill are removed. A named user transient service starts via `systemd-run` and stops via `systemctl --user stop winsvpn-power-inhibit.service`. Repeated starts reuse an active service. |
| F11, socket diagnostics | The affected comparison is actually in `winn_protocol_experimental/winn3/carrier/udp_socket_buffers.go`, not the Linux runner. Linux/Android raw getsockopt grants are divided by two for comparison. Raw diagnostic values are preserved; other operating systems retain their existing units. |

The stricter expiry rule exposed two necessary compatibility changes. Free
admission previously stored `FREE_ACCESS_LABEL` as the database expiration. It
now stores the existing ten-year `lifetime_expiry()` timestamp, refreshed by free
admission, while responses retain the free-access label. Legacy lifetime
migration now runs only when its original snapshot table is absent. After that
migration, newly missing expirations cannot silently become new ten-year grants.
The expiry regression fixture now supplies device authentication. The DeepSeek
suite now owns a separate database per test, removing cross-test migration
contamination without weakening assertions.

| Mandatory command | Final result |
| --- | --- |
| `flutter analyze --no-pub` | PASS, no issues, exit 0 |
| `flutter test --no-pub` | PASS, 1926 passed, 2 existing opt-in live tests skipped, exit 0 |
| `python3 server/test_control_plane_deepseek_round2.py` | PASS, 11 tests, exit 0 |
| `python3 server/test_control_plane_round4.py` | PASS, 8 tests, exit 0 |
| `python3 server/test_control_plane_round5.py` | PASS, 16 tests, exit 0 |
| `python3 server/test_control_plane_round6.py` | PASS, 7 tests, exit 0 |
| `python3 server/test_winn3_descriptor_hub.py` | PASS, 117 tests, exit 0 |
| `python3 tools/website_security_audit.py` | PASS, 56 checks, 1 explicit skip, zero failures, exit 0 |

Additional verification:

- New Round 7 server suite: 17 tests pass, including adversarial quote inputs,
  durable revocation rollback/drain, replaced-bearer rejection, both node-sync
  rollback branches, account/device/token isolation, invalid expiration and
  writer-lock recheck, free-access compatibility, bounded duration HTTP errors,
  and all four deletion routes under actual SQLite writer contention. The same
  suite against saved pre-fix source fails as expected. Provider/node calls are
  fakes and FastAPI/Pydantic/calendar types come from the existing test harness.
- Existing account deletion: 20 tests pass. Existing expiry/revocation: 4 pass.
  Existing cryptocurrency payment tests: 7 pass.
- Go carrier package: `go test -race ./winn3/carrier` passes on Darwin arm64.
  Cross-compiled Linux arm64 and amd64 socket-buffer tests also pass inside
  offline builder containers, including real loopback sockets and getsockopt
  readbacks. This is not a throughput or physical-device benchmark.
- The entire changed Linux runner translation unit passes C++17 syntax
  compilation with `-Wall -Wextra -Werror` on Linux arm64 and x64. The new
  inhibitor harness compiles and executes the actual production functions on
  both architectures, testing repeated start, stop, failed start and retry with
  a recording command runner. Actual desktop systemd/logind inhibition remains
  unverified.
- `bash -n` passes. All 59 general plus 6 Apple ruled invariants pass. Original
  newline formats are preserved; task-added lines contain no long dashes or
  trailing whitespace. Flutter commands held the shared release-build lock
  sequentially, and the task-owned lock was removed after verification.

The website skip concerns the absent `drop_in/lib/spa_service.dart`. Server
harnesses continue to emit existing SQLite ResourceWarnings from initialization
and fixture connections; the warning output is retained in the logs.

Android smoke is BLOCKED. A Motorola USB-debugging phone is connected, but
`build/app/outputs/flutter-apk/app-release.apk` is absent. The actual command
`pwsh -NoProfile -File tools/build_android_release.ps1` exits 1 with
`ReleaseInputIndex is required for every Android release build.` No reviewed
`RELEASE_INPUT_INDEX.json` was found in the checked repository artifact/docs
paths. The owner was asked for its path. No uninstall, APK installation, launch
or logcat smoke was performed. Resume with the reviewed index, build through
the producer, then uninstall/install/launch and inspect logcat as required by
`AGENTS.md`.

Both preferred Cursor/Grok lanes initialized with the requested model and then
failed account usage limits before making edits. Workspace-agent delegation
failed initialization. The lead performed implementation and final diff review
locally; no independent model review is claimed.

Technical references checked live on 2026-09-13:
[Python worker offload](https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread),
[finite Decimal values](https://docs.python.org/3/library/decimal.html#decimal.Decimal.is_finite),
[upstream systemd-run documentation](https://github.com/systemd/systemd/blob/main/man/systemd-run.xml),
and [Linux socket-buffer accounting](https://www.man7.org/linux/man-pages/man7/socket.7.html).
