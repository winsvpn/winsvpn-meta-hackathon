# Round 4 requested remediation

Date: 2026-09-13. Workspace: `/Users/owner/xprize/winsvpnv3`.
Base HEAD: `89be66e75747c0b493583ca9c9efd7787c88a974`, with existing owner changes preserved.

The eight requested source repairs are implemented. The three required checks
pass. This is source-remediation evidence, not release or deployment acceptance.
No commit, push, publication, deployment, signing, or device installation ran.
Exact repaired file hashes are in [source-manifest.json](round4_remediation/source-manifest.json).
The native-messaging Dart path is a pre-existing symlink to the repaired shared
library, not an additional edited implementation.

| Item | Implemented behavior |
| --- | --- |
| 1. Activation consumption | Enrollment calls the existing atomic activation consumer inside the admission writer transaction. Replays, used markers, malformed expiry, and expired keys reject. Bearer reconnects do not consume a new key. Rejected pre-commit admission rolls back consumption. |
| 2. Worker offload | The six named entry points delegate blocking work through `asyncio.to_thread`. Each worker owns its SQLite connections. The internal Core readiness wait runs synchronously inside the existing verify worker after its transaction is committed. |
| 3. Log pseudonym | The pre-authorization verify INFO record hashes the normalized account identifier. Raw identifiers and injected newlines do not reach this record. |
| 4. Linux pipes | Both child stdin paths use nonblocking writes and a monotonic 5000 ms deadline checked across partial progress, EINTR, and poll retries. The process ignores SIGPIPE. The standalone TUN writer is unchanged. |
| 5. Android APIs | minSdk is 26; the native key-custody API 30 gate and helpers have machine-readable annotations. The removed ProfileInstallReceiver has a targeted MissingClass annotation. |
| 6. Dart aliases | All supplied version aliases survive normalization, including malformed values. Compact-only values retain a canonical value for existing consumers. Strict parsing precedes tunnel dispatch and rejects disagreement in either order. Only absence defaults to v1. |
| 7. Apple proof ownership | Both providers register proving objects under the lifecycle gate. Stop and superseding starts capture them; promotion clears matching pending identity atomically. Proof failures clear identity after teardown. A separate stop lock serializes failure teardown with stopTunnel. |
| 8. Windows pipe | Client and service share the correctly escaped protected Administrators pipe name. The portable wire-contract test pins its exact runtime string. |

Android lint exposed two additional callsite details needed for the API repair:
`nativeHeldDirectoryNames` also needed `@RequiresApi(R)`, and the protected UDP
probe in `VpnTunnelService.kt` called API 30 `Os.fcntlInt` without a guard.
The probe now creates its socket nonblocking using Android's documented
`O_NONBLOCK` compatibility flag, keeping the API 26 floor without swallowing a
failure to set nonblocking mode. No lint baseline or broad suppression was added.

## Verification

All commands ran from the repository unless noted. `python3` for server tests
was resolved to Homebrew CPython 3.14.7 by putting its directory first in PATH.
The shell's original `/usr/bin/python3` is 3.9.6 and was rejected by the existing
server preflight; it was not treated as a test pass.

| Check | Result |
| --- | --- |
| `flutter analyze --no-pub` | PASS, no issues, exit 0 |
| `python3 server/test_control_plane_deepseek_round2.py` | PASS, 11 tests, exit 0 |
| `python3 tools/website_security_audit.py` | PASS, 56 pass, 1 explicit skip, 0 fail, exit 0. The skip is the absent `drop_in/lib/spa_service.dart` source scan. |
| `flutter test --no-pub --concurrency=1` | PASS, 1924 tests, 2 skips, exit 0 |
| Focused Flutter protocol/normalization/fallback tests | PASS, 216 tests, exit 0 |
| `python3 server/test_control_plane_round4.py` | PASS, 8 tests with sequential/concurrent enrollment, used/expired/malformed keys, reconnect, pre-commit rollback, log injection, SQLite contention, and all six worker boundaries |
| Same new server suite against the captured pre-repair script | Expected failure, 12 failing subcases. This is a negative control, not a candidate failure. |
| Real ASGI probe | PASS with FastAPI 0.139.2, Starlette 1.3.1, Pydantic 2.13.4. Sequential statuses 200/401; concurrent statuses 200/401/401/401. Under a 350 ms SQLite lock, 10 ms timers completed in 10.8 to 12.2 ms. Outbound connections and subprocesses were denied; lifespan startup did not run. |
| `python3 server/test_winn3_serving_hub.py` | PASS, 49 tests |
| `python3 server/test_protocol_selection_hub.py` | PASS, 20 tests |
| `python3 server/test_paid_refresh_authorization_hub.py` | PASS, 2 tests |
| `python3 tools/test_linux_engine_pipe.py` | PASS, both actual extracted writers compiled with warnings as errors. Partial payload, closed reader, full pipe, and repeated EINTR passed. Saturation measured 5000 to 5001 ms. Executed on macOS POSIX pipes. |
| `python3 tools/test_apple_proving_ownership.py` | PASS, extracted production ownership statements and real operation gate compiled and ran for iOS/macOS relay/standalone. Stop precedes completion, stale publication rejects, and concurrent failure teardown is awaited. Engines are test doubles. |
| `xcrun swiftc -typecheck apple/WinsTunnelCore/*.swift ios/PacketTunnel/PacketTunnelProvider.swift` | PASS |
| Same Swift typecheck for macOS provider | PASS |
| Portable Windows service client contract | PASS, 69 checks, compiled with C++17 and warnings as errors |
| `./gradlew :app:lintPhoneDebug :app:testPhoneDebugUnitTest --tests 'org.winsvpn.app.WinnV3*' --tests 'org.winsvpn.app.ApiLevelGateTest' --offline` from `android/` | PASS, lint plus 283 focused JVM tests. Lint retains existing warnings. |
| `sh tools/verify_rulings.sh` | PASS, 59 general plus 6 Apple route checks |
| `bash -n server/wins_control_plane_setup_ONETOUCH.sh` | PASS |
| Host syntax check of both Linux host translation units | PASS with `-Wno-unused-const-variable` for the existing Linux-only constant unused by macOS preprocessing. The extracted changed writers independently pass all warnings as errors. |
| Remediation-only whitespace check | PASS. Whole-checkout diff checking also sees pre-existing CRLF/trailing-space changes outside this repair. |

The real ASGI result is [asgi-result.json](round4_remediation/asgi-result.json).
Its [probe](round4_remediation/asgi_probe.py) reads the current installer through
the existing harness, with framework stubs disabled. Run it with an interpreter
containing the listed framework dependencies. The normal regression entry
points remain dependency-light and run against isolated SQLite files.

## Remaining limits and unrelated failures

- The USB Motorola phone was detected. `build/app/outputs/flutter-apk/app-release.apk`
  is absent. The formal PowerShell Android producer refuses without
  `ReleaseInputIndex`; no valid index was available in the checkout. Therefore
  uninstall/install/launch/logcat smoke testing of this repair did not run.
- The broader Android JVM run completed 591 tests with 6 failures: a pre-existing
  identity test still pins 1.0.15+30, while the starting tree already used
  1.0.16+33; five ShippedEngineFreshness tests fail on missing/stale debug engine
  packaging or the existing blocked native inventory. These were not bypassed
  or rewritten to manufacture a green release result.
- `tools/test_apple_standalone_v3_wiring.py` has one existing failure in seven
  tests: it expects `try validateUniqueWinnNodeBindings(rawConfig)` in
  `WinsTunnelConfig.swift`. That core file is byte-identical to the start-of-turn
  baseline. The proof-ownership tests and both provider typechecks pass.
- Real Linux full-application teardown, Windows unprivileged pipe creation,
  signed Apple extension lifecycle, and Android API 26/30 device coverage
  remain target acceptance work. Local source checks do not establish those.
- Six preferred Cursor/Grok 4.6 Extra High lanes were launched and each exited
  with an account usage-limit error before doing work. The workspace agent
  fallback also failed to initialize. The lead completed implementation and
  validation locally; no active external review lane is claimed.

## Primary references checked on 2026-09-13

- Python blocking-I/O offload and SQLite connection ownership: [asyncio.to_thread](https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread), [sqlite3](https://docs.python.org/3/library/sqlite3.html).
- Pipe backpressure, SIGPIPE, and polling behavior: [pipe(7)](https://man7.org/linux/man-pages/man7/pipe.7.html), [poll(2)](https://man7.org/linux/man-pages/man2/poll.2.html).
- Android API annotations and nonblocking socket compatibility: [AndroidX annotations](https://developer.android.com/reference/androidx/annotation/package-summary), [OsConstants](https://developer.android.com/reference/android/system/OsConstants).
- Alias presence checks: [Dart Map.containsKey](https://api.dart.dev/dart-core/Map/containsKey.html).
- Apple lifecycle contract: [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider).
- Protected prefix used by Microsoft's runtime package: [hcsshim/runhcs SafePipePrefix](https://pkg.go.dev/github.com/Microsoft/hcsshim/internal/runhcs#pkg-constants).
