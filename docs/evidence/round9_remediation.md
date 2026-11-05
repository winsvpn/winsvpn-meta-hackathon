# Round 9 source remediation

Date: 2026-09-13. Repository: `/Users/owner/xprize/winsvpnv3`.
Base commit: `89be66e75747c0b493583ca9c9efd7787c88a974`, with substantial pre-existing staged, unstaged and untracked work preserved.

All eight requested repair groups are implemented. All 15 mandatory commands exit 0. These are local source and regression results, not deployed or signed-release acceptance.

## Repairs

- **A9-01:** Gateway bindings retain expiration and recheck it on every authorized lookup. Registry refresh compares file identity, modification time, size and mode on a one-second cadence. Read or parse failure clears cached authority. Handshakes force a reload. Return-path lookup checks the authenticated session key against the current address binding, and the forwarding table receives the registry before TUN startup. Registry reads are capped at 1 MiB.
- **A9-02:** Runtime expiration now includes equality. Sweep selection uses the same date parser through a SQLite function with a frozen current time, covering missing, malformed and offset timestamps.
- **A9-04:** Selected-gateway publication occurs before the admission commit. Failure rolls back activation consumption and device creation, then records failed node management in a separate transaction. The regression proves the same single-use activation succeeds after publication recovers and returns the committed bearer.
- **A9-06 / DB-05 / SOL-04:** AI rate limiting, complete PayPal and BTCPay webhook processing, admin authentication and peer resync, Monero database phases, startup schema initialization, account deletion sweeps, emergency acceptance and backlog notification run in workers. Request-body reads remain asynchronous. SQLite connections stay on their creating worker.
- **A9-05 / SOL-05:** Linux RunArgv creates a dedicated process group, reads capture pipes without blocking, checks a monotonic deadline even during endless output, and uses poll plus nonblocking child checks. The default timeout is 15 seconds, followed by a two-second group termination grace and SIGKILL. Timeout status is 124. Signal refusal cannot send the caller into an unbounded blocking reap.
- **DB-04 / SOL-03:** iOS checks measured physical footprint against 15 MiB at admission and once per second during a Winn session. Reaching the ceiling, or an unusable runtime sample, cancels with error 1038. Generation and timer-identity checks share the lifecycle gate, preventing a stale callback from canceling a replacement. Start replacement, stop and cancellation release the watchdog. The existing 12 MiB OS headroom reserve remains a separate check; it is not added to the physical-footprint threshold.
- **DB-06 / SOL-08:** Legacy SPA rules use `WINVPN-HUB-INPUT`. Each opening has a unique rule comment and an independent systemd cleanup timer armed before insertion, expiring after 20 seconds. Timer scheduling failure refuses the opening; insertion failure or timeout attempts immediate cleanup. Firewall commands run outside the event loop.
- **DB-03:** The Apple wiring oracle uses `validateUniqueWinnSecurityBindings` and the current transient node-identity helper. The Apple ownership fixture includes the new watchdog-stop dependency. The broader emergency fixture now invokes its existing synchronous admin route correctly.

## Required verification

Every command below passed. Exact arguments, start times, durations, working directories and log paths are in [mandatory-results.json](round9_remediation/mandatory-results.json).

| Command | Result |
|---|---|
| `flutter analyze --no-pub` | No issues |
| `flutter test --no-pub` | 1,926 passed, 2 existing opt-in live tests skipped |
| `python3 server/test_control_plane_deepseek_round2.py` | 11 passed |
| `python3 server/test_control_plane_round4.py` | 8 passed |
| `python3 server/test_control_plane_round5.py` | 16 passed |
| `python3 server/test_control_plane_round6.py` | 7 passed |
| `python3 server/test_control_plane_round7.py` | 17 passed |
| `python3 server/test_control_plane_round8.py` | 13 passed |
| `python3 server/test_winn3_descriptor_hub.py` | 117 passed |
| `python3 server/test_account_deletion_hub.py` | 20 passed |
| `python3 tools/website_security_audit.py` | 56 passed, 1 existing explicit skip |
| `sh tools/verify_rulings.sh` | Passed |
| `python3 tools/verify_apple_method_channel_contract.py` | Passed |
| `python3 tools/test_apple_standalone_v3_wiring.py` | 7 passed |
| `cd winn_protocol_experimental && go test ./...` | Passed, 106 packages with passing tests |

The test PATH uses the installed Homebrew Python 3.14.7, OpenSSL and Bash alongside the local Flutter and Go launchers. The module resolves its declared Go 1.27.0 toolchain. No dependency or lockfile was changed.

## Additional evidence

- [Round 9 control-plane tests](../../server/test_control_plane_round9.py): 9 passed, including real SQLite contention, parsed expiration, activation retry, worker-thread checks, SPA command custody and replay rejection. Six tests reject the saved original source for the expected defects: [negative control](round9_remediation/server-negative.log).
- Seven new gateway authority tests cover active expiration, revocation/restoration, cached errors, metadata and atomic replacement, forced handshake refresh, an authenticated return-path session, and concurrent refresh. Gateway race tests, vet and a Linux amd64 cross-build pass. [Race receipt](round9_remediation/gateway-race.log), [original-source rejection](round9_remediation/gateway-negative.log).
- [Linux runtime tests](round9_remediation/linux-runargv.log): 9 passed in the existing arm64 builder with networking disabled and the repository mounted read-only. Quiet, noisy, TERM-resistant and descendant-holding helpers, output overflow, EINTR, all output modes, the default deadline and signal refusal are exercised. The lane also passed AddressSanitizer/UndefinedBehaviorSanitizer checks and three negative controls. [Sanitizers](round9_remediation/linux-sanitizers-gcc.log), [negative controls](round9_remediation/linux-negative-controls.log).
- [iOS watchdog tests](round9_remediation/apple-watchdog.log): 6 passed, including extracted production Swift, a real repeating timer, exact threshold boundaries, stale callbacks, cancellation/replacement races, NetworkExtension typechecking and the actual footprint reader. Provider Swift parsing passes. [Apple ownership tests](round9_remediation/apple-ownership.log) pass for both engine paths on both platforms.
- The complete emergency relay suite passes 33 tests; cryptocurrency configuration tests pass 7. Embedded Python parsing, shell syntax and scoped diff checks pass.
- All 13 changed source/test files contain zero CR bytes. Unrelated tracked deltas match the saved baseline. [File hashes](round9_remediation/changed-files.json), [this round's patch](round9_remediation/repairs.diff), [source checks](round9_remediation/source-checks.json).

Three preferred Cursor/Grok lanes exited before work due to usage limits, and workspace-agent startup failed. Three independent local Codex CLI lanes then completed the gateway, Linux and Apple slices. The lead implemented the control-plane changes, inspected the lane diffs, corrected the Apple integration details and ran the required suites. No commit, push, signing, device installation, publication or deployment occurred.

## Remaining verification boundaries

The one-second registry cadence bounds ordinary refresh detection, not stalled filesystem operations or packets already authorized. The iOS watchdog enforces observed samples; it cannot prove memory never crosses the ceiling between ticks. Real iOS stress, jetsam and route recovery remain unverified. Linux group containment assumes signalable children that remain in the group; elevated or escaped descendants and uninterruptible kernel waits are outside the demonstrated cleanup guarantee. SPA timer construction and failure behavior were tested with subprocess doubles, not a live hub firewall or systemd timer. SQLite rollback is not a distributed transaction with a remote gateway.

Existing SQLite ResourceWarnings remain in the server harness. The website skip is the optional absent `drop_in/lib/spa_service.dart`. The two Flutter skips are existing live tests. This task made no Android source changes and did not change the earlier device/release gates.

Technical references checked live on 2026-09-13: [Python worker offload](https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread), [FastAPI route execution](https://fastapi.tiangolo.com/async/), [SQLite deterministic functions](https://sqlite.org/deterministic.html), [Go file metadata](https://pkg.go.dev/os), [POSIX process groups](https://pubs.opengroup.org/onlinepubs/9799919799/functions/posix_spawn.html), [Apple dispatch cancellation](https://developer.apple.com/documentation/dispatch/dispatchsourceprotocol/cancel%28%29), and [systemd timer scheduling implementation](https://github.com/systemd/systemd/blob/main/src/run/run.c).

## 2026-09-13 continuation: Round 10

The ten requested Round 10 repair groups are implemented, including identity rotation, authority-checked revocation, rollback repair queues, stale forwarding-owner eviction, strict native origins and Linux inhibitor teardown. All 18 mandatory checks pass. See [Round 10 remediation](round10_remediation.md) for exact results, source custody, extension packages and remaining native-installer/Safari verification boundaries. Existing unrelated work is preserved; no publication or deployment occurred.
