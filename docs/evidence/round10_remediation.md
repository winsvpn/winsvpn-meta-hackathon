# Round 10 source remediation

Date: 2026-09-13. Repository: `/Users/owner/xprize/winsvpnv3`.
Base commit: `89be66e75747c0b493583ca9c9efd7787c88a974`, with the existing dirty checkout preserved.

The ten explicitly requested repair groups are implemented. All 18 mandatory commands pass. This is source and local regression completion, not signed-package or deployed-system acceptance.

## Repairs

1. **A10-01:** Existing-slot replacement clears the three Winn v3 fields in the database and in-memory device config before updating the device ID. Changing the device, changing its AWG key, or fresh paid enrollment rotates the v3 identity. An authenticated reconnect with the same identity preserves it. Registry publication removes the evicted public key.
2. **A10-02:** `peer_has_current_authority` requires an active account, a parseable future expiration, matching device public key, and matching node management host. Each queued removal is reread in its own `BEGIN IMMEDIATE` transaction. The writer lock covers authority validation and remote removal. Reauthorized peers have their obsolete queue entry deleted without removal; failed removals retain durable retry state.
3. **A10-03:** Old-node registry publication now precedes the admission commit. Old-node failure restores the account/device transaction, records immediate refreshes for both gateways, marks management failed, and returns 503 with the activation still usable. Defensive review identified another remote side effect: the selected node's AWG installation happened before rollback. Both registry-failure branches now durably queue that per-device AWG peer for authority-checked cleanup. The selected-node failure branch also queues its registry refresh because remote publication may have succeeded before reporting failure. Shared double-VPN core peers are excluded from per-device cleanup.
4. **A10-04:** A conflicting forwarding-table owner is evicted only when registry authority no longer binds its authenticated key to that address. Live authorized owners retain collision protection. An old session's later close cannot erase the replacement mapping.
5. **A10-05:** The native host requires a nonempty origin allowlist containing the caller. Identity regressions cover empty, missing, foreign and prefix-extended caller configurations, plus a valid configured caller. Existing authentication tests receive an explicit caller so the new gate does not hide their original checks. The nonshipping bridge harness also receives an explicit fixture identity.
6. **DB-04:** Standalone Linux disconnect calls `StopTunnelPowerProtection()` alongside bypass teardown before checking cleanup success. Compiled teardown tests cover failure, retry, no-op cleanup, SIGINT and SIGTERM.
7. **DB-07:** Donor admin tests use `call_handler`, running only awaitable handler results through `asyncio.run`. Assertions and existing legal-contract changes are preserved.
8. **DB-08:** Windows oracles bind directory/file SDDL to their separate constants and exact security descriptors. ARM64 assertions cover the sealed release directory, both engine artifacts, architecture checks, receipt hashes and failure handling.
9. **SOL-L2:** Fire-and-forget startup paths call `startReady`, which catches initialization rejection and records a retry status. Awaited alarm/auth/message paths retain their failure behavior. Six lifecycle tests inject rejection and prove later retry.
10. **SOL-P1:** Every security-event database connection site in the hub, triage module, monitor and query CLI configures WAL, NORMAL synchronous mode, a 10-second busy timeout and foreign keys. WAL refusal raises an error. The regression checks the settings, 100 concurrent writes, unique IDs and absence of plaintext source addresses. Per-event retention/schema maintenance was outside the requested connection-configuration change and remains unchanged.

## Mandatory verification

Exact commands, working directories, durations and exit codes are in [mandatory-results.json](round10_remediation/mandatory-results.json). The installed Homebrew Python 3.14.7 and OpenSSL are selected through PATH. No dependency lockfile was changed.

| Command | Result |
| --- | --- |
| `flutter analyze --no-pub` | PASS, no issues |
| `flutter test --no-pub` | PASS, 1,926 passed, 2 existing opt-in skips |
| `python3 server/test_control_plane_deepseek_round2.py` | PASS, 11 tests |
| `python3 server/test_control_plane_round4.py` | PASS, 8 tests |
| `python3 server/test_control_plane_round5.py` | PASS, 16 tests |
| `python3 server/test_control_plane_round6.py` | PASS, 7 tests |
| `python3 server/test_control_plane_round7.py` | PASS, 17 tests |
| `python3 server/test_control_plane_round8.py` | PASS, 13 tests |
| `python3 server/test_control_plane_round9.py` | PASS, 9 tests |
| `python3 server/test_winn3_descriptor_hub.py` | PASS, 117 tests |
| `python3 server/test_account_deletion_hub.py` | PASS, 20 tests |
| `python3 server/test_donor_acknowledgment_hub.py` | PASS, 57 tests |
| `python3 tools/website_security_audit.py` | PASS, 56 checks, 1 existing explicit skip |
| `sh tools/verify_rulings.sh` | PASS |
| `python3 tools/verify_apple_method_channel_contract.py` | PASS |
| `python3 tools/test_apple_standalone_v3_wiring.py` | PASS, 7 tests |
| `python3 tools/test_windows_awg_runtime_validation.py` | PASS, 31 tests |
| `cd winn_protocol_experimental && go test ./...` | PASS, 106 tested packages |

The initial Flutter run correctly caught two untracked Go tests: the new forwarding regression and its existing `gateway_authority_test.go` fixture. Both were reviewed and staged, preserving the fixture's bytes. The integrity guard was not changed. Other newly added tests were staged as well. No commit or remote write was made.

## Additional verification and packages

- [Round 10 control-plane tests](../../server/test_control_plane_round10.py): 10 pass. SQLite state and writer contention are real; remote node operations are controlled doubles. Negative controls reproduce original defects and reject an intermediate candidate lacking AWG rollback cleanup.
- Gateway package tests pass with the race detector. The new stale-owner tests fail against the original forwarding implementation and pass after the fix, using established cryptographic sessions.
- Windows ARM64 readiness: 8 tests pass. Linux compiled teardown and power-inhibition harnesses pass. Native-host identity checks and all 6 extension lifecycle cases pass.
- All four extension bundles build with `python3 extension/build.py`. The requested literal `python3 extension/build.py all` was attempted and rejected because `all` is not a target token; the documented no-argument command builds all targets.
- Chrome, Edge and Firefox archives independently pass `python3 extension/build.py --verify TARGET ZIP`. Safari's source bundle builds, but its exact-target verification receipt is refused by the existing source-only/owner-identity gate. No Safari App Store readiness is claimed.
- [Package hashes](round10_remediation/extension-packages.json), [Round 10 patch](round10_remediation/repairs.diff), [changed-file hashes](round10_remediation/changed-files.json), and [source checks](round10_remediation/source-checks.json) bind this result. All 14 changed source/test files contain zero CR bytes. Added lines contain no em/en dashes or trailing whitespace. Unrelated tracked file content matches the starting manifest.

## Remaining boundaries

The requested origin gate intentionally refuses an absent allowlist. Existing native-host installers do not produce the reader's `allowed_origins.txt`, and the current production argv parser does not recognize Firefox's bare add-on ID. A broader supporting installer candidate was evaluated and excluded from the final patch: shipping it would require coordinated receipt, rollback, uninstall and packaged-installer changes. These broader integration gaps remain; the local origin-gate repair is not proof of a working installed browser bridge.

The optional 46-test native-registration suite has eight failures, reproduced identically using saved pre-change files. Six tests assume missing owner identity when this machine resolves one; two macOS fixtures stop at source-freeze verification before their intended assertions. Those gates were not weakened. Captured intermediate companion-candidate test results are not acceptance evidence for the final source.

SQLite ResourceWarnings from existing shared harnesses remain. Registry repair and peer cleanup are durable retries, not a distributed atomic transaction with remote nodes. No live hub, firewall, systemd service, payment provider, device install, signing operation, publication or deployment was performed. The task changed no Android app source, so no Android uninstall/install smoke test was triggered.

Six Cursor/Grok lanes were attempted and all stopped on usage limits before editing. Workspace subagent startup also failed. Local CLI lanes implemented disjoint gateway, native/Linux/Windows and extension/donor slices. The lead inspected their changes, retained the bounded requested fixes, repaired the additional AWG rollback edge identified by a Daybreak read-only review, and ran final checks. There is no independent final release-approval claim.

Technical references checked live: [SQLite transactions](https://www.sqlite.org/lang_transaction.html), [SQLite PRAGMAs](https://sqlite.org/pragma.html), [Python awaitable detection](https://docs.python.org/3/library/inspect.html#inspect.isawaitable), [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging), [Mozilla native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging), and [Go race detection](https://go.dev/doc/articles/race_detector).
