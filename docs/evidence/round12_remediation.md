# Round 12 remediation

Date: 2026-09-13 UTC. Repository: `/Users/owner/xprize/winsvpnv3`.
Base commit: `89be66e75747c0b493583ca9c9efd7787c88a974`, with its existing dirty working tree preserved.

All eight requested target groups are implemented. **All 20 mandatory commands pass.** The new Round 12 suite passes 17 tests, and real FastAPI requests independently confirm admission ordering, the enrollment conflict response, webhook retries, and bound-price settlement. This is local source and regression evidence, not a cross-platform release approval.

The supplemental native registration suite passes 46 of 48 tests. Its two remaining macOS helper failures also reproduce using the exact pre-edit test bytes: both stop at an existing authenticated source-freeze requirement. The Linux native delivery suite passes all nine tests under pristine Python. These results are reported separately below.

## Repairs

### 1. A12-01: ordinary AWG admission and compensation

In `server/wins_control_plane_setup_ONETOUCH.sh:21149`, ordinary AWG installation now follows deterministic route, obfuscation, capability, protocol, descriptor, and per-device descriptor-material eligibility checks. Invalid route and obfuscation registrations return 503 without invoking the remote installer, creating a device, or consuming activation. Controlled capability and descriptor refusal tests also prove the ordering.

An unsuccessful AWG synchronization still rolls back tentative local authority, queues the attempted public key and node in the durable peer-revocation outbox, marks management failed, and commits that repair record before returning 503. A new regression exercises the actual synchronization function with a subprocess timeout. The existing Round 11 uncertain-install and outbox-drain regression also passes. Shared Double VPN Core exit peers retain their existing ownership path.

This repair does not establish crash recovery for every possible interruption between a successful remote installation and the final database commit. Those broader distributed-transaction windows were not claimed fixed by this target.

### 2. SOL-M1: Double VPN enrollment lease

The schema now includes `double_vpn_enrollment_leases`, keyed by account, with an unguessable ownership token, device identity, and expiration. Acquisition occurs within the admission transaction before device or assignment mutation. Its unique account key rejects a second preparer with HTTP 409, `X-Wins-Error-Code: double_vpn_enrollment_in_flight`, and `Retry-After: 5`.

The reservation survives the intermediate commit needed for Core readiness. `ExitStack` releases it after the primary connection closes, including timeout and exception exits. Cleanup matches the ownership token, so an older worker cannot delete a replacement lease. Expiration permits recovery after a crashed worker. Final admission also requires the same unexpired lease before consuming activation, closing a stale-worker gap in the proposed audit patch. See installer lines 7792, 14100, 14142, 20599, and 21442.

The concurrency regression and real HTTP probe demonstrate one preparer, one device, one active assignment, first-request success, second-request 409, and zero remaining leases. Timeout retries preserve the activation secret. Lease replacement and stale cleanup are tested separately. The transaction design was checked against [SQLite's transaction documentation](https://www.sqlite.org/lang_transaction.html) on 2026-09-13.

### 3. A12-02: webhook reservation and delivery ordering

Both PayPal and BTCPay handlers now distinguish a terminal duplicate from a live processing reservation. Only `processed` and `ignored` records receive successful duplicate acknowledgments. In-flight work returns 409 with `Retry-After: 10`, preserving the provider's retry signal without modifying another worker's reservation.

An early BTCPay settlement notification whose authoritative invoice is still processing now raises a retryable 409. The existing exception path durably marks the reservation failed, allowing the next settlement delivery to reacquire it immediately. The Round 9 regression oracle was updated from successful `pending` to 409 plus a persisted failed reservation. See installer lines 25640 and 25934.

Actual HTTP probes verify early BTCPay delivery followed by successful final settlement, terminal duplicate acknowledgment, two provider reads, and one activation outbox row. Tests also cover expired processing leases. This matches [PayPal's documented non-2xx retry behavior](https://developer.paypal.com/api/rest/webhooks) and BTCPay's distinction between [payment settlement and invoice settlement](https://docs.btcpayserver.org/Development/ecommerce-integration-guide/#invoice-webhook-events), checked live on 2026-09-13. Provider-side automatic redelivery settings were not inspected.

### 4. A12-03: lifetime purchase price binding

The bound BTCPay settlement contract no longer rechecks the live lifetime catalog price after verifying the stored purchase price. The handler retains invoice/order identity, plan, currency, positive amount, exact requested amount, and sufficient payment checks. Explicit finite-number checks were added for requested, paid, and expected amounts before decimal comparisons. See installer line 26039.

A purchase bound at USD 10.00 now settles when the catalog has changed to USD 20.00, with exactly one account grant and activation delivery. Negative cases reject underpayment, changed requested amount, wrong currency, mismatched order or plan, NaN, and infinity. Existing production invoices or manual-review records were not replayed or changed.

### 5. A12-06: journal checkpoint ordering

The generated monitor requires successful `journalctl` execution and advances its timestamp only after processing the returned lines. Failed reads, subprocess timeouts, and processing exceptions retain the previous checkpoint. A missing checkpoint starts with a bounded 60-second lookback and is created only after a successful read.

Checkpoint publication uses a same-directory temporary file, file fsync, atomic replacement, and directory fsync. Tests cover existing and absent checkpoints, read failures, timeouts, successful processing, processing exceptions, and temporary-file cleanup. See installer lines 32743 and 32759. The time-window arguments were checked against [journalctl documentation](https://www.freedesktop.org/software/systemd/man/255/journalctl.html) on 2026-09-13. This remains timestamp-based monitoring; it does not prove journal durability, retention, or email delivery.

### 6. A12-07: triage and alert SQLite lifecycle

All six SQLite contexts in the generated triage module and all three in the alert monitor now combine explicit connection closing with the connection's transaction context. Transaction commit or rollback runs before close, including exception exits.

The regression retains strong references to every instrumented connection, verifies immediate closure without garbage collection, checks persisted updates, and exercises classification, feedback, reclassification, listing, reporting, event recording, email-status updates, and alert formatting under success and database failures. This follows [Python's documented connection context-manager behavior](https://docs.python.org/3/library/sqlite3.html#how-to-use-the-connection-context-manager), checked on 2026-09-13. Existing broader hub test harnesses still emit some ResourceWarnings; those are not presented as proof that these nine corrected contexts leak.

### 7. SOL-M3: native-messaging test isolation

`tools/native_messaging/test_native_host_registration.py:55` now assigns absent or blank owner-identity overrides to a nonexistent path inside a temporary directory and restores the caller's environment afterward. Two child-process environments retain that isolated path instead of clearing it. The placeholder-manifest test also creates its own temporary manifest inputs instead of assuming the working tree still contains placeholders.

The missing-Chrome and missing-Edge cases in `tools/test_linux_native_host_delivery.py:314` and `:353` use temporary missing identity receipts. No production binder or authenticated source-freeze check was relaxed.

### 8. SOL-L1 / SOL-L3: Go expiry and LF hygiene

The brittle expiry test was found in `winn_protocol_experimental/cmd/winn3-gateway/gateway_authority_test.go:163`. It now observes the integer-second expiration condition in a short polling loop instead of assuming one sleep reaches that wall-clock boundary. The complete Go module, gateway race suite, and ten repeated expiry runs pass. Runtime expiry comparisons were not changed. [Go time documentation](https://pkg.go.dev/time) was checked on 2026-09-13.

`pubspec.yaml` and the modified Linux test were normalized from CRLF to LF. One whitespace-only pubspec line was cleaned. Every source, test, and evidence file written by this remediation has zero carriage returns. Added source lines contain no em or en dashes and no trailing whitespace.

## Mandatory verification

The final per-command ledger records command arguments, working directory, start time, duration, exit code, and log: [mandatory-results.json](round12_remediation/mandatory-results.json). Initial attempts remain in [check-results.json](round12_remediation/check-results.json). The final Round 9 run supersedes an initial fixture assertion that referenced headers discarded by the existing stub; real HTTP probes independently verify the headers.

| Command | Final result |
| --- | --- |
| `flutter analyze --no-pub` | PASS, no issues |
| `flutter test --no-pub` | PASS, 1,927 passed, 2 existing skips |
| `python3 server/test_control_plane_deepseek_round2.py` | PASS, 11 tests |
| `python3 server/test_control_plane_round4.py` | PASS, 8 tests |
| `python3 server/test_control_plane_round5.py` | PASS, 16 tests |
| `python3 server/test_control_plane_round6.py` | PASS, 7 tests |
| `python3 server/test_control_plane_round7.py` | PASS, 17 tests |
| `python3 server/test_control_plane_round8.py` | PASS, 13 tests |
| `python3 server/test_control_plane_round9.py` | PASS, 9 tests |
| `python3 server/test_control_plane_round10.py` | PASS, 10 tests |
| `python3 server/test_control_plane_round11.py` | PASS, 6 tests |
| `python3 server/test_winn3_descriptor_hub.py` | PASS, 117 tests |
| `python3 server/test_account_deletion_hub.py` | PASS, 20 tests |
| `python3 server/test_donor_acknowledgment_hub.py` | PASS, 57 tests |
| `python3 tools/website_security_audit.py` | PASS, 56 checks, 1 explicit skip |
| `sh tools/verify_rulings.sh` | PASS, 59 invariant checks and 6 Apple checks |
| `python3 tools/verify_apple_method_channel_contract.py` | PASS |
| `python3 tools/test_apple_standalone_v3_wiring.py` | PASS, 7 tests |
| `python3 tools/test_windows_awg_runtime_validation.py` | PASS, 31 tests |
| `cd winn_protocol_experimental && go test ./...` | PASS |

Flutter commands ran sequentially under a task-owned release-build lock. Independent server, Go, and platform groups ran concurrently. The task released only its own lock.

## Additional evidence and remaining limits

- [New regression suite](../../server/test_control_plane_round12.py): 17 passing tests. [Log](round12_remediation/round12-final.log).
- [Real FastAPI probe](round12_remediation/asgi_probe.py) and [results](round12_remediation/asgi-results.json): actual ASGI routing and HTTP responses, real SQLite, and local signing. Network connections are denied by the fixture's audit hook; provider, remote peer, readiness, and background delivery boundaries are controlled.
- [Negative-control results](round12_remediation/negative-control-results.json): all 11 selected behavioral tests reject saved pre-edit installer bytes, producing 16 failing assertions/subtests and one expected settlement error. The same current-source cases pass. The original repository file was never replaced for these probes.
- [Go race log](round12_remediation/go-race.log) and [ten-run expiry log](round12_remediation/go-expiry-repeat.log): PASS.
- `python3 -I -S tools/test_linux_native_host_delivery.py`: 9/9 PASS. [Log](round12_remediation/linux-native-delivery-pristine.log). Plain Python stopped at the production import-custody boundary because its import environment was not pristine.
- `python3 -I -S tools/native_messaging/test_native_host_registration.py`: 46/48 PASS. [Log](round12_remediation/native-registration-final.log). `test_macos_helper_first_rollback_failure_still_restores_later_files` and `test_macos_helper_owner_blocks_edge_without_touching_live_registration` both stop before their intended scenario because an authenticated native-host source-freeze receipt is unavailable. Both failures reproduce against exact pre-edit test bytes: [baseline results](round12_remediation/native-baseline-results.json). Neither is counted as a pass or silently skipped.
- Shell syntax, three generated Python modules, and modified Python tests compile. Targeted tracked-file whitespace checks pass. New Python test files have no trailing whitespace. [Syntax and whitespace evidence](round12_remediation/syntax-and-whitespace.json). The `git diff --no-index --check` entry exits 1 with empty diagnostics because the compared new file differs from `/dev/null`; it is not counted as a command pass.

No node deployment, payment, external message, signing operation for a release, phone installation, push, commit, or release approval occurred. Test signing used local fixture keys only. Native/browser/device acceptance and the broader audit's deployment and source-custody findings are outside the eight requested source repairs.

Preferred Cursor/Grok 4.6 Extra High lanes were attempted for native tests and Go timing; both exited at usage limits before doing work. The fallback worker service could not create a thread. The lead completed the edits and verification locally. No independent model review is claimed.

## Change custody

[Source checks](round12_remediation/source-checks.json) contain exact before/after hashes, line-ending checks, and comparison against the initial 3,795-file tracked manifest. Only the five intended previously tracked files changed. The existing untracked Round 9 test was updated, and the Round 12 test and this evidence directory were added. Existing index state was preserved; new files remain local and untracked.

[repairs.diff](round12_remediation/repairs.diff) is the task-only semantic diff, with pre-edit CRLF normalized for readability. Exact pre-edit copies remain at the temporary backup path recorded in [baseline.json](round12_remediation/baseline.json). The full dirty-tree whitespace check still reports pre-existing issues outside this task's files; no broad cleanup was applied.

The two legacy milestone briefs named in AGENTS.md are absent from this checkout. This requested report is the durable Round 12 milestone record. Earlier remediation reports were preserved.
