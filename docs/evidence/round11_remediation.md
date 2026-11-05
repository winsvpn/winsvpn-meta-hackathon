# Round 11 source remediation

Date: 2026-09-13. Repository: `/Users/owner/xprize/winsvpnv3`.
Base commit: `89be66e75747c0b493583ca9c9efd7787c88a974`, with the existing dirty working tree preserved.

All eight requested repair groups are implemented. All 19 mandatory commands pass. This records local source and regression results. Android phone acceptance and packaged native browser/desktop acceptance remain unverified.

## Repairs

- **A11-01:** A failed direct AWG synchronization now rolls back admission, durably queues the possibly installed peer for revocation, marks node management failed, and commits the repair record. Existing authority checks prevent obsolete cleanup from removing a reauthorized peer. Shared Double VPN Core exit peers retain their separate handling.
- **A11-02:** `verify_and_consume_activation_secret` accepts the keyword-only `consume` argument. Double VPN enrollment validates without consuming, commits the pending assignment for Core synchronization, then consumes only when the terminal response is ready. Timeout retries retain the same activation key. Successful enrollment remains single-use.
- **A11-03:** After Core readiness, `BEGIN IMMEDIATE` protects rereading the device bearer hash, current account status and expiration, and current assignment revision. Missing, invalid, expired, or changed authority returns 409 with the requested retry message. A changed expiration is rejected even when still in the future. Final activation verification returns 401 if the key was replaced, consumed, or expired during the wait.
- **A11-07:** `innerForPeer` uses direct `byKey[candidate]` and `notAfter[candidate]` lookups under the existing read lock. Malformed keys, refresh errors, missing expiry records, and expired authorization still deny access. The unused constant-time comparison import and linear scan were removed.
- **A11-04 / DB-01 / DB-02:** The installer atomically provisions public `allowed_origins.txt` companions beside the host executable and browser manifest. The file uses a bounded JSON map of browser names to their exact permitted identity lists, so a browser ID update replaces its prior entry while preserving the other browsers. POSIX companions are readable at mode 0644; the manifest writer retains its existing 0600 default. Missing, malformed, oversized, or linked runtime configuration denies credentials. Firefox's manifest-path plus stable add-on-ID launch is recognized; foreign and ambiguous caller arguments deny access. Chrome/Edge support remains intact. No store identity was invented for production; tests use explicit fixture IDs. Native argv remains caller input, not proof of browser process ancestry.
- **DB-03:** Linux promotion refusal emits only the requested twelve numeric engine counters. It no longer writes raw Winn v3 engine status with endpoint/session fields to stderr.
- **DB-06:** `OwnedKeyboardListener` creates its non-traversable `FocusNode` in `initState`, retains it across rebuilds, and disposes it with the widget. Five inline allocations across TV support, the power control, and dialogs were replaced. The lifecycle test verifies focus retention, callback replacement, key delivery, semantics forwarding, and disposal.
- **DB-07 / SOL-L1:** The connected Linux path no longer starts an infinite sleep inhibitor; the now-unused starter was removed. Disconnect cleanup still stops any existing named inhibitor unit. The split-bypass anchor resolves `Which("sleep")` and fails safely if unavailable.
- **Git custody:** Every new Go test is in the index, including the new Round 11 peer-registry regression. Earlier staged Go tests remain staged. New Flutter source/tests and the new server/native-host tests are also staged. No commit or remote state was created.

## Mandatory verification

Exact commands, exit codes, durations, and log paths: [mandatory-results.json](round11_remediation/mandatory-results.json).

| Command | Result |
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
| `python3 server/test_winn3_descriptor_hub.py` | PASS, 117 tests |
| `python3 server/test_account_deletion_hub.py` | PASS, 20 tests |
| `python3 server/test_donor_acknowledgment_hub.py` | PASS, 57 tests |
| `python3 tools/website_security_audit.py` | PASS, 56 checks and 1 explicit skip |
| `sh tools/verify_rulings.sh` | PASS |
| `python3 tools/verify_apple_method_channel_contract.py` | PASS |
| `python3 tools/test_apple_standalone_v3_wiring.py` | PASS, 7 tests |
| `python3 tools/test_windows_awg_runtime_validation.py` | PASS, 31 tests |
| `cd winn_protocol_experimental && go test ./...` | PASS |

The first Flutter run reported an unnecessary import and two custody failures for the new listener files. The import was removed and those files were staged. Both exact commands then passed. Initial logs are retained alongside final results.

## Additional behavioral evidence

- Six new server tests pass, covering retry-to-success, activation replay, uncertain remote side effects, final writer-lock ownership, and multiple authority/activation changes. Four selected behavioral tests against saved pre-edit server bytes produce twelve expected failing assertions/subtests: [negative control](round11_remediation/server-negative-control.json).
- A real FastAPI/HTTPX ASGI probe executes current extracted hub code with real SQLite and controlled remote operations: uncertain install returns 503 and one durable repair removes the peer; two timeout attempts both return 503 without consuming activation; final success returns a bearer matching the database and rejects replay with 401; concurrent bearer replacement and account revocation return 409 without a bearer. [ASGI results](round11_remediation/asgi-results.json). The probe fixture was adapted from the Round 11 audit's inspected local probe; it uses current repository code, and its audit hook refuses network connections.
- `go test -race ./cmd/winn3-gateway` passes. [Go results](round11_remediation/go-results.json).
- Compiled Linux production seams prove alternative sleep-path use, missing-sleep refusal, idempotent inhibitor cleanup, and endpoint/session redaction. Existing compiled shutdown tests pass. The broader Linux-only RunArgv suite exits zero with all nine tests explicitly skipped on macOS; it supplies no Linux runtime acceptance.
- Four focused installer tests pass, including real shell install/uninstall fixtures. Dart origin and host identity suites pass, as do seven app IPC tests. The actual production native host compiles and passes its self-test. A compiled probe importing the production origin functions reads fresh installer-generated companions through the default executable-directory path: Chrome, Edge and Firefox accept their configured launch form and deny missing/foreign callers. [Compiled origin results](round11_remediation/native-compiled-results.json). These are synthetic launches, not registered browser integration tests.
- The full supplemental native-registration suite has **8 failures out of 48 tests**. A copy-on-write snapshot using pre-edit native files has the **same 8 failure names out of 46 tests**. Six failures assume absent owner identity while a configured identity is available; two macOS helper tests stop at existing authenticated source-freeze requirements. [Baseline comparison](round11_remediation/native-baseline-comparison.json). This suite is not reported green. The snapshot includes tracked working files and excludes `.git` and untracked artifacts; its scope is recorded with the result.

## Remaining acceptance and custody

The connected Android phone was visible to ADB. The proper macOS release entry point, `pwsh -NoProfile -File tools/build_android_release.ps1`, refused with `ReleaseInputIndex is required for every Android release build.` No matching index was found under `.artifacts`, and `build/app/outputs/flutter-apk/app-release.apk` is absent. Therefore no phone uninstall/install/launch/logcat smoke test ran. The earlier `-SkipPubGet` attempt was rejected as a Windows-only switch and was corrected. [Final Android result](round11_remediation/android-final-result.json).

No signing, deployment, publication, push, or release approval occurred. Ruled lines were not edited. Preferred Cursor/Grok lanes were attempted and all stopped at usage limits before doing work; the Codex worker service also failed to create a thread. The lead completed the repairs and ran independent checks concurrently. No independent model review is claimed.

Changed source/test bytes and hashes: [source-checks.json](round11_remediation/source-checks.json). Task-only diff against saved pre-edit files: [repairs.diff](round11_remediation/repairs.diff). Changed source/tests use LF, contain zero carriage returns, and add no em/en dashes. Logs are retained with LF line normalization. Existing historical wording in unrelated lines was preserved.

Technical references checked live on 2026-09-13: [SQLite transaction behavior](https://www.sqlite.org/lang_transaction.html), [Mozilla native messaging launch arguments](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging), [Flutter FocusNode lifecycle](https://api.flutter.dev/flutter/widgets/FocusNode-class.html), [Go map lookup](https://go.dev/blog/maps), and [systemd inhibitor lifetime](https://www.freedesktop.org/software/systemd/man/250/systemd-inhibit.html).
