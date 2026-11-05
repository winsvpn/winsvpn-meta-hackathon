# Round 5 requested remediation

Date: 2026-09-13. Workspace: `/Users/owner/xprize/winsvpnv3`.

All six requested repair groups are implemented in the existing working tree.
All five mandatory commands pass. The connected Android release smoke test is
blocked by the missing release APK and required immutable release input index.
These results establish local source and regression coverage. They do not
establish deployment acceptance or an Apple extension process memory ceiling.

The starting tree already contained substantial owner and earlier-round work.
The [manifest](round5_remediation/source-manifest.json) records the base HEAD,
before/after hashes for the targeted files, and final regression-test hashes.
The [remediation diff](round5_remediation/remediation.diff) isolates this task's
changes from that starting tree. Machine-readable outcomes are in
[results.json](round5_remediation/results.json).

| Requested group | Resulting behavior |
| --- | --- |
| Website checkout and modal | The donation modal is reparented to `document.body`. Paid coin selectors begin disabled in markup and JavaScript. Configuration failure, disabled checkout, and missing automated controls produce an inline notice. A paid coin click cannot open the donation wallet. Monero-only, BTCPay-only, and combined configurations retain their enabled automated controls. Both CSP files pin the modified script hash `rsoC5LXzwZ6X10jhP+IqVrjDVLw8L6AFJ+1xcvm1pbA=`. |
| Firefox privacy | Both privacy settings require a successful boolean set result, the exact requested readback value, and `controlled_by_this_extension`. Errors propagate to controller containment. The controller regression verifies that privacy rejection prevents a protected state and retains blocking rules. |
| Android routing and power | `stealth-xray` and `winn-v3-stealth-chain` clear restart configuration, tear down, and return `START_NOT_STICKY` until an individually protected carrier descriptor exists. The app UID is no longer excluded for those modes. The full-session Wi-Fi lock is removed; the wake lock remains. |
| Client QUIC windows | Every `h3QUICConfig` path sets initial/max stream windows to 128/512 KiB and connection windows to 256/2048 KiB. Supplied configs are cloned before modification. Server configurations are unchanged. |
| Control plane | PayPal subscriptions, lifetime purchases, BTCPay and Monero grants insert encrypted activation delivery records inside the grant/event transaction. A startup worker claims fenced leases, sends after closing SQLite, and retries with bounded exponential backoff. PayPal signature verification, subscription retrieval, refund checks and admin reconciliation run off the event loop. Reconciliation closes its candidate connection before HTTP and rejects stale snapshots after concurrent changes. Paid Smart Router advice requires a valid bearer or unconsumed activation key first. The requested free-access offloads were already present from Round 4 and passed verification. |
| Descriptor suite | `arm_activation` resets consumed and expiry fields. Three tests also needed to reconnect with the bearer returned by their first enrollment instead of replaying the consumed activation key. Production single-use enforcement remains intact. |

Activation envelopes use separate encryption and authentication keys derived
from the existing activation pepper, a random 256-bit nonce, an HMAC-SHA256
keystream, and an encrypt-then-MAC tag bound to the delivery/account identifiers.
Envelope sizes and component lengths are checked before decryption. The
construction follows the existing prepaid fulfillment approach without adding
an unpinned dependency.

Retries keep the same credential across ambiguous SMTP outcomes. Before sending,
the worker checks the current account, recipient, key hash and consumption
state, and refreshes the still-current key's activation window. Superseded,
consumed or inactive deliveries are cancelled and their sealed secrets erased.
Successful delivery also erases the sealed secret. Account deletion cascades
to the outbox. Transient failures remain retryable; the backoff caps at one hour.

Delivery is at least once: SMTP acceptance followed by a crash before the final
SQLite update can produce a duplicate email. The existing activation pepper
must remain available to decrypt pending records. This change does not claim
recovery of credentials already lost before the outbox existed, or proof of
replica durability across loss of the database host.

## Verification

Server commands use Homebrew CPython 3.14.7. `python3` was resolved to that
interpreter through PATH for the mandatory commands. Descriptor signatures use
the available Homebrew OpenSSL. Each server harness creates isolated test data.

| Command or probe | Result |
| --- | --- |
| `flutter analyze --no-pub` | PASS, no issues, exit 0 |
| `python3 server/test_control_plane_deepseek_round2.py` | PASS, 11 tests, exit 0 |
| `python3 server/test_control_plane_round4.py` | PASS, 8 tests, exit 0 |
| `python3 server/test_winn3_descriptor_hub.py` | PASS, 117 tests, exit 0 |
| `python3 tools/website_security_audit.py` | PASS, 56 pass, 1 explicit skip, 0 fail, exit 0. The skip is the absent `drop_in/lib/spa_service.dart` scan. |
| `python3.14 server/test_control_plane_round5.py` | PASS, 16 tests covering all four grant paths, transactional rollback, dedupe, SMTP false/exception retries, authenticated envelopes, concurrent claims, expired leases, stale completion, credential refresh/cancellation, deletion, startup/shutdown, advisory authorization and worker boundaries |
| `python3.14 -m pytest -q extension/tools/test_browser_enforcement_regressions.py` | PASS, 12 tests, including 14 Firefox privacy failure variants and controller containment |
| `tools/test_round5_crypto_checkout.py` in an isolated Playwright environment | PASS, 14 Chromium scenarios at widths 390 and 1440: loading, failed, disabled, malformed, Monero-only, BTCPay-only and combined configuration. Enforced local CSP, synthetic disabled-button clicks, automated panels, visible donations with a hidden drawer, and scroll-lock cleanup. All requests intercepted. |
| `go test -race ./internal/carrier` with the installed Go 1.27.0 toolchain | PASS, including default/supplied client receive-window bounds and preservation of caller config |
| `./gradlew :app:lintPhoneDebug :app:testPhoneDebugUnitTest --tests 'org.winsvpn.app.WinnV3*' --tests 'org.winsvpn.app.ApiLevelGateTest' --offline` | PASS, Kotlin compilation, lint, and 283 JVM tests with JDK 21 |
| `server/test_account_deletion_hub.py` | PASS, 20 tests |
| `server/test_donor_acknowledgment_hub.py` with outbound sockets denied | PASS, 57 tests |
| `server/test_crypto_payments_spain.py` | PASS, 7 tests |
| [Real ASGI probe](round5_remediation/asgi_probe.py) | PASS with FastAPI 0.139.2, Starlette 1.3.1 and Pydantic 2.13.4. Unauthorized verify 401, paid webhook 200 with a committed pending outbox row, duplicate webhook 200/duplicate. A 10 ms timer completed in 12.1 ms during two 150 ms provider calls. All provider calls ran outside the event-loop thread. Outbound sockets and subprocesses prohibited; SMTP mocked; lifespan not started. [Result](round5_remediation/asgi-result.json). |
| Original website negative control | Expected failure: loading state leaves all three paid coin controls enabled |
| Original server negative controls | Expected failure: four failing subcases prove blocking PayPal work and unauthorized Smart Router invocation |
| `bash -n server/wins_control_plane_setup_ONETOUCH.sh` | PASS |
| `sh tools/verify_rulings.sh` | PASS, 59 general and 6 Apple route checks |
| Remediation-only formatting/integrity | PASS, no new long dashes or trailing whitespace; original line endings preserved |

Raw command logs are stored beside the manifest. Existing server harnesses emit
SQLite `ResourceWarning` messages from their import/security-event paths; these
were not hidden or treated as outbox connection-lifecycle proof. An initial run
of the pre-existing donor harness attempted its security-alert SMTP path and
failed TLS certificate verification. Its final run denied outbound socket
connections and passed all 57 tests. No successful external email is evidenced.

## Remaining verification limits

The USB phone is connected. `build/app/outputs/flutter-apk/app-release.apk` is
absent. The actual `tools/build_android_release.ps1` invocation returned exit 1:
`ReleaseInputIndex is required for every Android release build.` No matching
`RELEASE_INPUT_INDEX.json` was found in the checkout. The owner was asked for
its path. No phone uninstall, installation, launch or VPN logcat smoke was run.
This gate was not bypassed with an older or differently packaged APK.

Real Firefox network containment, packaged Android route refusal/power behavior,
and Apple extension memory/throughput measurements remain device acceptance
work. The QUIC receive-window caps are not a total process-memory limit.
Live PayPal, BTCPay, Monero and SMTP integration was not exercised by the new
regressions. Nothing was committed, pushed, published or deployed.

Six preferred Cursor/Grok 4.6 Extra High lanes were launched. All exited with
account usage-limit errors before doing work. The workspace agent fallback
failed to initialize. The lead implemented, reviewed and verified the repairs
locally; no independent model-review completion is claimed.

## Implementation references checked live

Firefox setting changes return a boolean and readback exposes control ownership:
[Mozilla BrowserSetting.set](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/types/BrowserSetting/set).
The QUIC maximum receive-window fields bound autotuning:
[quic-go flow control](https://quic-go.net/docs/quic/flowcontrol/).
Blocking I/O can be awaited in a separate worker thread:
[Python asyncio.to_thread](https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread).
HMAC tag comparison uses the standard constant-time comparison helper:
[Python hmac](https://docs.python.org/3/library/hmac.html).
