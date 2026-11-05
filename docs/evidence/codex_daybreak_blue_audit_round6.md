# Codex Deep Audit Report: Daybreak Blue

- Model Identifier: `gpt-daybreak-blue-latest`
- Reasoning Effort: `xhigh`
- Collected: `2026-09-13T15:50:02.519404+00:00`
- Process Exit Code: `0`
- Content Source: `lane report file (/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/daybreak/docs/evidence/codex_daybreak_blue_audit.md)`
- Usage Metadata: `{"input_tokens": 21129066, "cached_input_tokens": 20476763, "cache_write_input_tokens": 642443, "output_tokens": 69686, "reasoning_output_tokens": 23913}`

## Reasoning Trace

```
**Planning exhaustive single-agent audit**
**Confirming audit constraints and report scope**

**Locating task-relevant memory entries**

**Confirming memory skill usage and citation range**
**Planning workspace inspection and AGENTS inventory**

**Assessing test environment and worktree state**
**Planning workspace snapshot and audit strategy**
**Initiating official technical web searches**

**Planning documentation research on key technologies**

**Identifying Cloudflare and FastAPI SQLite dependencies**

**Reissuing database query**

**Planning performance research and repo inspection**

**Planning code inspection and audit**
**Listing target files**

**Planning targeted audit with scripts**

**Locating precise Windows service code**

**Inspecting Windows sections and pointer usage**

**Planning service authentication flow**

**Assessing local pipe access vulnerability**
**Verifying pipe inheritance and DoS impact**

**Verifying truncated validateRoot function**

**Assessing TOCTOU risk in root-owned path validation**
**Identifying TOCTOU on intermediate directory components**
**Analyzing signal handling and potential DoS risk**

**Identifying potential tunnel cleanup issue**
**Planning source verification and cleanup inspection**

**Assessing application shutdown process**

**Investigating app shutdown and service integration**

**Inspecting systemd recover service**

**Planning source line referencing with nl -ba**

**Verifying iOS deployment target and memory limits**
**Confirming platform support and route enforcement**

**Locating MainFlutterWindow settings**

**Investigating iOS route code near line 2400**

**Inspecting Apple completion handler race**
**Assessing macOS memory limit and Android service needs**

**Identifying missed protect occurrences**

**Identifying Android DNS blocking delay**
**Reviewing Android split tunnel exception handling**

**Planning dynamic Android testing and build verification**
**Evaluating offline Flutter release build setup**

**Verifying store_ids content**

**Verifying Python versions**

**Inspecting package tests**

**Planning browser initialization with CUA**

**Creating browser tab without session name**

**Testing button click for plan details**

**Exploring bypass for extension UI block**

**Planning escape key dismissal**

**Exploring Playwright for browser automation**
**Recording browser interaction blocker and probing network**

**Reviewing wallet address classification**

**Planning temporary file handling**

**Planning live script hash validation**
**Identifying live hash counts**

**Analyzing Cloudflare script injection impact**
**Investigating CSP hash discrepancies**

**Diagnosing CSP blocking Cloudflare scripts**
**Planning headless browser testing for click behavior**

**Evaluating Edge headless browser options**
**Planning Edge headless profile management**
**Configuring Edge headless execution with timeout**

**Planning headless Edge remote debugging**
**Designing headless Edge session management**
**Testing headless Edge launch without user data**

**Implementing WebSocket connection with Node fetch**
**Designing dynamic interaction testing via WebSocket**

**Stopping Edge session**

**Diagnosing browser profile impact**
**Preparing code fixes for deployment**
**Starting Flutter code analysis**

**Running full Flutter tests**

**Investigating failure count -1**

**Planning targeted test rerun with JSON output**

**Planning JSON test rerun with error parsing**

**Identifying test failure cause**

**Planning audit of untracked test file**
**Planning segmented Go tests execution**

**Confirming parallel command allowance**

**Identifying packaging issue in go test**

**Planning website audit and build process**

**Planning package verification via build script**

**Investigating test path symlink issue**
**Analyzing sys.path and symlink effects**

**Planning poll session investigation**

**Analyzing stale pyc traceback issue**
**Exploring pycache prefix environment variables**

**Noting individual command failures despite session exit**

**Planning selective server test inspection**

**Planning targeted test execution**
**Searching for SQLite usage patterns**

**Inspecting blocking time.sleep in async function**

**Inspecting potential fromisoformat defect**

**Planning static analysis for async DB usage**
**Extracting Python heredoc segment**

**Planning async function analysis for blocking calls**

**Identifying blocking SQLite calls in async FastAPI handlers**
**Analyzing async route blocking and test allowlist**

**Verifying test code output boundaries**

**Planning dynamic logout test with harness**

**Planning test setup and dependencies**

**Planning dynamic testing with writer lock**

**Testing logout and rate limiting behavior**
**Confirming safe test environment cleanup**

**Identifying database write lock risks**
**Planning async-to-sync database fix**
**Planning AST analysis for public sync routes**

**Planning sync conversion for no-await async funcs**
**Designing async-sync route handling strategy**
**Preparing precise no-await async-to-sync patch**

**Refactoring account endpoints to prevent stalls**
**Planning precise async-to-sync route fixes**

**Diagnosing OpenSSL concurrency issue**

**Verifying test execution method**

**Investigating OpenSSL version and PATH impact**

**Identifying test bug in OpenSSL handling**

**Identifying poll extension 17328**

**Inspecting native standalone test script**

**Enforcing hyphen use in commentary**

**Planning bottom namespace and wrapper**

**Planning build and shellcheck steps**

**Inspecting array reuse and variable behavior**

**Clarifying shellcheck warning validity**

**Inspecting script shebang**

**Searching for fuzz functions**

**Planning sequential Go fuzz tests**

**Planning race condition test**

**Verifying rulings and building APK**

**Planning private directory build**

**Testing direct phone build with debug info**

**Checking environment variable keys**

**Designing secure eval with public keys**
**Analyzing APK build output discrepancies**

**Evaluating build signing and debug options**
**Confirming test scope and artifact constraints**

**Analyzing FastAPI background task threading**
**Planning async route refactoring and AST analysis**
**Inspecting Gradle release signing configuration**

**Planning live command evidence gathering**
**Designing read-only curl hash commands**

**Correcting PATH usage and verifying commands**

**Planning dynamic Edge report command**

**Confirming Android manifest handling**

**Analyzing Android manifest feature additions**

**Inspecting worker.js rate fallback and placeholders**

**Inspecting transaction and email pipelines**

**Investigating Socket buffer settings**

**Verifying iOS deployment target**

**Updating iOS memory documentation**
**Analyzing WakeLock timeout behavior**

**Verifying test file locations**

**Planning verification of file paths and assert script**

**Investigating build reproducibility failure**

**Planning targeted Apple and Android tests**
**Planning xcodebuild and dart test executions**

**Planning exact CSP repro using Playwright**
**Verifying CORS and TLS configurations**

**Planning git status and test summary**

**Refining diff check with sed and zsh**

**Planning Linux cleanup and shutdown verification**

**Assessing Linux tunnel shutdown cleanup**
**Designing safe tunnel stop checks**

**Examining IsTunnelRunning side effects**

**Designing robust tunnel shutdown checks**
**Planning comprehensive tunnel cleanup checks**

**Inspecting StopXrayProcess functionality**

**Planning tunnel shutdown safeguards**

**Adding and managing tunnel session flag**
**Planning Unix signal handling for clean shutdown**
**Preparing comprehensive server patch with helpers**

**Planning comprehensive patch verification report**
**Drafting patch report with strict content filters**
**Clarifying unverified WAF defect handling**

**Assessing Durable Object support for Pages**
**Defining precise WAF rule expressions for mitigation**

**Requesting toolchain API integration**

**Refactoring OpenSSL import and environment usage**

**Adjusting PATH for OpenSSL tests**
**Planning detailed patch for high severity fix**
**Proposing event loop timing assertion**

**Identifying precise test commands**
**Summarizing exact test and patch instructions**

**Refining tunnel session committed flag logic**
**Adding Unix signal handler for clean shutdown**
**Clarifying mkdir mode behavior with -p option**

**Confirming logout path risk and scope**
**Analyzing DB lock stall risk and test coverage**
**Summarizing confirmed test results and passes**

**Analyzing build warnings and test failures**
**Planning patch composition**

**Verifying forbidden characters and placeholders**

**Clarifying Go command syntax preservation**
**Revising patch to include full function replacements**
**Planning full section replacement for patch**

**Planning complete function replacements with decorators**
**Confirming request header usage and patch application**

**Assessing diff format requirements**
**Planning precise diff generation**
**Finalizing line count calculations for diffs**

**Assessing patch hunk line counts and CRLF endings**
**Analyzing detailed hunk line changes and context**

**Reviewing patch application method**

**Inspecting patch replacement scope**

**Identifying patch hunk misalignment**
**Planning full valid patch reconstruction**

**Rebuilding diff with corrected hunk lines**
**Confirming and adjusting function hunk ranges**

**Testing patch with process substitution**
**Implementing dynamic diff extraction with awk**

**Patching corrupted hunk counts**

**Fixing patch hunk line counts**
**Refining patch hunk line ranges**

**Fixing header hunk line counts**

**Investigating CRLF handling in git apply**

**Testing git apply with ignore-whitespace**

**Fixing patch logic and parsing code extraction**

**Verifying iOS patch line mappings**
**Planning complete paragraph replacement**

**Replacing stale deployment-floor paragraph**

**Verifying report completeness and testing patch**

**Verifying test script existence and execution**
**Running iOS release artifact test script**

**Locating exact memory lines**

**Finalizing concise audit summary**
**Confirming final report details and citations**
```

## Audit Findings & Exact Fix Implementations

# WinsVPN ecosystem independent security and performance audit

Author: Daybreak Blue  
Audit date: 2026-09-13  
Workspace: `/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/daybreak`  
Revision observed: `89be66e75747c0b493583ca9c9efd7787c88a974` on `main`  
Verdict: **NO-GO for release from these exact workspace bytes**

## 1. Executive summary

This audit found no verified Critical vulnerability. It found three High defects, three Medium release or control defects, and two Low defects. The strongest positive result is that the protocol parsers, anti-downgrade rules, platform privilege boundaries, route posture, payment method guards, and most static regression gates are materially stronger than a normal VPN client codebase. The strongest negative result is that those controls do not yet form a releasable, immutable artifact set.

The High findings are concrete:

1. The Kansas FastAPI hub performs synchronous SQLite work inside `async def` request handlers. A controlled lock-contention test made an unrelated coroutine stop for 0.526 seconds while `/logout` waited on SQLite. The configured busy timeout is 30 seconds. This is an availability defect in the single event loop, not just a slow request.
2. The live site still contains an older paid-crypto failure path that calls the static donation modal when automated checkout controls are not ready. A direct click works today, but the deployed race and failure branch can divert a purchase into a donation that cannot provision an account. The current workspace has the correct fail-closed behavior, but its HTML hash differs from the live response.
3. Linux handles only `SIGPIPE`. Its `GApplication::shutdown` hook is empty, and `StopTunnel()` is called only by the Flutter method channel. Window close, `SIGINT`, or `SIGTERM` can therefore bypass removal of the interface, routes, firewall posture, split-tunnel slice, Xray process, and power inhibitor.

There are also release-custody failures. The full Flutter suite reports 1 failure because a QUIC receive-window regression test is untracked. The canonical Chrome ZIP fails 2 of 22 native-identity packaging tests and fails direct archive inspection because one JavaScript member is not the reproducible esbuild output. The tree has 149 status entries, including 27 untracked entries, and `git diff --check` reports 314 lines. These are not evidence that the implementation is unsafe by themselves. They are decisive evidence that these bytes are not a frozen release candidate.

### Finding register

| ID | Severity | Result | Finding |
|---|---|---|---|
| DB-01 | High | VERIFIED | Synchronous SQLite blocks the FastAPI event loop under contention |
| WEB-01 | High | VERIFIED | Live paid-crypto failure branch can open the non-provisioning donation modal |
| LNX-01 | High | VERIFIED STATIC | Linux normal and signal exits bypass tunnel teardown |
| REL-01 | Medium | VERIFIED | QUIC memory regression test is untracked and full Flutter suite is red |
| EXT-01 | Medium | VERIFIED | Canonical Chrome ZIP is stale against the reproducible minifier and identity gate |
| EDGE-01 | Medium | VERIFIED CODE, EXTERNAL MITIGATION UNVERIFIED | Pages rate limiting is isolate-local for payment and AI endpoints |
| CSP-01 | Low | VERIFIED | Cloudflare-injected scripts violate the site's strict CSP |
| IOS-01 | Low | VERIFIED | iOS memory comments retain an obsolete iOS 13 deployment-floor claim |

No finding was assigned from a comment alone. Each result below distinguishes source evidence, executed evidence, and platform evidence that was unavailable.

## 2. Scope, method, and evidence limits

The review covered the requested Windows, Linux, macOS, Android, Android TV, iOS, browser-extension, control-plane, data-plane, shared Dart, protocol, website, DNS, TLS, payments, provisioning, memory, and performance surfaces. tvOS was inspected as product scope rather than as a build target because this repository contains no shipping tvOS target. The repository ruling explicitly marks it as a future separate product and not part of the current release denominator.

Only read-only live probes were used. The audit sent GET requests, performed DNS and TLS inspection, and exercised client-side DOM behavior. It did not create a payment order, invoice, account, email, DNS change, Cloudflare change, deployment, or server mutation.

The checkout UI was exercised in a fresh Microsoft Edge process. The paid-plan control expanded, the Monero and BTCPay controls rendered, the XMR selector opened its email panel, and `#cryptoModalBackdrop` remained hidden. That proves the current happy path at the observation time. It does not erase the older deployed failure branch described in WEB-01.

The workspace was already dirty. This report did not reset, clean, stage, commit, or rewrite unrelated files. Findings therefore describe the observed working bytes, not a clean clone of the named Git revision.

### Authoritative API references used

- Microsoft documents named-pipe DACL behavior and access-right implications in [Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
- Android documents `VpnService.protect()` as the mechanism that keeps an outer socket outside the VPN in the [VpnService API](https://developer.android.com/reference/android/net/VpnService) and [VPN developer guide](https://developer.android.com/develop/connectivity/vpn?authuser=002).
- Apple documents the packet tunnel provider and route controls in [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider), [`includeAllNetworks`](https://developer.apple.com/documentation/networkextension/nepackettunnelnetworksettings/includeallnetworks), and [`enforceRoutes`](https://developer.apple.com/documentation/networkextension/nevpnprotocol/enforceroutes?changes=l___2).
- Apple DTS records the modern iOS packet-tunnel memory limit as approximately 50 MiB on modern devices in [Network Extension memory limits](https://developer.apple.com/forums/thread/73148). Runtime headroom remains device-specific.
- Mozilla documents MV3 background behavior in [manifest background](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background) and [background scripts](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Background_scripts).
- Microsoft documents native-host origin binding in [Native messaging in Microsoft Edge](https://learn.microsoft.com/en-us/microsoft-edge/extensions-chromium/developer-guide/native-messaging).
- Apple documents Safari app-extension messaging in [Messaging between the app and JavaScript in a Safari web extension](https://developer.apple.com/documentation/safariservices/messaging-between-the-app-and-javascript-in-a-safari-web-extension?changes=lat_3_5).
- FastAPI explains the event-loop versus thread-pool distinction in [Concurrency and async](https://fastapi.tiangolo.com/async/).
- SQLite documents [write-ahead logging](https://www.sqlite.org/wal.html) and [PRAGMA behavior](https://www.sqlite.org/pragma.html). Python documents its synchronous driver in [`sqlite3`](https://docs.python.org/3.13/library/sqlite3.html).
- Cloudflare documents [Rate Limiting bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/), [cache configuration](https://developers.cloudflare.com/workers/cache/configuration/), [Worker routes](https://developers.cloudflare.com/workers/configuration/routing/routes/), and the fact that Pages `_headers` rules do not apply to Worker-generated responses in [Headers](https://developers.cloudflare.com/workers/static-assets/headers/).

## 3. Executed verification matrix

| Area | Command or probe | Result |
|---|---|---|
| Ruled invariants | `sh tools/verify_rulings.sh` | PASS, 59 invariants and 6 Apple route checks |
| Dart analysis | `flutter analyze --no-pub` | PASS, 0 issues |
| Flutter tests | `flutter test --no-pub --concurrency=1` | FAIL, 1920 passed, 5 skipped, 1 failed |
| Winn Go module | `go test ./...` from `winn_protocol_experimental` | PASS |
| Winn race checks | `go test -race ./winn3/core ./winn3/session ./internal/carrier ./internal/protocol` | PASS |
| Winn fuzzing | Three 5 second targets in core, carrier, and protocol | PASS, 4,875,577 executions, no crash |
| Native standalone | `bash tools/verify_native_standalone_tests.sh` | Host PASS, 9 passed, 2 skipped |
| Native skipped | libsecret and Linux eBPF tests | UNVERIFIED on macOS host |
| Website security | `python3.14 tools/website_security_audit.py` | PASS, 56 passed, 1 explicit skip |
| Website self-test | `python3.14 tools/website_security_audit.py --selftest` | PASS |
| Server rounds 2, 4, 5 | Pytest aggregate for those suites | PASS, 35 tests plus 22 subtests |
| Descriptor hub | Homebrew OpenSSL 3 on `PATH`, then `python3.14 server/test_winn3_descriptor_hub.py` | PASS, 117 of 117 |
| Descriptor hub default Mac tools | Same command with system LibreSSL | FAIL, Ed25519 CLI unsupported |
| Paid refresh | Dedicated paid-refresh suite | PASS, 2 of 2 |
| Protocol selection and router | Dedicated server suites | PASS, 20 of 20 |
| Extension core | Core JavaScript tests | PASS, 5 of 5 |
| Extension enforcement | Regression suite | PASS, 19 of 19 |
| Extension proxy-auth scope | Regression suite | PASS, 41 of 41 |
| Extension identity controller | Regression suite | PASS, 8 of 8 |
| Cross-store adapters | Pytest suite | PASS, 63 of 63 |
| Strict JSON | Pytest suite | PASS, 29 of 29 |
| Release witness | Pytest suite | PASS, 27 of 27 |
| Chrome identity | `python3.14 -m pytest -q extension/tools/test_chromium_native_identity.py` | FAIL, 20 passed, 2 failed |
| Chrome archive | `python3.14 extension/tools/assert_chrome_zip.py extension/dist/wins-vpn-companion-chrome.zip` | FAIL |
| Shell static analysis | `shellcheck -x -S warning` on three requested installers | 18 warnings, no parser error |
| Git whitespace gate | `git diff --check` | FAIL, exit 2, 314 diagnostic lines |
| Android release build | `flutter build apk --release --no-pub` | Correctly refused missing obfuscation and private split-debug-info flags |
| Android USB smoke | Connected Motorola phone detected | NOT RUN, no current signed release APK existed in the assigned workspace |
| Live root | GET, headers, DOM, console | 200, Cloudflare, HTTP/2, strict headers, details below |
| Live crypto config | GET `/api/site/crypto-config` | 200, both payment modes enabled, 300 second cache |
| Live payment mutation guards | GET to both payment creation endpoints | 405, no order or invoice created |
| DNS | A and AAAA queries | Cloudflare anycast records present |
| TLS | SNI certificate inspection | CN `winsvpn.org`, Google Trust Services WE1, valid 2026-09-01 through 2026-11-30 |

The root Go command `go test ./...` is not a valid repository-wide test entry point because the root tooling directory mixes C sources and modules and lacks the Winn module dependencies. The module-scoped Winn command passed.

## 4. Detailed findings and exact remediation

### DB-01: synchronous SQLite blocks the FastAPI event loop

Severity: **High**  
Status: **VERIFIED DYNAMIC**  
Affected surface: `server/wins_control_plane_setup_ONETOUCH.sh:7261-7290`, `:21254-21324`, and handlers with the same pattern

#### Root cause

`get_db()` opens a synchronous `sqlite3` connection with a 30 second timeout, enables WAL, and sets `busy_timeout=30000`. `/free/logout` and `/logout` are `async def` handlers. They await body parsing, then run the entire synchronous database transaction directly on the event-loop thread. FastAPI only moves normal `def` route functions into its thread pool. It does not move blocking work found inside `async def`.

The controlled test held `BEGIN IMMEDIATE` on a second connection for 0.35 seconds, called `/logout`, and ran an unrelated ticker on the same loop. The request completed in 0.526 seconds. The unrelated ticker was also delayed 0.526 seconds. This proves whole-loop blocking. A longer writer collision can approach the configured 30 second timeout.

The same source pattern exists in account-deletion, redemption, webhook, emergency, agent, and administrative handlers. Not every one was dynamically forced into contention. They require the same audit rule: no synchronous SQLite or remote I/O may run directly in an `async def` handler.

#### Exact fix for the two dynamically proven public handlers

Insert the two synchronous helpers immediately after `perform_authenticated_device_logout`, then replace the two route handlers with this complete block:

```python
def free_logout_device_sync(
    background_tasks: BackgroundTasks,
    request: Request,
    dev: str,
) -> None:
    account_number, synthetic_device_id, hardware_fingerprint = free_identity_for_device(dev)
    with get_db() as conn:
        ensure_schema(conn)
        check_rate_limit(
            conn,
            rate_limit_bucket("free-logout-ip", request_origin_bucket_value(request)),
            20,
            60,
        )
        conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        device = perform_authenticated_device_logout(
            conn,
            background_tasks,
            request,
            account_number,
            synthetic_device_id,
            "free logout",
        )
        if device is not None:
            record_free_access_event(
                conn,
                request,
                "logout",
                account_number,
                hardware_fingerprint,
                device["client_public_key"] or "",
                "",
                device["device_model"] or "Device",
                device["location_slug"] or "",
                False,
            )


def logout_device_sync(
    background_tasks: BackgroundTasks,
    request: Request,
    account_number: str,
    device_id: str,
) -> None:
    with get_db() as conn:
        ensure_schema(conn)
        perform_authenticated_device_logout(
            conn,
            background_tasks,
            request,
            account_number,
            device_id,
            "logout",
        )


@app.post("/free/logout")
async def free_logout_device(
    background_tasks: BackgroundTasks,
    request: Request,
    device_id: Optional[str] = None,
    deviceid: Optional[str] = None,
):
    body = {}
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            decoded = await request.json()
            if isinstance(decoded, dict):
                body = decoded
        except Exception:
            body = {}
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        body = await request.form()
    dev = device_id or deviceid or body.get("device_id") or body.get("deviceid") or ""
    if not dev:
        raise HTTPException(status_code=400, detail="Missing device_id/deviceid")
    await asyncio.to_thread(free_logout_device_sync, background_tasks, request, dev)
    return {"ok": True}


@app.post("/logout")
async def logout_device(
    background_tasks: BackgroundTasks,
    request: Request,
    account_number: Optional[str] = None,
    accountnumber: Optional[str] = None,
    device_id: Optional[str] = None,
    deviceid: Optional[str] = None,
):
    form = {}
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            decoded = await request.json()
            if isinstance(decoded, dict):
                form = decoded
        except Exception:
            form = {}
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        form = await request.form()
    acc = normalize_account_number(
        account_number
        or accountnumber
        or form.get("account_number")
        or form.get("accountnumber")
        or ""
    )
    dev = device_id or deviceid or form.get("device_id") or form.get("deviceid") or ""
    if not acc or not dev:
        raise HTTPException(
            status_code=400,
            detail="Missing account_number/accountnumber or device_id/deviceid",
        )
    await asyncio.to_thread(logout_device_sync, background_tasks, request, acc, dev)
    return {"ok": True}
```

For every `async def` handler, use one of two complete rules. If it has no required await, change it to `def` so FastAPI runs it in the thread pool. If it must await request-body parsing, parse first, then move one complete synchronous transaction function into `await asyncio.to_thread(sync_transaction, parsed_payload)`. Do not split one transaction across several thread calls because that loses connection and transaction affinity.

#### Verification

```bash
python3.14 -m pytest -q server/test_round2_fixes.py server/test_round4_fixes.py server/test_round5_fixes.py
python3.14 server/test_winn3_descriptor_hub.py
rg -n -U 'async def [^(]+\([^)]*\):(?:(?!^def |^async def |^@app\.).)*with get_db\(\)' server/wins_control_plane_setup_ONETOUCH.sh
```

Expected: all tests pass. The final search returns no handler that performs `with get_db()` directly in an async route body. Repeat the lock-contention harness. Expected: the logout request may wait for the lock, but a 10 ms loop ticker must continue with no gap over 100 ms.

### WEB-01: live paid crypto can fall into a non-provisioning donation flow

Severity: **High**  
Status: **VERIFIED DEPLOYED SOURCE AND LIVE DOM**  
Affected surface: live `https://winsvpn.org/`; fixed workspace code at `web/index.html:6483-6538`, `:6611-6616`, and `:6764-6791`

#### Root cause

There are two different crypto products on one page:

- Static donation buttons open `#cryptoModalBackdrop` and display a fixed donation address.
- Paid-plan controls call `/pay/monero/create-order` or `/pay/crypto/create-invoice`, which create tracked payment state and can provision an account after settlement.

The deployed HTML still contains `openModal(coin, planTitle)` in the paid coin-selector failure branch. If the automated row is late, unavailable, or lacks the expected generated control, the click becomes a donation. A donation address has no paid order identity, email binding, settlement state, or account-provisioning transaction. This is a payment-integrity and customer-support defect.

The direct bug did not reproduce on the current happy path. A fresh Edge run showed four automated controls, enabled coin selectors, the Monero email panel, and a hidden donation modal. That narrows the failure to the deployed fallback or race path. It does not make the branch safe.

The live root hash changed across requests because Cloudflare injects response content, but neither observed live hash equaled the workspace `web/index.html` SHA-256 `e26c1a54371cedb9783f9d0923d3cacc4a1ae222fd77d43c0a8d2c9428752bc3`. A direct live source search found `openModal(coin, planTitle)`. The workspace correctly uses `renderCryptoUnavailable(card, unavailable)` instead.

#### Exact fix

The current workspace already contains the required production behavior. Preserve these exact blocks in the deployed bytes:

```javascript
function setCryptoCoinSelectors(card, moneroEnabled, cryptoEnabled) {
  card.querySelectorAll(".crypto-coin-selector-grid .crypto-coin-btn").forEach((button) => {
    const coin = button.getAttribute("data-switch");
    const enabled = coin === "xmr" ? moneroEnabled :
      (coin === "btc" || coin === "dash") && cryptoEnabled;
    button.disabled = !enabled;
    button.setAttribute("aria-disabled", String(!enabled));
  });
}

function renderCryptoUnavailable(card, message) {
  if (!card) return;
  setCryptoCoinSelectors(card, false, false);
  const row = card.querySelector("[data-crypto-row]");
  if (!row) return;
  row.replaceChildren();
  const notice = document.createElement("p");
  notice.className = "crypto-pay-status";
  notice.setAttribute("role", "status");
  notice.textContent = translateRuntimeText(message);
  row.appendChild(notice);
  const trigger = card.querySelector(".crypto-plan-btn");
  row.hidden = trigger ? trigger.getAttribute("aria-expanded") !== "true" : false;
}
```

```javascript
if (!triggered) {
  renderCryptoUnavailable(card, "Automated crypto checkout is unavailable. Please retry shortly or choose another payment method.");
}
```

```javascript
var backdrop = document.getElementById("cryptoModalBackdrop");
if (backdrop && backdrop.parentElement !== document.body) {
  document.body.appendChild(backdrop);
}
```

Deployment is an owner operation and was not performed by this audit.

#### Verification

```bash
python3.14 tools/website_security_audit.py --selftest
python3.14 tools/website_security_audit.py
/usr/bin/curl -fsS https://winsvpn.org/ | rg -n 'openModal\(coin, planTitle\)'
/usr/bin/curl -fsS https://winsvpn.org/ | shasum -a 256
shasum -a 256 web/index.html
```

Expected after publication: both audit commands pass, the forbidden live search returns no match, and the published HTML identity matches the reviewed staged asset before any optional edge transformation. In a fresh browser, block `/api/site/crypto-config` before reload, click a paid crypto plan, and confirm that the inline unavailable message appears while `document.getElementById('cryptoModalBackdrop').hidden` remains `true`. Do not click a payment creation control during this verification.

### LNX-01: Linux exit paths bypass tunnel teardown

Severity: **High**  
Status: **VERIFIED STATIC, HOST RUNTIME UNAVAILABLE**  
Affected surface: `linux/runner/main.cc:27-38`, `linux/runner/my_application.cc:114-120`, `linux/runner/linux_tunnel_backend.cc:4380-4481`

#### Root cause

`main.cc` ignores only `SIGPIPE`. `my_application_shutdown()` calls only its parent. `StopTunnel()` is reachable from the Flutter `stopTunnel` method, not from application shutdown. Normal window closure and default `SIGINT` or `SIGTERM` termination can therefore skip the cleanup transaction. Classical AWG state lives in the kernel after its setup process exits. Xray and power-inhibit processes can also outlive the UI. This can strand a fail-closed route or firewall state and make the host appear offline until manual cleanup or reboot.

Signal handlers must not call tunnel code directly because the teardown is not async-signal-safe. The correct design is to translate `SIGINT` and `SIGTERM` into a GLib main-loop quit, then run one idempotent shutdown function from `GApplication::shutdown`.

#### Exact fix

```diff
diff --git a/linux/runner/linux_tunnel_backend.h b/linux/runner/linux_tunnel_backend.h
--- a/linux/runner/linux_tunnel_backend.h
+++ b/linux/runner/linux_tunnel_backend.h
@@ -1,8 +1,10 @@
 #ifndef RUNNER_LINUX_TUNNEL_BACKEND_H_
 #define RUNNER_LINUX_TUNNEL_BACKEND_H_
 
 #include <flutter_linux/flutter_linux.h>
+#include <string>
 
 void RegisterLinuxTunnelBackend(FlBinaryMessenger* messenger);
+bool ShutdownLinuxTunnelBackend(std::string* error);
 
 #endif  // RUNNER_LINUX_TUNNEL_BACKEND_H_
diff --git a/linux/runner/linux_tunnel_backend.cc b/linux/runner/linux_tunnel_backend.cc
--- a/linux/runner/linux_tunnel_backend.cc
+++ b/linux/runner/linux_tunnel_backend.cc
@@ -67,3 +67,4 @@
 FlMethodChannel* g_channel = nullptr;
 bool g_linux_split_tunnel_ready = false;
+bool g_tunnel_session_committed = false;
 winsvpn::winn3host::Winn3StartProof g_last_winn3_proof;
@@ -4095,3 +4096,4 @@ bool StartTunnel(const std::string& raw_config, int64_t transition_generation,
     g_last_winn3_proof =
         winsvpn::winn3host::MakeConnectedWinn3StartProof(transition_generation);
+    g_tunnel_session_committed = true;
     return true;
@@ -4347,4 +4349,5 @@ bool StartTunnel(const std::string& raw_config, int64_t transition_generation,
   g_linux_split_tunnel_ready = !g_linux_excluded_apps.empty();
   StartTunnelPowerProtection();
+  g_tunnel_session_committed = true;
   return true;
 }
@@ -4444,5 +4447,6 @@ bool StopTunnel(std::string* error) {
     if (!winn3_ok) {
       if (error != nullptr) *error = winn3_error;
       return false;
     }
+    g_tunnel_session_committed = false;
     return true;
@@ -4479,5 +4483,6 @@ bool StopTunnel(std::string* error) {
   if (!data_directory.empty()) {
     std::remove((data_directory + "/winsvpn.conf").c_str());
   }
+  g_tunnel_session_committed = false;
   return true;
 }
@@ -4995,7 +5000,12 @@ void RegisterLinuxTunnelBackend(FlBinaryMessenger* messenger) {
 void RegisterLinuxTunnelBackend(FlBinaryMessenger* messenger) {
   g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
   g_channel = fl_method_channel_new(messenger, kChannelName,
                                     FL_METHOD_CODEC(codec));
   fl_method_channel_set_method_call_handler(g_channel, MethodCallHandler,
                                             nullptr, nullptr);
 }
+
+bool ShutdownLinuxTunnelBackend(std::string* error) {
+  if (!g_tunnel_session_committed) return true;
+  return StopTunnel(error);
+}
diff --git a/linux/runner/my_application.cc b/linux/runner/my_application.cc
--- a/linux/runner/my_application.cc
+++ b/linux/runner/my_application.cc
@@ -115,7 +115,8 @@
 static void my_application_shutdown(GApplication* application) {
-  // MyApplication* self = MY_APPLICATION(object);
-
-  // Perform any actions required at application shutdown.
+  std::string error;
+  if (!ShutdownLinuxTunnelBackend(&error)) {
+    g_warning("Linux tunnel shutdown cleanup failed: %s", error.c_str());
+  }
 
   G_APPLICATION_CLASS(my_application_parent_class)->shutdown(application);
 }
diff --git a/linux/runner/main.cc b/linux/runner/main.cc
--- a/linux/runner/main.cc
+++ b/linux/runner/main.cc
@@ -1,7 +1,8 @@
 #include "linux_secure_store.h"
 #include "linux_secure_store_async.h"
 #include "my_application.h"
 
+#include <glib-unix.h>
 #include <sys/stat.h>
 
 #include <csignal>
@@ -20,6 +21,11 @@ void HardenLegacyStateFiles() {
                                                : "");
   if (base.empty()) return;
   HardenLegacyStateDirectory(base + "/wins_vpn");
 }
+
+gboolean QuitApplicationFromUnixSignal(gpointer user_data) {
+  g_application_quit(G_APPLICATION(user_data));
+  return G_SOURCE_REMOVE;
+}
 
 }  // namespace
@@ -34,6 +40,8 @@ int main(int argc, char** argv) {
   // first persist routes through linux_secure_store_async.cc and is never
   // issued synchronously (blocking) on the UI thread.
   InitializeLinuxSecureStoreAsync();
   g_autoptr(MyApplication) app = my_application_new();
+  g_unix_signal_add(SIGINT, QuitApplicationFromUnixSignal, app);
+  g_unix_signal_add(SIGTERM, QuitApplicationFromUnixSignal, app);
   return g_application_run(G_APPLICATION(app), argc, argv);
 }
```

The committed flag prevents an ordinary app exit that never started a tunnel from invoking an elevation prompt. A failed cleanup keeps the flag set because `StopTunnel()` clears it only after complete success.

#### Verification

```bash
bash tools/verify_native_standalone_tests.sh
cmake -S linux -B build/linux/daybreak-release -DCMAKE_BUILD_TYPE=Release
cmake --build build/linux/daybreak-release --parallel
```

On a Linux VM, start a test tunnel, record the owned `WINVPN-*` chains and `winsvpn` or `winsvpn3` interface, then send `SIGTERM` to the UI process. Expected within the shutdown timeout: no owned interface, no Xray child, no power-inhibit PID, no split-tunnel cgroup, and no jump from host base chains into owned chains. Repeat using window close and `SIGINT`. Also start and close the app without a tunnel. Expected: no privilege prompt.

### REL-01: a release-critical QUIC window regression test is untracked

Severity: **Medium**  
Status: **VERIFIED**  
Affected surface: `winn_protocol_experimental/internal/carrier/h3_receive_window_test.go`

The current carrier implementation caps client QUIC receive windows at 128 KiB initial stream, 512 KiB maximum stream, 256 KiB initial connection, and 2 MiB maximum connection. The regression test that pins those values exists but is untracked. The Flutter suite's completeness guard intentionally fails because a clean clone would silently lose the test.

#### Exact fix

Review the file contents, then add that exact file to the release change set:

```bash
git add -- winn_protocol_experimental/internal/carrier/h3_receive_window_test.go
git ls-files --error-unmatch winn_protocol_experimental/internal/carrier/h3_receive_window_test.go
flutter test --no-pub --concurrency=1
```

Expected: `git ls-files` prints the path and returns 0. The full Flutter suite has zero failures. This audit did not stage the file because the workspace contains unrelated owner changes.

### EXT-01: canonical Chrome ZIP is stale

Severity: **Medium**  
Status: **VERIFIED**  
Affected surface: `extension/dist/wins-vpn-companion-chrome.zip`

`test_chromium_native_identity.py` reports 20 passed and 2 failed. Direct archive inspection reports `ok: false` because `src/adapters/firefox.js` inside the Chrome archive is not the reproducible pinned-esbuild output. The archive is 93,363 bytes and identifies extension ID `lnehjdblendkagjbmdclepjalahdhbbn`. Source-level manifest and controller tests pass, so this is an artifact freshness failure rather than a demonstrated origin-binding bypass.

The failure trace displays an old production-tree path because cached Python bytecode retains a prior `co_filename`. The test file itself resolves inside this assigned workspace and is not a symbolic link. No production tree was read for the result.

#### Exact fix

```bash
cd extension
python3.14 build.py chrome
python3.14 build.py --verify chrome dist/wins-vpn-companion-chrome.zip
cd ..
python3.14 -m pytest -q extension/tools/test_chromium_native_identity.py
python3.14 extension/tools/assert_chrome_zip.py extension/dist/wins-vpn-companion-chrome.zip
```

Expected: the producer completes with the pinned local esbuild dependency, both test failures disappear, and the final JSON says `"ok": true`. Do not reuse the current ZIP.

### EDGE-01: live Pages rate limits are isolate-local

Severity: **Medium**  
Status: **VERIFIED CODE, EXTERNAL WAF UNVERIFIED**  
Affected surface: `web/_worker.js:8-41`, `:242-298`; `web/wrangler.jsonc:1-112`

`requireQuota()` uses a bound limiter only when one exists. The current Pages deployment cannot use the migration-only `ratelimits` block, so it falls back to an in-memory `Map`. That map is correctly capped at 10,000 entries and uses only `CF-Connecting-IP`. It is still local to one isolate and region. An attacker can distribute traffic across isolates and bypass the intended global request ceiling on translation, AI, wallet, Monero, and BTCPay creation routes.

The repository says a zone-level WAF rate-limit rule is the current mitigation. Dashboard state was not available, so this audit cannot say whether that mitigation exists.

#### Exact operational fix

On the current Pages architecture, create a zone-level Cloudflare rate-limit rule with this exact expression:

```text
http.host in {"winsvpn.org" "www.winsvpn.org" "winsvpn.com" "www.winsvpn.com"} and http.request.method eq "POST" and http.request.uri.path in {"/api/site/translate" "/api/site/ai-chat" "/pay/wallet/create-order" "/pay/wallet/capture" "/pay/monero/create-order" "/pay/crypto/create-invoice"}
```

Use the Cloudflare source IP as the counting characteristic, a 60 second period, 20 requests per source for payment routes, and a block response. Translation and AI should use their existing 30 and 20 request limits in separate rules. Do not trust `X-Forwarded-For`.

Longer term, migrate the site to a Worker with real Rate Limiting bindings, replace every nonfunctional namespace ID in `web/wrangler.jsonc`, add the `ASSETS` binding, and verify static security headers before changing domain routing. Real namespace IDs are environment resources and cannot be safely invented in a source report.

#### Verification

Expected dashboard state: an enabled rate-limit rule with the exact host, method, and path expression, source-IP characteristic, and configured thresholds. Use Cloudflare Security Events or a staging hostname to verify cross-point-of-presence counting. Do not load-test the production payment paths.

### CSP-01: Cloudflare-injected scripts are blocked

Severity: **Low**  
Status: **VERIFIED LIVE**

The live response uses a strict hash-based `script-src`. The main site script runs. Browser console output shows Cloudflare-injected inline code and Browser Insights code blocked by CSP, including the `static.cloudflareinsights.com` path. This is not the cause of the crypto-button bug. It creates console noise and disables those Cloudflare extras.

The safe fix is operational: disable Cloudflare Browser Insights and any automatic script injection for this zone. Do not add `unsafe-inline`, and do not weaken `script-src` to accept mutable injected code. If Browser Insights is a deliberate product requirement, add only its documented origin and use a Worker-generated per-response nonce for the exact injected script.

Verification:

```bash
python3.14 tools/website_security_audit.py
/usr/bin/curl -fsS -D - -o /dev/null https://winsvpn.org/ | rg -i '^content-security-policy:'
```

Expected: the static audit passes and a fresh browser console has no CSP violations from Cloudflare injection. The policy must still omit `unsafe-inline` and `unsafe-eval`.

### IOS-01: memory documentation contradicts the current deployment floor

Severity: **Low**  
Status: **VERIFIED**

`ios/PacketTunnel/PacketTunnelProvider.swift:1213-1217` says the project targets iOS 13.0 and supports the historical roughly 15 MiB cohort. The Xcode project now pins `IPHONEOS_DEPLOYMENT_TARGET = 15.0` in every build configuration. Later code at line 1303 also states iOS 15.0. The runtime gate itself is conservative and reads `os_proc_available_memory()`; the defect is stale assurance text that can mislead reviewers into applying the wrong release ceiling.

Replace the stale deployment-floor paragraph at lines 1211 through 1228 with this complete comment:

```swift
  /// # Why a runtime gate and not a deployment-target assumption
  ///
  /// The project now pins `IPHONEOS_DEPLOYMENT_TARGET` and the packaged
  /// `MinimumOSVersion` to 15.0. The historical roughly 15 MiB packet-tunnel
  /// limit on iOS 13 and 14 therefore does not describe a supported build.
  /// A modern platform estimate is not a compile-time entitlement guarantee,
  /// and available headroom still varies with device, operating-system build,
  /// loaded frameworks, and current process state.
  ///
  /// This code therefore asks the system for the process-specific remaining
  /// headroom immediately before every Winn start. It fails closed when that
  /// measurement is unavailable or below the measured datapath requirement.
  /// The decision uses the current device's limit and current resident state,
  /// not a hardcoded historical ceiling.
```

Verification:

```bash
rg -n 'IPHONEOS_DEPLOYMENT_TARGET = ' ios/Runner.xcodeproj/project.pbxproj
python3.14 tools/test_verify_ios_release_artifact.py
```

Expected: every project setting is 15.0 and the artifact verifier passes. Device testing under sustained full-size traffic is still required to establish actual peak footprint and jetsam behavior.

## 5. Platform-by-platform assessment

### Windows x86 and arm64

Result: **PASS STATIC, WINDOWS RUNTIME UNVERIFIED**

The privileged implementation is separated by `WINS_TUNNEL_SERVICE_CORE`. The service pipe uses `ProtectedPrefix`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, message mode, bounded request and response sizes, and `PIPE_REJECT_REMOTE_CLIENTS`. Its DACL grants full access to SYSTEM and administrators and read/write to interactive users. The request authorization path impersonates the client, checks the active console user and exact installed executable identity, and does not treat pipe access alone as authorization.

Child processes are created suspended, assigned to Job Objects with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and only then resumed. Assignment and resume failures terminate the child and close handles. AWG and Xray paths use the same containment shape. Winn seam handles use `uintptr_t`, avoiding 64-bit handle truncation and remaining valid for native arm64.

The direct `GRGW` interactive-user DACL is broader than the final application authorization, but the in-protocol identity check narrows it before privileged operations. This matches Microsoft's warning that `FILE_GENERIC_WRITE` includes pipe-instance creation rights and is why the current explicit rights are preferable to generic write.

No memory leak was found in the reviewed start and failure paths. Windows x86, arm64, service-control, WOW64, pipe-impersonation, and real Wintun execution were not available on this Mac. Required next evidence is the Windows production-host receipt named by the native test gate.

### Linux x86 and arm64

Result: **FAIL, LNX-01**

Positive controls are strong. `validate_root_owned_path()` resolves the bundle and checks every ancestor for UID 0 and no group or other write bit. Architecture-specific AWG, AmneziaWG-Go, Xray, and helper hashes are pinned. Helper arguments remain vectors across the privilege boundary. File descriptors use `FD_CLOEXEC`; engine code handles `EINTR`, bounded termination, and reaping. The eBPF helper uses `pidfd_open` and `PR_SET_NO_NEW_PRIVS`. Firewall setup uses dedicated `WINVPN-*` chains and `iptables-restore --noflush` instead of flushing host policy.

The blocker is lifecycle cleanup. See LNX-01. Linux libsecret, eBPF kernel execution, systemd sandbox behavior, real iptables/nft compatibility, x86 artifact identity, and arm64 artifact identity remain unverified on this host.

`shellcheck` produced warnings but no proven injection or firewall flush. The quoted `=~` expression still performs a literal membership substring match with space delimiters; it is unconventional but not the release blocker reported here.

### macOS x86 and arm64

Result: **PASS STATIC AND DARWIN UNIT COVERAGE, DEVICE TUNNEL UNVERIFIED**

The ruled route posture is centralized at `WinsMacRoutePosture.enforceRoutes = true`. The app writes that value into `NETunnelProviderProtocol`, sets `excludeLocalNetworks = true`, and has regression coverage for save and reload. Full-tunnel settings include default routes, a specific outer endpoint exclusion, DNS ownership, IPv6 handling, and MTU propagation. The app and extension entitlements declare NetworkExtension and shared app-group access. Hardened-runtime settings are present.

The outer-route exclusion and `enforceRoutes` combination are consistent with Apple's route model. The review found no loop caused by `scutil` parsing or a missing `/32` exclusion in current source. Real x86 and arm64 signed-app launches, hardened-runtime notarization, packet tunnel traffic, sleep and wake, and sustained memory were not executed.

### Android phone, tablet, and Android TV

Result: **PASS STATIC, USB RELEASE SMOKE UNVERIFIED**

The TV overlay declares `android.software.leanback` and `android.hardware.touchscreen` with `required="false"`, supplies a banner, and includes both `LAUNCHER` and `LEANBACK_LAUNCHER`. The base application remains playable on phones. The VPN service is non-exported, requires `BIND_VPN_SERVICE`, uses `specialUse` foreground-service metadata, and retains `stopWithTask="false"`.

Carrier sockets are protected before use. AWG socket registration calls `VpnService.protect()`. Winn v3 protected sockets do the same and fail closed on refusal. The `stealth-xray` and `winn-v3-stealth-chain` variants no longer use package-wide exclusion as a substitute for socket protection. User-selected package exclusions remain isolated in `applyUserExcludedApplications()`. The removed full-session Wi-Fi lock is absent; a bounded 10 minute partial wake lock remains.

An attached Motorola phone was detected, but the assigned workspace had no current `build/app/outputs/flutter-apk/app-release.apk`. A direct release build correctly refused because it lacked mandatory Dart obfuscation and private symbol custody flags. This audit did not use owner signing credentials or create an unsigned substitute, so uninstall, install, launch, and logcat smoke testing were not performed. That is a release gate, not a static code failure.

### iOS and tvOS

Result: **PASS STATIC FOR iOS, tvOS NOT A TARGET, MEMORY UNVERIFIED**

iOS saves `enforceRoutes = true` and `excludeLocalNetworks = true`. Tests pin save and reload behavior and verify the carrier endpoint exclusion survives promotion. The NetworkExtension reports physical footprint and available process memory, requires 12 MiB of remaining headroom for Winn starts, and fails closed if headroom is unknown. QUIC client receive windows are explicitly capped.

The requested strict 15 MiB ceiling is not the current platform contract because this project now targets iOS 15.0. That does not establish safety. Actual peak footprint under high packet throughput on the oldest supported device remains unverified. The correct acceptance test is measured `phys_footprint`, `os_proc_available_memory()`, packet loss, and jetsam status on real devices.

There is no shipping tvOS Xcode target. D-pad navigation and background wakeup therefore cannot be tested or claimed. The Android TV implementation does not substitute for tvOS evidence.

### Browser extensions

Result: **FAIL ARTIFACT, SOURCE CONTROLS PASS**

Chrome and Edge use MV3 service workers. Firefox uses a nonpersistent background script. Listeners are installed synchronously, and the controller reconstructs state after worker termination. Chromium and Firefox request `webRequest` and `webRequestAuthProvider` only for proxy authentication. Authentication decisions bind scheme, loopback host, port, realm, challenge type, and current in-memory credential.

PAC generation has no `DIRECT` fallback for protected scope and avoids DNS helper calls. Block rules are installed before proxy transitions. Native-host manifests bind exact Chrome, Edge, and Firefox identities, and no `externally_connectable` surface is declared. Safari accurately reports that it has no WebExtension proxy-routing API rather than claiming VPN coverage.

Source tests pass, but the canonical Chrome archive is stale. See EXT-01. Live Chrome, Edge, Firefox, and Safari install, worker-termination recovery, private-window behavior, native-host registration, and store-signed package identities remain unverified.

### Control plane and data planes

Result: **FAIL, DB-01**

SQLite WAL, foreign keys, normal synchronous mode, and a busy timeout are configured. Single-use activation secrets use `secrets.token_urlsafe(32)`, explicit expiry, and an atomic used-at transition. Datetime parsing normalizes aware and naive input into UTC. Payment provisioning uses an encrypted activation-delivery outbox, leases, exponential retry, and cascade cleanup. Remote PayPal verification and subscription calls observed in the reviewed paths are moved through `asyncio.to_thread`, with database connections closed during remote HTTP calls.

The data-plane installers use dedicated chains and avoid broad host-firewall flushes. Token entropy and single-use SQL were adequate in reviewed paths. The event-loop issue remains release blocking. Real multi-worker SQLite contention, SMTP delivery, PayPal signature exchange, BTCPay settlement, Monero settlement, refund reversal, and data-plane deployment were not exercised.

### Shared Dart and three protocol paths

Result: **PASS IMPLEMENTATION TESTS, RELEASE CUSTODY FAIL**

Winn v3 is selected before v1 parsing. Once v3 is selected, native hosts fail closed and do not fall back to classical AWG. Descriptor verification checks signature, node identity, generation, TTL, carrier, and device material. Ordinary v3 failure authorization is generation-bound and target-bound.

The v1 compatibility sequence is AWG first, Xray second. The grant cannot reorder or retry consumed legs, extend its TTL by re-observation, cross a selection generation, or survive a security refusal. `servedConfigMayUseCoverNodeFallback()` denies fallback when `securityRefused` is true. The Go module, race tests, and selected fuzz targets passed.

The release-custody failure is REL-01. There was no live protocol handshake to a gateway, no packet-capture proof, no adverse carrier migration, and no performance run against actual server hardware.

### Live website, DNS, payments, and provisioning

Result: **FAIL, WEB-01; EDGE-01 EXTERNAL CONTROL UNKNOWN**

Live root and crypto-config GETs returned 200. Payment-creation endpoints returned 405 to GET, so no state was created. The crypto-config response correctly varies by Origin: the allowed origin is echoed and an untrusted origin receives no `Access-Control-Allow-Origin`. HSTS, nosniff, frame denial, opener policy, resource policy, referrer policy, and permissions policy are present. DNS resolves through Cloudflare over IPv4 and IPv6. The TLS certificate is current for the audit date.

The live paid button works on the happy path but the older failure branch remains. See WEB-01. The live response also contains CSP-blocked Cloudflare extras. See CSP-01. Cloudflare dashboard DNS record types, proxy flags, Pages custom-domain routing, cache rules, WAF rules, rate-limit rules, and Worker binding values were not accessible and are not claimed.

## 6. Performance and memory assessment

No evidence supports a blanket request to enlarge buffers. Current code already uses bounded, measured queues:

- Winn's default path MTU is 1450. The carrier plan computes the floor across all allowed carrier classes, then native hosts apply the published inner MTU. Tests reject the historical dialed-only MTU and reject IPv6 when the inner MTU is below 1280.
- Linux's relay seam uses a 2 MiB requested receive buffer, reads back the granted size, drains with `recvmmsg` batches of 128, writes batches of 32, and uses a 2048-slot ring with drop and high-water counters. It attempts `SO_RCVBUFFORCE` only when capability permits and falls back to `SO_RCVBUF`.
- The shared datapath defaults to 512 queue slots and caps configuration at 8192, bounding its pooled datagram memory below roughly 12 MiB at the absolute packet limit.
- iOS QUIC receive windows are capped at 512 KiB per stream and 2 MiB per connection. The untracked regression test must be brought into custody.
- Android removed the full-session Wi-Fi performance lock. The remaining partial wake lock expires after 10 minutes, while underlying-network hints avoid needless handoff ambiguity.

Optimization priority should be measurement, not larger constants. Capture throughput, p50 and p99 packet latency, CPU time, wakeups, battery drain, granted socket-buffer size, queue high-water marks, and drop counters on each target. The first code optimization should be DB-01 because eliminating event-loop stalls improves both availability and tail latency without raising memory.

Required performance acceptance runs:

1. Windows x86 and arm64: Wintun traffic at 64-byte, 1280-byte, and negotiated-MTU packets; process-handle and Job Object counts before and after 100 start-stop cycles.
2. Linux x86 and arm64: `perf stat`, seam counters, socket grant, BPF map and FD counts, and teardown residue across 100 cycles.
3. iOS oldest supported device: sustained bidirectional traffic with footprint, available memory, jetsam log, QUIC stream count, packet loss, and sleep-wake transitions.
4. Android phone and TV: Battery Historian, foreground-service survival, screen-off traffic, network handoff, `protect()` failure injection, and package-exclusion isolation.
5. Browser: worker termination during each state transition, proxy outage, credential rotation, PAC exception, incognito control, and native-host disconnect.
6. Hub: concurrent paid webhook, logout, deletion, and descriptor traffic with event-loop lag and SQLite lock telemetry.

## 7. Release gates and definite next actions

The following order is mandatory for these observed bytes:

1. Fix DB-01 and add a contention regression that proves an unrelated event-loop ticker keeps running.
2. Fix LNX-01 and obtain Linux x86 and arm64 shutdown receipts for window close, `SIGINT`, and `SIGTERM`.
3. Publish the already-corrected website only after a clean staged hash and static audit, then verify that the live paid selector has no donation fallback.
4. Bring `h3_receive_window_test.go` into version control and rerun the full Flutter suite.
5. Rebuild the Chrome ZIP with the pinned producer and rerun every exact-archive gate.
6. Resolve or document every `git diff --check` failure in the intended release change set.
7. Produce a signed Android release APK through the guarded release producer, uninstall `org.winsvpn.app`, install the exact canonical APK, launch it, and inspect startup and VPN logs on the attached phone.
8. Obtain real Windows, Linux, iOS, macOS, Android TV, Chrome, Edge, Firefox, and Safari receipts. Static checks on a Mac do not satisfy those targets.
9. Confirm Cloudflare WAF and rate-limit state from the dashboard. Keep CSP strict and remove unwanted script injection.
10. Freeze the intended tree, record its hash, rerun all gates from the frozen bytes, and compare artifact inputs to that exact tree.

Current decision: **NO-GO**. No Critical exploit was demonstrated, but the three High defects and the red release-custody gates prevent a defensible release claim.

