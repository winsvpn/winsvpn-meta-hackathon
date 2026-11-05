# Codex Deep Audit Report: Daybreak Blue

- Model Identifier: `gpt-daybreak-blue-latest`
- Reasoning Effort: `xhigh`
- Collected: `2026-09-14T05:06:49.309173+00:00`
- Process Exit Code: `0`
- Content Source: `lane report file (/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/daybreak/docs/evidence/codex_daybreak_blue_audit.md)`
- Usage Metadata: `{"input_tokens": 28700071, "cached_input_tokens": 27956526, "cache_write_input_tokens": 726749, "output_tokens": 72634, "reasoning_output_tokens": 24514}`

## Reasoning Trace

```
**Clarifying workspace and memory boundaries**
**Planning audit with memory and web tools**

**Reviewing MEMORY lines 340-381**

**Planning repository inspection and reporting**
**Orchestrating parallel command execution**

**Investigating empty diff output**

**Planning defect inspection and reporting**

**Inventorying target file sizes and lines**

**Planning targeted static analysis**
**Investigating Git diff discrepancies**

**Investigating missing git object**
**Inspecting named pipe functions**

**Inspecting line ranges**

**Identifying potential TOCTOU vulnerability**
**Preparing audit and inspection of Windows service core**

**Identifying potential WriteResponse bug**

**Inspecting RunArgv for bugs**

**Identifying Linux shutdown race condition**
**Assessing root path validation and memory leak**

**Identifying BPF hash issue in dev vs release**

**Inspecting and arming watchdog**

**Investigating watchdog race conditions**

**Tracing activeConfig assignments**

**Inspecting active configuration**

**Identifying potential lifecycle gate bug**

**Checking for native_sources usage**

**Investigating LifecycleGate class location**

**Inspecting lifecycleGate variable usage**

**Searching class with case sensitivity**

**Assessing potential deadlock in tunnel cancellation**

**Classifying unsupported tvOS target**

**Examining Android early Xray failure flow**

**Identifying start flow bug and verifying Android variants**

**Investigating Android exported service permissions**
**Reviewing official Android service documentation**

**Verifying environment variable usage restrictions**
**Checking permission requirements for exported services**

**Examining Play Services permissions for Wearable API**

**Prioritizing background and controller setup**

**Verifying duplicated catch syntax**

**Assessing MV3 webRequestAuthProvider support**

**Checking store IDs file**

**Exploring store ID sources**

**Identifying Firefox host argument differences**
**Planning inspection of installed scripts**

**Inspecting get_db function**

**Assessing expiration timestamp consistency**
**Planning workspace-local temp directory**

**Evaluating flush scope with regex**

**Identifying risky global IPv6 DROP policy**
**Analyzing firewall rule restore behavior**

**Focusing on section 6150-6800**

**Identifying checkout URL validation gap**

**Preparing live site repro with browser**

**Requesting exact getState data**

**Retrieving exact winsvpn tab**

**Inspecting current directory state**

**Inspecting dev logs before clicking buttons**

**Planning UI interaction alternatives**
**Planning parallel git and network probes**
**Designing sequential shell command execution**

**Planning browser tab creation for recovery**
**Confirming fallback to createBrowserTab with IAB**

**Identifying wallet permission policy bug**
**Planning live HTML retrieval for code comparison**
**Mapping missing Git blobs to index paths**

**Investigating CSP script hash mismatch blocking payment listener**
**Analyzing inline script hashes and Cloudflare injection effects**

**Verifying script blocking due to Cloudflare injection**
**Exploring tab CUA API for browser control**

**Clicking node 618 and retrieving AX**

**Evaluating browser UI automation options**
**Planning safe browser test with Playwright**

**Inspecting Playwright installation**

**Planning parallel test execution**
**Organizing parallel test lanes**

**Planning sequential test runs**

**Planning unified server tests**

**Verifying environment setup and session handling**

**Tracking extension test failures**

**Identifying large test suite size**

**Investigating missing frozen esbuild archive**
**Verifying Bash regex behavior and Python version**

**Locating gate file and inspecting test helpers**

**Configuring fetch-enabled cache for tests**

**Identifying and isolating race condition in tests**
**Optimizing extension fetch with parallel sessions**

**Adjusting function wait timing**

**Starting independent Flutter analysis**

**Planning polling with exec Promise**

**Investigating server import path issue**
**Verifying server directory symlink status**

**Investigating pytest rootdir and module paths**

**Tracing import source in test setup**

**Investigating duplicate test directory scanning**
**Checking for sys.path manipulation causing collisions**

**Planning isolated test script execution**
**Planning sequential Flutter testing execution**

**Starting Flutter test and server script**

**Planning parallel Go test runs with isolated caches**

**Implementing multiple polling mechanism**

**Tracing unexpected production test imports**
**Investigating pyc origin causing production path reports**

**Inspecting fetch_allowed function**

**Requesting specific code lines 258-265**

**Investigating environment mutation in tests**

**Investigating test environment contamination**

**Identifying and planning fix for env leakage across tests**
**Investigating OpenSSL path and logger file handle issues**

**Identifying Go module issues and pending dependency polling**

**Identifying security flaw in appUpdateRequired**

**Reviewing main logic comments**

**Identifying version validation weaknesses**
**Preparing deployment verification without cloud deploy**

**Investigating Cloudflare challenge script**

**Analyzing Cloudflare JS detection CSP issue**

**Diagnosing live button activation and test inconsistencies**

**Inspecting live vs local PaymentRequest fallback**
**Planning targeted platform test execution**

**Handling missing test files**

**Assessing Android minSdk and API guards**

**Inspecting jniLibs symlink issues**

**Inspecting build directories for debug binaries**

**Assessing debug engine compatibility issues**

**Inspecting WatchCommandService permissions**

**Researching Android Wear listener service guarantees**

**Investigating ResourceWarning cause in logs**

**Identifying logging FileHandler leak in repeated exec calls**
**Assessing logging and caching issues in production and tests**
**Testing click event blocking by extension UI**

**Exploring pressKey API to dismiss popup**
**Using cua.getState to inspect Edge app**

**Planning cautious polling strategy**

**Isolating Apple test failures for clarity**
**Estimating final test counts including skips**
**Investigating duress SMS feature mismatch**

**Verifying duress code deadness and permissions**
**Planning Git object integrity verification**

**Fixing PATH corruption from loop variable**

**Diagnosing missing Git report file**
**Inspecting git status for missing staged file**

**Verifying _is_dotted_version function behavior**
**Investigating HTTP route and QUIC performance**

**Assessing envelope encode/decode allocations**
**Inspecting envelope.go for optimization**

**Assessing H3 packet allocation optimization**
**Planning decodeEnvelope memory management changes**

**Preparing commentary before tool use**

**Planning exhaustive report inspection**

**Querying codebase for version and manifest**

**Requesting exact sed/nl snippets**

**Requesting complete web lines from 6785 onward**

**Planning test executions for Go suite**

**Locating brew Python path**

**Investigating Homebrew OpenSSL path**

**Checking alternate OpenSSL locations**

**Planning test runs 9-13 with environment**

**Confirming standalone script execution**

**Planning individual Apple test runs**

**Planning macOS build with lock handling**

**Testing macOS release build without pub**

**Planning git fsck check**

**Confirming source hashes before running**

**Planning version validator proof with extracted function**

**Inspecting parser logic**

**Identifying extension test contamination lines**

**Listing artifact variant sizes**

**Adjusting cache path for tests**

**Searching for archive in build tmp**

**Planning build environment setup**
**Evaluating test environment restrictions**

**Planning Android Gradle unit tests**

**Analyzing test result XML for failures**

**Adjusting test strategy and reporting release hold**

**Planning live web source verification**

**Analyzing dynamic Cloudflare script impact**

**Switching to Brew OpenSSL path**

**Planning CSP hash verification script**

**Planning in-app browser reproduction**

**Researching browser tab controls**

**Planning IAB tab creation with known URL**

**Evaluating Playwright usage for read-only browsing**

**Evaluating browser automation options**

**Assessing macOS Edge scripting limitations**

**Assessing architecture-specific process checks**

**Inspecting Android service lines**

**Inspecting tunnelWakeLock usage**

**Inspecting early xray check timing**

**Identifying unreachable dead code**

**Planning benchmark runs for allocation metrics**

**Preparing shellcheck analysis for optimizations**

**Investigating potential SC2178 bug**

**Assessing shellcheck warnings and path handling**
**Planning ResourceWarning isolation and testing**

**Planning website security audit**

**Planning Flutter test with compact reporter**

**Planning delayed polling**

**Reporting test execution status**

**Verifying Windows test accuracy**

**Assessing stale MSI and AWG blockers**

**Inspecting item 276**

**Planning dependency replacement with official binaries**

**Running extension bundle gates**

**Verifying Edge support in Chrome script**

**Considering edge zip for ID inference**

**Identifying edge assertion scripts**

**Planning audit report without source modifications**
**Verifying presence of Python imports**

**Analyzing environment variable handling in tests**
**Investigating producer call in parameterization**

**Planning full test suite rerun with caching**
**Isolating tests for missing archive failure**

**Investigating missing session ID and output termination**

**Estimating required test count**

**Evaluating full test suite stability**
**Planning full pytest run with diagnostics**

**Planning detailed comprehensive report**
**Detailing web flow fixes and CSP alternatives**

**Switching to official curl for requests**

**Selecting markdown endpoint**

**Designing nonce-based CSP injection**
**Inspecting worker fetch handler for patch**

**Planning dynamic nonce implementation fix**
**Evaluating no-transform impact on JSD**

**Adding no-transform to Cache-Control header**
**Planning exact patch and verification commands**
**Drafting report file without placeholders**

**Clarifying Go commands syntax**
**Outlining report structure and severity levels**
**Verifying live button reproduction inconsistencies**

**Planning button and coin selector behavior**

**Fixing coin selector disabling on config failure**

**Planning account provisioning pipeline review**

**Planning poll session and patch application**

**Planning precise line-number extraction**

**Planning code inspection with line numbers**

**Searching Windows named pipe lines**

**Searching for CreateNamedPipe usage**

**Inspecting backend and service separation**

**Planning exact issue fixes and diffs**
**Detailing exact code patch snippets**
**Preparing exact diffs against live code**

**Planning JSD no-transform patch**
**Planning detailed multi-platform report**

**Planning report verification and banned term search**

**Planning placeholder scanning**

**Clarifying placeholder usage and code completeness**

**Designing robust file sorting loop**
**Implementing exact sorted file list extraction**

**Planning report update post-test**

**Planning report validation and test enhancement**
**Inspecting server tests for app version**

**Confirming endpoint function testing approach**

**Implementing wait after exec return**

**Updating report ledger with patch**

**Planning detailed markdown and byte analysis**
**Verifying code defects and systemd service parameters**

**Investigating Linux build script sandbox usage**

**Inspecting extension manifest permissions**

**Planning dynamic PAC fallback and systemd patching**

**Verifying PAC fallback support**

**Clarifying PAC fallback behavior**

**Patching sentence**

**Planning git status verification**

**Evaluating trailing spaces in assertions**
**Planning removal of trailing whitespace**

**Planning patch to remove trailing spaces**

**Planning rerun checks**

**Verifying final file details and banned terms**
**Composing final concise audit report**
```

## Audit Findings & Exact Fix Implementations

# Daybreak Blue Independent WinsVPN Audit

Author: Daybreak Blue

Audit date: 2026-09-14

Assigned snapshot: `/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/daybreak`

Revision at audit start: `89be66e75747c0b493583ca9c9efd7787c88a974`

## 1. Executive result

Release decision: **NO-GO**.

No Critical source vulnerability was confirmed. Four High findings prevent a defensible release or expose a live customer path. The most urgent live defect is a deployment gap: the public paid crypto controls still fall back to a static donation modal when automated checkout is unavailable. A customer can therefore send funds without creating the order that provisions an account. The assigned snapshot already contains the correct fail-closed logic, but those bytes are not live.

The repository also has an incomplete Git object database. Eleven staged blob objects are missing, normal staged and unstaged diff inspection fails, and one staged-add report has no working-tree copy. Ten missing objects can be restored exactly from current files because their hashes match. The absent report cannot be reconstructed from this checkout.

Windows packaging is blocked by stale AWG payload identities. Android phone and TV unit suites each have three freshness-gate failures because debug engine files are absent and native producer authority is not current. The macOS release build reaches the native packaging phase and then correctly stops on missing reviewed external AWG and Xray authority. These are safe refusals, but they are still release failures.

| ID | Severity | Verified finding | State |
|---|---|---|---|
| WEB-01 | High | Live paid crypto buttons retain a donation-modal fallback with no account-order binding | Open on live site, fixed only in assigned snapshot |
| CUST-01 | High | Eleven staged Git blobs are missing and repository diff custody is broken | Open |
| WIN-01 | High | Windows AWG MSI and `awg.exe` do not match the pinned official identities | Packaging refuses release |
| REL-01 | High | Apple and Android native artifact authority gates are not satisfied | Release blocked |
| CP-01 | Medium | Hub app-version validation accepts malformed floors the client rejects | Open in assigned snapshot |
| WEB-02 | Medium | Live `Permissions-Policy` sets `payment=()` and disables Payment Request | Fixed only in assigned snapshot |
| WEB-03 | Medium | Cloudflare JavaScript Detection injects an inline script rejected by the live CSP | Open on live site |
| AND-01 | Medium | Android debug engine inventory is absent for all three tested ABIs | Unit variants fail |
| OPS-01 | Low | Shell diagnostics expose fragile iteration and directory-mode warnings | Open |
| PERF-01 | Low | Two measured Go hot paths allocate per operation | Optimization candidate, not a field regression |

All findings below distinguish verified evidence from untested target behavior. No deployment, payment order, account creation, email, firewall mutation, or other live state change was performed. No secret value is reproduced.

## 2. Scope, custody, and method

The audit read and tested only the assigned workspace. The production tree at `/Users/owner/xprize/winsvpnv3` was not read. Live activity against `https://winsvpn.org` was limited to DNS, TLS, GET, response-header, HTML, and browser accessibility inspection.

The checkout was already heavily modified and staged at audit start. Those bytes were treated as the candidate under review. No pre-existing change was cleaned, reset, staged, or rewritten. This report is the only file added by this audit.

Primary dynamic checks included Flutter static analysis and 1,926 tests, the complete Winn Protocol Go suite, server suites through Round 12, descriptor and deletion standalone harnesses, the 56-check website security audit, Apple contract and watchdog tests, Windows release-oracle tests, Linux teardown and pipe tests, Android phone and TV unit variants, extension packaging tests, shell syntax checks, ShellCheck, release-build attempts, Git object verification, and read-only live web probes.

Severity meaning:

* Critical: directly exploitable broad compromise, key disclosure, or systemic authorization loss.
* High: live payment integrity failure, release-custody failure, or a mandatory release gate that cannot pass.
* Medium: a security control can silently become ineffective, or an important feature is disabled under a realistic state.
* Low: hardening, maintainability, or measured optimization work without demonstrated security or release impact.

## 3. High findings

### WEB-01: Paid crypto can fall into a donation flow on the live site

Severity: **High**

Affected service: `https://winsvpn.org`

Local corrective implementation: `web/index.html:6483-6540`, `web/index.html:6611-6616`, `web/index.html:6764-6791`

#### Verified behavior

The live page returned enabled paid-plan controls. Its deployed click handler still contains this branch:

```javascript
if (!triggered) {
  openModal(coin, planTitle);
}
```

The same deployed page returns early if `/api/site/crypto-config` cannot be loaded. It does not disable the paid-plan coin selectors or render an inline failure. The later handler can then open `#cryptoModalBackdrop`, which displays the static donation address. That modal does not call `/pay/monero/create-order` or `/pay/crypto/create-invoice`, so it creates no automated provisioning transaction.

The endpoint itself was healthy during this audit and returned HTTP 200 with both public enablement flags true. That does not remove the defect. A transient endpoint failure, initialization exception, script timing problem, or missing automated button still enters the donation path. The result is a payment-to-account binding failure.

The user-reported visual symptom, that the button cannot be clicked, was not reproduced through a complete physical click because the available Edge surface was covered by another extension UI and the in-app browser was unavailable. Accessibility inspection showed four enabled collapsed payment buttons. The source-level fallback and deployed byte drift were independently verified. No payment endpoint was called.

#### Root cause

Two distinct concepts share one event path:

* The donation UI is intentionally static and can display a public address.
* Paid plans require an order or invoice before money is sent.

The deployed paid-plan handler treats missing automated controls as permission to enter the donation path. The deployed initialization path also fails open by leaving selectors usable after configuration failure.

#### Exact production correction

Deploy the current audited `web/index.html` bytes. The controlling implementation must contain these complete functions and the fail-closed click branch:

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

async function setupCryptoPayments() {
  const cards = [...document.querySelectorAll("[data-plan-key]")];
  if (!cards.length) return;
  cards.forEach((card) => setCryptoCoinSelectors(card, false, false));
  const unavailable = "Automated crypto checkout is unavailable. Please retry shortly or choose another payment method.";
  let config = null;
  try {
    const response = await fetch("/api/site/crypto-config", { cache: "no-store" });
    if (!response.ok) throw new Error("Crypto configuration unavailable");
    config = await response.json();
  } catch (_) {
    cards.forEach((card) => renderCryptoUnavailable(card, unavailable));
    return;
  }
  const moneroEnabled = Boolean(config && config.monero_enabled === true);
  const cryptoEnabled = Boolean(config && config.crypto_enabled === true);
  if (!moneroEnabled && !cryptoEnabled) {
    cards.forEach((card) => renderCryptoUnavailable(card, unavailable));
    return;
  }

  for (const card of cards) {
    const planKey = card.dataset.planKey;
    const row = card.querySelector("[data-crypto-row]");
    if (!row || !planKey) continue;
    try {
      buildCryptoRow(row, planKey, moneroEnabled, cryptoEnabled);
      setCryptoCoinSelectors(card, moneroEnabled, cryptoEnabled);
    } catch (_) {
      renderCryptoUnavailable(card, unavailable);
    }
  }
}
```

Replace the paid-plan fallback with:

```javascript
if (!triggered) {
  renderCryptoUnavailable(card, "Automated crypto checkout is unavailable. Please retry shortly or choose another payment method.");
}
```

Keep the donation modal separate. Its backdrop reparenting must remain:

```javascript
var backdrop = document.getElementById("cryptoModalBackdrop");
if (backdrop && backdrop.parentElement !== document.body) {
  document.body.appendChild(backdrop);
}
```

#### Verification

Run before deployment:

```sh
python3 tools/website_security_audit.py
rg -n 'openModal\(coin, planTitle\)' web/index.html
rg -n 'renderCryptoUnavailable\(card' web/index.html
```

Expected: 56 checks pass, the first search prints no paid-plan fallback, and the second search shows configuration failure plus the click fallback. In a staging browser, intercept `/api/site/crypto-config` with HTTP 503. Every plan coin selector must be disabled, an inline status must appear, and `#cryptoModalBackdrop` must remain closed. Then restore HTTP 200 and confirm each paid coin invokes only its automated panel. No test should send a real payment.

After an authorized deployment, GET the live page, hash it, and repeat the failure injection in a non-production route. The live HTML must no longer contain `openModal(coin, planTitle)`.

### CUST-01: Git object loss prevents reproducible review

Severity: **High**

Affected state: assigned repository index and object database

#### Verified behavior

`git diff` and `git diff --cached` fail because required staged blobs are absent. `git fsck --full --no-reflogs` reports eleven missing blobs. HEAD is still connected. There is no alternate object directory and no promisor or partial-clone configuration.

Ten corresponding working-tree files exist and hash to the exact missing object names. One entry, `docs/evidence/round11_remediation.md`, has index state `AD`, no working-tree copy, and missing blob `78c9cd895b9b1bc866035d0371a7ab8082c8a095`. Its exact content is unrecoverable from this checkout.

Missing object inventory:

| Blob | Path | Recoverable here |
|---|---|---|
| `c781de65bceda7d35a117e874790b5fa87ead90d` | `test/owned_keyboard_listener_test.dart` | Yes, exact file hash matches |
| `6c8704b46510d7d141dc0525c9c4a719a716c502` | `extension/tools/test_background_lifecycle.py` | Yes |
| `5917a278c5a689254fd8cadce18bd7e79193f8d9` | `tools/native_messaging/host/test/wins_bridge_host_origins_test.dart` | Yes |
| `329e8bd5e17cd22e70785b048ee445658bfdf1d2` | `server/test_control_plane_round11.py` | Yes |
| `242d2bedebfba51085fbf8d60eb0c03740ef2c3a` | `winn_protocol_experimental/cmd/winn3-gateway/peer_registry_round11_test.go` | Yes |
| `bd3895a1b59e7f767350665812f6d6b5a2c87afe` | `winn_protocol_experimental/cmd/winn3-gateway/gateway_authority_test.go` | Yes |
| `ddc0b2518629d461034e6ae6455d7c397677a89d` | `lib/owned_keyboard_listener.dart` | Yes |
| `78c9cd895b9b1bc866035d0371a7ab8082c8a095` | `docs/evidence/round11_remediation.md` | No |
| `115cf5c93e22c2ab34031109410f958668dd7c78` | `server/test_control_plane_round10.py` | Yes |
| `93e17cfd087927c9ea11a48ff3fb0ec6e7e560b5` | `winn_protocol_experimental/internal/carrier/h3_receive_window_test.go` | Yes |
| `d97471e0e6ef89ace5da75451e1d7bb650e76466` | `winn_protocol_experimental/cmd/winn3-gateway/forward_round10_test.go` | Yes |

#### Root cause

The index refers to objects not present in `.git/objects`. Git cannot reconstruct staged or unstaged changes consistently without those preimages. Test success against working bytes does not repair or authenticate the staged state.

#### Exact recovery procedure

The ten matching files can be restored without changing their bytes or the index:

```sh
git hash-object -w -- test/owned_keyboard_listener_test.dart extension/tools/test_background_lifecycle.py tools/native_messaging/host/test/wins_bridge_host_origins_test.dart server/test_control_plane_round11.py winn_protocol_experimental/cmd/winn3-gateway/peer_registry_round11_test.go winn_protocol_experimental/cmd/winn3-gateway/gateway_authority_test.go lib/owned_keyboard_listener.dart server/test_control_plane_round10.py winn_protocol_experimental/internal/carrier/h3_receive_window_test.go winn_protocol_experimental/cmd/winn3-gateway/forward_round10_test.go
```

Expected output is the ten matching blob hashes listed above, excluding the unavailable Round 11 report hash.

Recover the exact Round 11 report bytes from an independently trusted backup or another object database. Verify before importing:

```sh
git hash-object /absolute/trusted/path/round11_remediation.md
```

Expected: `78c9cd895b9b1bc866035d0371a7ab8082c8a095`. Only after that equality is proven:

```sh
git hash-object -w /absolute/trusted/path/round11_remediation.md
git fsck --full --no-reflogs
git diff --check
git diff --cached --check
```

Expected: no missing objects, both diffs render, and both whitespace checks exit 0. Do not create replacement prose and claim it is the missing object. That would destroy staged-byte provenance.

### WIN-01: Windows native payload identity is stale

Severity: **High**

Affected target: Windows x86 and ARM64 release packaging

#### Verified behavior

The Windows migration and release-oracle tests passed because they correctly detect and refuse stale inputs. Current and required identities are:

| Artifact | Current SHA-256 | Required SHA-256 | Result |
|---|---|---|---|
| AmneziaWG MSI | `a0fa8102ccbb7f873c701022b14ba5a8c121c535260467a2b33733369193da17` | `a1b48ea815696194b31eea7f42d6ebc9f42d2cc86767295172418b122914ce02` | Stale |
| `awg.exe` | `cd17f864b32ab9af1b65205d75b1ae2d87c418cc6635233471524d77a2333b0b` | `272badaccc2cd3c0fe17c00a26d5bbc714966188142656507c09a7229ce4bd2c` | Stale |
| Migration helper | `902c9f2856e899e440933d3f1ed62ff377e2b5ba561e42c4145a1b7c0fac55ad` | Same | Correct |

The owner Authenticode sentinel is also absent. No Windows release candidate can be authenticated or packaged from this state.

#### Root cause and correction

This is an artifact-custody defect, not a C++ logic defect. Code cannot manufacture the required signed binaries. Obtain the reviewed upstream payloads through the documented producer path, prove the exact hashes and signatures, then rerun the sealed packager. Do not edit the expected hashes to accept current bytes.

Verification:

```powershell
Get-FileHash installer\windows\dependencies\amneziawg-amd64.msi -Algorithm SHA256
Get-FileHash installer\windows\dependencies\awg.exe -Algorithm SHA256
python tools/test_windows_awg_migration.py
python tools/test_windows_release_readiness.py
python tools/test_windows_arm64_inner_gate.py
```

Expected: the first two hashes equal the required values above; all three test programs exit 0; the packager no longer reports stale identity; Authenticode validation names the intended signer and a valid chain. Native x86 and ARM64 execution still requires Windows target machines.

### REL-01: Native release authority is incomplete

Severity: **High**

Affected targets: Android, Android TV, macOS, Windows, and any cross-platform release claim depending on their native engines

#### Verified behavior

`flutter build macos --release --no-pub` compiled and reached native packaging, then stopped with an explicit owner block because reviewed external AWG and Xray authority, authorization, candidate, source freeze, and producer receipt custody are absent.

Both `:app:testPhoneDebugUnitTest` and `:app:testTvDebugUnitTest` ran 592 tests and failed the same three `ShippedEngineFreshnessTest` cases. Debug `libwinnengine` is absent for `arm64-v8a`, `armeabi-v7a`, and `x86_64`; source freshness is blocked by stale Windows native consumer authority; variant identity cannot be compared without debug files. Profile and release files exist for all three ABIs, but presence is not authority.

This is a correct fail-closed outcome. It disproves the supplied claim that all mandatory verification commands pass in the current assigned snapshot.

#### Correction and verification

Use the repository's reviewed producer workflow to generate one frozen engine candidate, its receipts, and all consumer copies. Satisfy the existing owner authority records without weakening their checks. Then run, without parallel Flutter commands in this checkout:

```sh
./android/gradlew -p android :app:testPhoneDebugUnitTest
./android/gradlew -p android :app:testTvDebugUnitTest
flutter build macos --release --no-pub
```

Expected: each Android task reports 592 tests with zero failures, all ABI and variant identity checks pass, and the macOS builder produces a release artifact without an owner-blocked message. Follow with physical Android and Apple smoke tests under the project release procedure. No code change that bypasses freshness, identity, source-freeze, or signature checks is acceptable.

## 4. Medium findings

### CP-01: Server accepts app-version floors the client will ignore

Severity: **Medium**

Affected code: `server/wins_control_plane_setup_ONETOUCH.sh:25322-25357`, `lib/app_update_gate.dart:40-87`

#### Verified behavior

The server validator is:

```python
def _is_dotted_version(value):
    return all(ch.isdigit() or ch == "." for ch in value) and any(ch.isdigit() for ch in value)
```

It accepts `1..2`, `1.2.3.4`, and unbounded numeric components. The client accepts only an exact three-component release version with at most nine digits per component. On a fresh client, a malformed nonempty minimum parses to null and the update gate remains open. An administrator can therefore receive HTTP 200 while setting a minimum-security version that new clients silently ignore.

#### Root cause

Server and client enforce different grammars. The server comment promises a typo cannot set an unparseable value, but the predicate checks only the character alphabet.

#### Exact production diff

The hub already imports `re`. Apply this targeted replacement:

```diff
-    def _is_dotted_version(value):
-        return all(ch.isdigit() or ch == "." for ch in value) and any(ch.isdigit() for ch in value)
+    release_version_pattern = re.compile(
+        r"(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\Z"
+    )
+    def _is_release_version(value):
+        return release_version_pattern.fullmatch(value) is not None
     # A non-empty min/latest must be a plain dotted version so a typo cannot
     # set a value that either blocks everyone or the client cannot parse.
-    if min_supported and not _is_dotted_version(min_supported):
+    if min_supported and not _is_release_version(min_supported):
         raise HTTPException(status_code=400, detail="min_supported must be a dotted version like 1.0.15, or empty to disable the gate.")
-    if latest and not _is_dotted_version(latest):
+    if latest and not _is_release_version(latest):
         raise HTTPException(status_code=400, detail="latest must be a dotted version like 1.0.16, or empty.")
```

Add a direct route test that posts accepted values `0.0.0`, `1.0.16`, and `999999999.999999999.999999999`; each must return 200. Post `1..2`, `1.2`, `1.2.3.4`, `01.2.3`, and `1000000000.2.3`; each must return 400 and must not alter stored settings.

Verification:

```sh
pytest -q server/test_control_plane_round8.py server/test_control_plane_round9.py server/test_control_plane_round10.py server/test_control_plane_round11.py server/test_control_plane_round12.py
flutter test --no-pub --concurrency=1 test/app_update_gate_test.dart
```

Expected: all server tests pass, the malformed cases return 400, and the Dart test passes with identical accepted grammar.

### WEB-02: Live policy disables browser wallet payments

Severity: **Medium**

Affected service: live response headers

Correct local code: `web/_headers:6`, `web/_worker.js:1781-1785`

The live response advertises `payment=()`. That disables the Payment Request feature for every origin, including the site itself. Local candidate bytes correctly set:

```http
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(self "https://www.paypal.com" "https://www.sandbox.paypal.com" "https://pay.google.com"), usb=()
```

Deploy both `web/_headers` and `web/_worker.js` from the same candidate. They cover different response paths and must remain byte-equivalent for this policy.

Verification:

```sh
curl -fsSI https://winsvpn.org/ | tr -d '\r' | grep -i '^permissions-policy:'
```

Expected: `payment` contains `self`, PayPal production and sandbox origins, and Google Pay. It must not equal `payment=()`.

### WEB-03: Cloudflare-injected JavaScript conflicts with CSP

Severity: **Medium**

Affected service: live HTML and Content Security Policy

Cloudflare injects an inline JavaScript Detection bootstrap that loads `/cdn-cgi/challenge-platform/scripts/jsd/main.js`. Its content hash changes and is not authorized by the page CSP. The main application inline script hash is authorized. This finding is separate from WEB-01: the crypto implementation script itself is permitted.

Cloudflare documents that JavaScript Detection injects this script and that sites using nonce-based CSP must allow it through a nonce. The observed dynamic block can reduce bot-signal coverage and produces console policy errors.

There are two safe correction paths:

1. If no WAF rule depends on JavaScript Detection, prevent HTML transformation. Set this exact header for HTML in both static and Worker paths:

```http
Cache-Control: public, max-age=0, must-revalidate, no-transform
```

Worker insertion after `const headers = new Headers(response.headers);`:

```javascript
const contentType = headers.get("Content-Type") || "";
if (contentType.toLowerCase().includes("text/html")) {
  headers.set("Cache-Control", "public, max-age=0, must-revalidate, no-transform");
}
```

2. If WAF rules require JavaScript Detection, retain injection and migrate inline application scripts to a per-response cryptographic nonce. Put the same unpredictable nonce in every allowed script tag and in `script-src 'nonce-<value>'`. Do not add `unsafe-inline` and do not pin the changing injected hash.

The correct branch depends on live WAF configuration, which was outside read-only public visibility. Verification for either branch: load the page twice in a clean browser, confirm no CSP refusal, confirm the application initializes, and verify the intended WAF signal behavior in the Cloudflare dashboard.

### AND-01: Android debug native engine matrix is incomplete

Severity: **Medium**

Affected targets: phone and TV debug unit variants

All three tested ABIs have profile and release engine payloads, but no debug payload. Release file sizes observed were 10,518,976 bytes for ARM64, 10,579,996 bytes for ARMv7, and 11,407,776 bytes for x86-64. The test oracle requires debug, profile, and release sameness under a reviewed candidate.

Correction: run the native producer for the frozen source revision and publish all variants through the repository's manifest-verified path. Do not copy release files into debug by hand unless the producer receipt explicitly defines those bytes as identical.

Expected verification is the same pair of Gradle commands under REL-01, with all 592 tests passing in each variant.

## 5. Platform and subsystem assessment

### 5.1 Windows x86 and ARM64

Static result: no new named-pipe or process-lifetime vulnerability was confirmed.

The privileged service is a separate build with `WINS_TUNNEL_SERVICE_CORE=1` (`windows/runner/CMakeLists.txt:68-93`). The service pipe in `windows/runner/windows_tunnel_service_main.cpp:718-755` uses a protected DACL for SYSTEM, Administrators, and interactive-user read/write, rejects remote clients, requests first-instance ownership, uses message mode, and limits the server to one instance. Before privileged start or stop handling, it proves the active console session, exact `wins_vpn.exe` image path, and an impersonated non-service user token (`:164-239`). Elevated administrator access is status-only.

Child launches use suspended creation, Job Object assignment, and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (`windows_tunnel_backend.cpp:338-380`, `:1952-1958`). Failure to assign a suspended child terminates it before handles are released. Bounded reads prevent a partial-header client from holding the only pipe indefinitely.

The client PID crosses the API as `ULONG` and is narrowed to `DWORD`, matching Windows process-ID width. No pointer value is serialized across the pipe, so no WOW64 versus native ARM64 pointer-size defect was found.

Dynamic limits: the C++ runner was not compiled or executed on Windows x86 or ARM64. Named-pipe DACL behavior, SCM identity, child crash containment, and handle counts remain target-runtime unverified. WIN-01 blocks release first.

### 5.2 Linux x86 and ARM64

Static result: no new custody, signal, or file-descriptor leak was confirmed.

`RunArgv` creates a process group, sets output nonblocking, uses a monotonic 15-second deadline, polls with `waitpid(..., WNOHANG)`, handles interruption, sends SIGTERM to the group, then SIGKILL if required (`linux/runner/linux_tunnel_backend.cc:351-382` and adjacent teardown). Root-path validation walks path components without following untrusted links, requires root custody and non-writability, and checks pinned material before privileged invocation (`:1460-1547`). Shutdown reaches `ShutdownLinuxTunnelBackend()` through application shutdown and SIGINT or SIGTERM handlers. Disconnect also calls `StopTunnelPowerProtection()`.

The firewall scripts use owned `WINVPN-*` chains. No broad host-chain flush was found in the audited paths. Power protection no longer uses an unbounded sleeper. Helper paths are resolved before invocation. The recovery unit at `linux/packaging/winsvpn-recover.service:18-41` is a bounded oneshot with a 30-second timeout, an explicit network capability set, `NoNewPrivileges`, strict filesystem protection, namespace and address-family restrictions, `MemoryDenyWriteExecute`, and a system-service syscall filter. It is intentionally not enabled by package installation.

Dynamic checks: tunnel shutdown, Round 7, engine pipe saturation, and architecture release tests passed. The pipe test completed four five-second saturated-writer cases. Nine `RunArgv` tests skipped because this host is macOS. `bash -n` passed for the audited shell scripts. Linux x86, Linux ARM64, eBPF attachment, systemd sandbox enforcement, real signal delivery, and socket/FD counts remain unverified on target kernels.

### 5.3 macOS x86 and ARM64

Static result: ruled route posture remains intact.

The single macOS authority is `WinsMacRoutePosture.enforceRoutes = true` in `macos/Runner/RouteAudit.swift:108`. `MainFlutterWindow.swift:1927-1928` applies it with `excludeLocalNetworks = true`. The route audit and configuration readback retain a narrow outer-carrier exclusion so the VPN does not capture its own carrier socket. The hardened runtime and network-extension configuration passed repository contract checks.

`tools/verify_rulings.sh` passed all 59 locked invariants and all six Apple route checks. Apple method-channel verification passed seven checks. The macOS build failure is the authority gate described in REL-01, not a compiler error.

Dynamic limits: no signed macOS app was launched. Intel, Apple Silicon, Network Extension IPC under termination, route-socket churn, wake/sleep, hardened runtime validation, and memory ceilings remain device unverified.

### 5.4 Android phone and Android TV

Static result: required TV and VPN-service controls are present.

The TV overlay declares `android.software.leanback` and `android.hardware.touchscreen` with `required="false"`, sets a banner, and includes both `LAUNCHER` and `LEANBACK_LAUNCHER` (`android/app/src/tv/AndroidManifest.xml:26-51`). The phone manifest keeps `VpnTunnelService` non-exported, binds it to `BIND_VPN_SERVICE`, and declares the API 34 special-use foreground type (`android/app/src/main/AndroidManifest.xml:208-220`).

AmneziaWG socket protection fails closed when any valid descriptor is refused or when no valid carrier descriptor is available (`AwgSocketProtection.kt:30-63`). Xray carrier mode returns `START_NOT_STICKY` before DNS, performance locks, or process launch (`VpnTunnelService.kt:1159-1166`). Split-tunnel exclusions drop the VPN app itself, tolerate only a package that disappeared, and throw on other failures (`:3959-3976`). The startup wake lock is bounded to 60 seconds and is not renewed for the full session.

The current code does still call `addDisallowedApplication` for explicit user-selected third-party packages. That is correct split-tunnel behavior. The dangerous self-exclusion path is absent.

Dynamic limits: no uninstall, APK install, launch, VPN connection, TV remote session, logcat review, Doze cycle, roaming, kill-switch cycle, or high-throughput socket-protection test was performed. The user prohibited deployment, and this audit made no app change. AND-01 and REL-01 capture the unit-suite failures.

### 5.5 iOS and tvOS

Static result: iOS route and watchdog implementations are present; tvOS is not a current shipping target.

iOS applies `enforceRoutes = true` and `excludeLocalNetworks = true` in the tunnel protocol (`ios/Runner/AppDelegate.swift:1589-1590`, with repeat guarded configuration paths). The packet provider uses a strict project ceiling of 15 MiB and samples physical footprint every second. Its timer starts at `.now()`, is lifecycle-token scoped, and cancels the tunnel with provider error 1038 on an over-ceiling or failed sample (`ios/PacketTunnel/PacketTunnelProvider.swift:1240-1305`). The watchdog and proving-ownership tests passed.

The repository ruling identifies tvOS as future post-release product scope, not a current supported binary. There is therefore no current tvOS Network Extension, D-pad, or background-wakeup implementation to certify. Website copy aligned to that scope. Any claim that tvOS is presently supported would be false.

Dynamic limits: no physical iPhone high-packet-throughput memory run was made. A one-second watchdog is code evidence, not proof that the full data path remains below 15 MiB. iOS suspend, memory-pressure, handover, and Packet Tunnel termination need signed-device evidence.

### 5.6 Chrome, Firefox, Edge, and Safari extensions

Static result: no new service-worker recovery, permission, PAC, or origin-binding defect was confirmed.

Chrome and Edge use Manifest V3 service workers. Firefox uses an event-page background model. Safari uses a nonpersistent background page. Event listeners are registered at module load, while initialization rejection is recorded for retry. Chrome, Edge, and Firefox declare both `webRequest` and `webRequestAuthProvider`; Firefox keeps all-host access optional. Safari exposes no unsupported proxy-auth surface. Firefox privacy protection verifies `levelOfControl === "controlled_by_this_extension"` and throws when WebRTC or network-prediction posture cannot be enforced. The generated PAC performs no DNS lookup, never appends a direct fallback for in-scope hosts, returns the proxy from its exception handler, and uses Chromium `mandatory: true`; proxy application is read back before acceptance. Chrome-family native messaging derives an exact extension origin; the native host fails closed when allowed origins are empty or do not contain the caller.

Current package checks passed: Chrome zip has 26 members and 93,385 bytes; Firefox zip has 26 members and 93,468 bytes. Canonical Chrome and Gecko identifiers and Chrome, Edge, and Firefox native-host manifest origins passed. The focused cross-store adapter and packaging suite passed 164 tests. The complete `extension/tools` suite passed 568 tests in 518.44 seconds.

Dynamic limits: installation into clean Chrome, Firefox, Edge, and Safari profiles was not performed. Browser restart, service-worker termination, proxy restoration, PAC failure, proxy authentication, native-host launch, and extension-update continuity remain browser-runtime unverified.

### 5.7 Control plane and data planes

Static result: recent transaction and concurrency remediations are present. CP-01 is the new confirmed mismatch.

The control-plane generator configures SQLite WAL, NORMAL synchronous mode, a ten-second busy timeout, foreign keys, explicit connection closure, and `BEGIN IMMEDIATE` for authority-sensitive mutation paths. Remote payment and subscription calls are moved away from the event loop, with database connections closed while remote HTTP runs. Expiration parsing is timezone aware and fails closed. Activation secrets use a single-use transactional path; delivery uses an authenticated encrypted outbox with retry. Durable peer-revocation and Winn v3 registry refresh queues are transaction-coupled.

Owned firewall chains use the `WINVPN-*` namespace. The examined scripts did not flush host-wide firewall state. Legacy SPA cleanup uses bounded transient units.

The Winn v3 gateway refreshes authority, bounds registry reads to 1 MiB, verifies session key authority during lookup, checks expiration in packet handling, evicts stale conflicting sessions, and performs direct O(1) key lookup. The complete Go suite passed across 106 packages.

Server verification: Round 8 through Round 12 pytest cases passed. Round 9 alone reported nine tests and ten subtests. The descriptor harness passed 117 of 117 and the deletion harness passed 20 of 20. Running those two standalone programs under pytest produces fixture errors because they are not pytest suites; those harness errors are not product failures.

Dynamic limits: no live Kansas hub, node, SQLite contention, PayPal, BTCPay, Monero, SMTP, systemd, or iptables operation was executed. Actual replay behavior, provider signatures, provider latency, multi-writer contention, outbox recovery after power loss, node rollback, and firewall coexistence require an isolated target environment.

### 5.8 Shared Dart and three protocols

Static and test result: no new downgrade or dispatch defect was confirmed.

Winn Protocol v3 remains the primary authorized path. Winn v1 uses AmneziaWG first and only uses Xray or VLESS-WS under the explicit runtime fallback grant. Android reports Xray unsupported and refuses its carrier before network work. Generation tokens, selection generations, failed-v3-node binding, and exact target or leg binding prevent a stale or unrelated fallback from starting. Unknown or unproved states fail closed.

`flutter analyze --no-pub` reported no issues. `flutter test --no-pub --concurrency=1 --reporter compact` completed with 1,926 passing tests and three intentional skips. The supplied known context said two skips and 1,927 tests in later rounds; current bytes prove three skips and 1,926 passes.

Dynamic limits: no real AWG handshake failure was induced, no Xray fallback was run, and no multi-device generation race was exercised against a live control plane. Protocol interoperability, carrier censorship behavior, and downgrade resistance remain unverified outside tests.

### 5.9 Website, DNS, payments, and provisioning

Live result: HTTPS and public configuration were available, but deployed bytes and headers lag the assigned snapshot.

Observed public DNS: IPv4 `172.67.185.162`, `104.21.36.50`; IPv6 `2606:4700:3037::ac43:b9a2`, `2606:4700:3031::6815:2432`. No public CAA result was returned. The certificate named `winsvpn.org`, was issued by Google Trust Services WE1, and was valid from 2026-09-01 through 2026-11-30. Root returned HTTP/2 200 through Cloudflare with HSTS.

The fetched live HTML hash was `4f20e75621f80a75b1cb068d439ebcef87c10e66ad74327f85184f1739e561ea`; local `web/index.html` was `a79671f5ad0240675a13745407d96b35aa9f3d163565dbfc09ba08f90aa47672`. Cloudflare injection can change the live hash, so source-level WEB-01 evidence and policy headers are the stronger drift proof.

The public crypto-config response used `Cache-Control: public, max-age=300`. Root HTML uses HSTS and a restrictive CSP. Public DNS cannot reveal private Cloudflare dashboard records, Worker route definitions, rate-limiter bindings, cache rules, or WAF dependencies.

No payment capture, secret generation, lifetime expiration, account provision, or transactional email was triggered. Those pipeline claims are static and test-backed only.

### 5.10 Performance and memory

Measured on the audit host:

| Benchmark | Result | Allocation |
|---|---:|---:|
| H2 frame codec | 30.58 ns/op | 50 B/op, 2 allocs/op |
| Relay, batch 1 | 331.7 ns/op | 0 B/op, 0 allocs/op |
| Relay, batch 64 | 319.6 ns/op | 0 B/op, 0 allocs/op |
| Gateway dispatch miss | 6.477 ns/op | 0 B/op, 0 allocs/op |
| Gateway dispatch hit | 912.7 ns/op | 108 B/op, 1 alloc/op |

The relay and miss paths are already allocation free. H2 frame encoding and gateway-hit dispatch merit a profile under representative concurrency. They are not proven field bottlenecks. The H3 client windows are bounded at 128 KiB initial and 512 KiB maximum per stream, plus 256 KiB initial and 2 MiB maximum per connection. UDP buffer code reads back the kernel-granted size. MTU probing uses one datagram, and HTTP/3 admission considers handshake capacity.

Optimization rule: capture CPU, heap, block, and mutex profiles under actual packet distributions before changing ownership or buffer reuse. A suitable gate is zero allocations for gateway dispatch hits and at most one allocation for H2 framing, provided race tests and payload ownership checks pass. Do not pool secret-bearing buffers without deterministic zeroing and ownership proof.

No battery drain, mobile radio wakeups, thermal behavior, real socket-buffer grant, MTU black-hole recovery, AES or ChaCha hardware acceleration, or end-to-end throughput was measured on target devices.

## 6. Low findings and hardening

### OPS-01: Shell robustness warnings

ShellCheck identified a fragile `for candidate in $(ls ...)` pattern near control-plane line 5549 and a directory creation that combines `mkdir -p` with a mode expectation flagged by SC2174. Several additional unused-variable, array-inference, literal-regex, and trap warnings appear to be analyzer limitations or low-risk cleanup.

Replace command-substitution iteration with a null-safe or glob-based loop appropriate to the exact filename contract. Set directory mode explicitly after creation:

```sh
install -d -m 0750 -- "$target_directory"
```

Do not apply a generic rewrite until the expected empty-directory and whitespace behavior is covered by a shell test. Verification:

```sh
shellcheck server/wins_control_plane_setup_ONETOUCH.sh server/wins_data_plane_setup_ONETOUCH.sh tools/build_linux_release.sh
bash -n server/wins_control_plane_setup_ONETOUCH.sh server/wins_data_plane_setup_ONETOUCH.sh tools/build_linux_release.sh
```

Expected: syntax exits 0 and the addressed warnings disappear without new warnings in modified regions.

### PERF-01: Allocation candidates

The measured allocation counts are real, but causality and production impact are not established. Treat them as Low optimization candidates. Required verification after any optimization:

```sh
cd winn_protocol_experimental
go test -race ./...
go test ./... -run '^$' -bench 'BenchmarkH2FrameCodec|BenchmarkRelay|BenchmarkDispatch' -benchmem -count 10
```

Expected: race detector passes; behavior tests remain green; allocation targets improve without a statistically significant latency regression.

## 7. Verification ledger

| Command or probe | Result |
|---|---|
| `git rev-parse HEAD` | `89be66e75747c0b493583ca9c9efd7787c88a974` |
| `git fsck --full --no-reflogs` | FAIL, eleven missing staged blobs |
| `tools/verify_rulings.sh` | PASS, 59 invariants and six Apple route checks |
| `flutter analyze --no-pub` | PASS, no issues |
| `flutter test --no-pub --concurrency=1 --reporter compact` | PASS, 1,926 pass and three skip |
| `go test ./...` in `winn_protocol_experimental` | PASS, 106 packages |
| server Round 8 through Round 12 pytest files | PASS |
| descriptor hub standalone | PASS, 117 of 117 |
| deletion hub standalone | PASS, 20 of 20 |
| `tools/website_security_audit.py` | PASS, 56 pass, one explicit skip, zero fail |
| Apple watchdog test | PASS, six checks |
| Apple proving ownership test | PASS, four concurrent stop checks |
| Apple standalone v3 wiring | PASS, one check |
| Apple method-channel contract | PASS, seven checks |
| macOS release build | FAIL CLOSED, missing external artifact authority |
| Android phone debug unit tests | FAIL, 589 of 592 pass, three freshness failures |
| Android TV debug unit tests | FAIL, 589 of 592 pass, same three failures |
| Windows readiness | PASS, eight checks |
| Windows AWG migration | PASS, ten checks, stale artifacts correctly refused |
| Windows ARM64 inner gate | PASS, fourteen checks |
| Chrome package gate | PASS, 26 members |
| Firefox package gate | PASS, 26 members |
| extension adapter and packaging pytest | PASS, 164 tests |
| complete `extension/tools` pytest | PASS, 568 tests in 518.44 seconds |
| Linux shutdown and Round 7 tests | PASS |
| Linux engine-pipe test | PASS, four saturation cases |
| Linux architecture release test | PASS, thirteen checks |
| Linux `RunArgv` target test | SKIP, nine cases require Linux |
| audited shell `bash -n` | PASS |
| ShellCheck | WARN, OPS-01 |
| live DNS, TLS, GET, headers | PASS as read-only probes, findings WEB-01 through WEB-03 remain |

## 8. Required release sequence

1. Restore all eleven exact Git objects. Prove `git fsck`, staged diff, unstaged diff, and whitespace checks.
2. Apply CP-01 and add its positive and negative route tests.
3. Preserve the current local WEB-01 and WEB-02 fixes, resolve WEB-03 based on actual WAF use, and rerun the website audit.
4. Obtain reviewed Windows and cross-platform native engine candidates with exact signed identities and producer receipts. Do not weaken gates.
5. Rerun the complete static and dynamic suite from a clean, object-complete checkout.
6. Perform Windows x86 and ARM64 tests, Linux x86 and ARM64 tests, connected Android phone and TV tests, and signed iOS and macOS tests. Capture route, memory, FD, handle, crash, wake, and throughput evidence.
7. Only after local candidate acceptance, deploy the website through the authorized path. Confirm live HTML behavior and headers using GET-only checks before any synthetic transaction in a designated test environment.

Release success requires every High finding closed and every mandatory target gate proved. Passing shared tests alone is not cross-platform release authority.

## 9. External technical references

* [Microsoft Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
* [Android uses-feature manifest element](https://developer.android.com/guide/topics/manifest/uses-feature-element)
* [Create and run a TV app](https://developer.android.com/training/tv/get-started/create)
* [Android VpnService protect](https://developer.android.com/reference/android/net/VpnService)
* [Android foreground service type requirements](https://developer.android.com/about/versions/14/changes/fgs-types-required)
* [Apple Network Extension enforceRoutes](https://developer.apple.com/documentation/networkextension/nevpnprotocol/enforceroutes?changes=l___2)
* [Apple Network Extension includeAllNetworks](https://developer.apple.com/documentation/networkextension/nepackettunnelnetworksettings/includeallnetworks)
* [Chrome extension service worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
* [Chrome native messaging security model](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging?authuser=2)
* [Cloudflare JavaScript Detections](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/)

## 10. Final statement

The assigned snapshot contains substantial fail-closed engineering and broad automated coverage. It is not releasable. The live paid-crypto path is materially behind the audited local correction, Git custody is incomplete, native producer authority is unresolved, and one server-side grammar mismatch can disable the minimum-version control for fresh clients. Those facts remain even though the shared Flutter, Go, server, website, Windows-oracle, Linux-hosted, Apple-contract, and extension-package checks are mostly green.

