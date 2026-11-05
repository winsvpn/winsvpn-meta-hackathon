# Codex Deep Audit Report: Daybreak Blue

- Model Identifier: `gpt-daybreak-blue-latest`
- Reasoning Effort: `xhigh`
- Collected: `2026-09-13T21:36:32.547482+00:00`
- Process Exit Code: `0`
- Content Source: `lane report file (/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/daybreak/docs/evidence/codex_daybreak_blue_audit.md)`
- Usage Metadata: `{"input_tokens": 26309004, "cached_input_tokens": 25463888, "cache_write_input_tokens": 826229, "output_tokens": 67249, "reasoning_output_tokens": 22740}`

## Reasoning Trace

```
**Planning live web audit and memory inspection**
**Starting audit report generation**

**Planning code inspection at lines 345-390 and 467**

**Planning live technical documentation search**
**Sequencing web search before local commands**

**Refining search to target sqlite and systemd separately**

**Verifying Python SQLite version and repo details**

**Auditing current working tree and changes**

**Planning complete AGENTS file review**

**Planning report verification and inspection**

**Planning targeted static analysis and environment checks**

**Investigating SQLite version dependency**

**Assessing Python and SQLite versions**
**Planning static inspection of Windows targets**

**Locating named pipe server implementation**

**Planning service main installation and configuration**

**Inspecting return statement in HANDLE function**

**Requesting code lines 316-355**

**Assessing client auth vulnerability and service path risks**
**Analyzing race conditions and pipe buffer limits**

**Investigating pipe versus pipe2 usage**

**Analyzing pipe2 incompatibility on macOS**
**Inspecting embedded root path shell function**

**Identifying TOCTOU vulnerability in path validation**
**Evaluating root-owned path stability against TOCTOU**
**Assessing VPN power inhibition impact**

**Inspecting state transitions and failures**

**Starting analysis from section 4053**

**Identifying privacy leak in engine status logging**

**Requesting LinuxWinn3EngineStatusJSON data**

**Identifying Apple-specific components**

**Planning precise iOS memory watchdog inspection**

**Assessing memory limit enforcement and watchdog impact**

**Identifying plaintext logging privacy leak**
**Planning conditional debug-only logging removal**

**Assessing manifest compatibility and permissions**

**Verifying Android service Xray behavior**
**Planning APK install and log filtering**

**Planning Flutter APK build and extension inspection**

**Inspecting base manifest and PAC files**

**Adding origin parsing to main**

**Investigating origin allowlist handling**

**Diagnosing Firefox origin authentication bug**

**Updating commentary for clarity**

**Inspecting installer presence**

**Resuming installer after step 455**

**Investigating Dart sidecar and credential issues**
**Testing native message sending via subprocess**

**Inspecting enum value type**

**Inspecting package symlinks and imports**

**Verifying production source invocation**

**Identifying matching existing tabs**

**Investigating tab binding conflict**

**Planning Edge tab creation**

**Planning Playwright click action**

**Planning Escape key handling via Edge app**

**Verifying button state and interaction**
**Planning toggle interaction and state check**

**Assessing console log availability on Edge**
**Planning console access via new tab**

**Planning tab switching sequence**

**Planning DevTools access via native app**
**Testing Edge DevTools shortcut for console access**

**Accessing developer tools interface**

**Investigating inline CSP hash mismatch**

**Identifying Cloudflare challenge injection cause**
**Analyzing CSP limitations with Cloudflare injections**
**Running static grep for tvOS logs**

**Searching for tvOS target in project**

**Identifying FocusNode memory leak issues**

**Planning stateful TvActivatable fix**
**Planning Apple log inspection**

**Validating Apple logging behavior**

**Assessing SQLite version and patch status**
**Planning version verification via Ubuntu advisories**

**Planning Debian patch inspection**

**Identifying unreported SQLite 2026-09 bug**

**Planning comprehensive Linux and Windows analysis**
**Listing test scripts and audit commands**

**Locating website security audit script**

**Planning combined test execution with PTY**

**Polling session ID**

**Identifying Python version newline param impact**

**Investigating failing tests environment**

**Investigating hung native host tests**

**Adjusting test timeouts**

**Investigating host handshake hang**

**Waiting through test timeouts**

**Waiting to verify combined stop**

**Inspecting hung test subprocess**

**Diagnosing stalled stdin communication**

**Inspecting test script input handling**

**Identifying test harness hang and failures**
**Planning fast-fail test rerun**

**Testing environment store ID reset**

**Inspecting ID validation in isolated_store_env**

**Identifying test environment authority leak**
**Setting safe default owner identity env**

**Planning concise commentary updates**

**Planning parallel command execution**
**Designing safe parallel test runs**

**Checking Python versions in toolchain**

**Running Flutter full test suite**

**Locating pinned OpenSSL path**

**Checking for Homebrew OpenSSL installation**

**Running command with PATH prefix**

**Inspecting ResourceWarnings in server script**

**Investigating resource leak and source mapping**

**Tracing SQLite connection leaks in tests**
**Inspecting test harness for unclosed contexts**

**Investigating unclosed generator warning**

**Analyzing SQLite connection warnings**
**Planning Flutter run ignoring pub lock**

**Running Flutter tests**

**Identifying build script failure cause**

**Planning precise failed test rerun**

**Running isolated compact test**

**Running release build despite failing tests**

**Locating Android build script**

**Identifying Flutter version mismatch blocking release build**

**Running Go tests including untracked files**

**Planning selective race testing on critical packages**

**Inspecting native host and extension manifests**

**Planning Dart run with Python subprocess**

**Testing Firefox manifest path handling**

**Inspecting Windows service separation and WOW pointer handling**

**Planning line 690 pipe and backend process**

**Investigating Extract keys call**

**Verifying macOS packet tunnel memory usage**

**Inspecting FocusNode leaks**

**Inspecting VpnPowerControl class**

**Identifying FocusNode leak and fixing strategy**
**Planning live web analytics inspection**

**Planning static grep and automated flow**

**Correcting payment file line ranges**

**Clarifying local button logic**

**Identifying high-severity rate limiter bypass**
**Highlighting potential payment abuse risk**

**Assessing rate limiting and CSRF protections**

**Assessing provider call limits at hub**

**Requesting exact payment limit**

**Identifying async server and SQLite issues**

**Locating pubspec for build and test**

**Running full build and Dart tests**

**Evaluating test strategy for build**

**Verifying public ID exposure safety**

**Inspecting SQLite versions locally and officially**

**Planning live search for Ubuntu packages**

**Planning live header and crypto inspection**
**Emphasizing use of exact commands**

**Planning cleanup of /tmp files**

**Switching file deletion method to unlink**

**Diagnosing CSP hash differences between live and local**
**Computing and comparing inline script hashes**

**Comparing live and local app scripts**

**Inspecting live script for crypto functions**

**Preparing commentary update on compaction**

**Planning precise method inspection**

**Planning exact patch report**

**Planning precise report extraction and hashing**
**Designing live data extraction pipeline**

**Extracting live script functions and hashes**

**Verifying script hash changes**

**Planning comprehensive defect report**

**Verifying build counts consistency**

**Confirming no tvOS target and inspecting toolchain pin**

**Correcting JSON key access**

**Checking availability of cppcheck tool**

**Planning shellcheck verification**

**Investigating local vs global array conflict**

**Verifying Bash local variable behavior**
**Planning targeted Flutter test run**

**Inspecting function lines for test patch**

**Planning secure atomic write for sidecar IDs**
**Adding install-allowlist command with atomic write**

**Planning build script fixes for sidecar removal**

**Planning consistent build and packaging strategy**
**Designing multi-platform manifest integration**
**Verifying Dart compile define syntax**

**Planning build script reordering**
**Drafting exact patch diffs for fixes**

**Inspecting store_ids.json content**

**Noting external identity file access**
**Planning allowed origins sidecar file**
**Addressing sidecar file overwrites during install**

**Planning cross-platform build wrapper design**
**Identifying native host argument spoofing risk**
**Analyzing native host trust boundaries**

**Inspecting script injection discrepancies**

**Planning exact code diff inclusion**
**Verifying Firefox argument order across platforms**

**Planning native messaging page**

**Preparing cache-control directives**

**Adding security headers**

**Planning cache-control no-transform patch**
**Verifying no-transform effectiveness against Cloudflare injection**

**Planning script nonce injection in HTML**
**Designing CSP nonce and header rewrite strategy**
**Finalizing nonce implementation recommendations**

**Planning nonce-based CSP injection**
**Removing invalid response headers**

**Planning CSP fix with performance tradeoff**
**Outlining CSP fix report with dashboard steps**
**Compiling severity matrix with nine findings**

**Determining release no-go due to high severity issues**
**Implementing platform caller validation in Dart**

**Designing Chrome caller normalization function**
**Refactoring PowerShell build script parameters**
**Enabling Apple build ID resolution via Python**

**Planning runtime sidecar with allowlist file**
**Detailing sidecar installation and rollback strategy**
**Choosing compile-time constants over sidecar**

**Implementing SQLite version check**
**Removing redundant KeyboardListener wrappers**

**Verifying engine status counter keys**

**Identifying status.go keys for v3 engine**

**Planning socket buffer and benchmarking report**

**Planning patch application and report formatting**
**Drafting detailed patch code snippets**
**Noting forward declaration for ExtractJsonCounters**

**Adding ExtractJsonCounters prototype and call**
**Implementing OwnedKeyboardListener wrapper and replacement**

**Verifying Android build script usage**
**Recommending immediate no-transform fix**
**Summarizing Flutter test results**

**Clarifying package count and build artifact handling**
**Reviewing environment qualification and test outcomes**

**Verifying report content and formatting**

**Verifying code compilation details and namespace placement**
**Adjusting verification to hash app script only**
**Reviewing macOS watchdog and audit tool details**

**Planning report content and verification steps**

**Verifying test and script extraction accuracy**
**Planning detailed report inspection and contradiction searches**

**Replacing ellipsis with newline string**

**Verifying completeness of setup function diff**
**Adding full setupCryptoPayments function**

**Adding build arrays DB01**

**Inspecting code changes around deletion and addition**

**Verifying PowerShell array splatting support**
**Adding Ubuntu SQLite package reference**
**Testing Dart format with stdin input**

**Planning code formatting via stdin**
**Validating snippets using exec heredocs**

**Exploring Dart syntax validation via stdin**

**Validating compile-time constants usage**
**Checking report generation and code changes**

**Drafting final concise report summary**
**Summarizing top findings and citation details**
```

## Audit Findings & Exact Fix Implementations

# WinsVPN Ecosystem Independent Audit

Author: Daybreak Blue  
Audit date: 2026-09-13  
Workspace: `/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/daybreak`  
Reviewed HEAD: `89be66e75747c0b493583ca9c9efd7787c88a974`  
Mode: Static review, local dynamic tests, offline builds, and read-only live website probes  
Production tree: Not accessed  

## 1. Executive verdict

**NO-GO. Do not produce, upload, or deploy a release from this working tree.**

No Critical vulnerability was verified. Four High defects were verified:

1. The browser native host reads `allowed_origins.txt`, but no production installer or release producer creates that file. Chrome and Edge therefore fail closed when asking for the local proxy credential.
2. The same host does not parse Firefox's documented native messaging argument shape. Firefox supplies the native manifest path followed by the raw add-on ID. The host only accepts URL-shaped arguments.
3. Linux logs the complete Winn v3 engine status document on a promotion refusal. That document contains the customer gateway endpoint, local endpoint, and session ID.
4. The live site is serving older crypto checkout code than this workspace. If `/api/site/crypto-config` fails, a paid-plan coin selector falls back to the static donation modal. Funds sent through that path do not enter the automated account provisioning transaction.

Five Medium issues were also verified: an affected SQLite WAL runtime can be installed on Ubuntu 24.04, Flutter TV focus nodes are allocated during `build()`, Linux blocks sleep and idle for the entire tunnel session, current release evidence fails its own tracked-test invariant, and Cloudflare injects scripts that the live CSP blocks. One Low test-harness defect can hide native-host regressions or hang the suite.

The strongest repaired areas held up under review. Route rulings passed. Go tests and selected race tests passed. Flutter analysis passed. Windows lifecycle oracles passed. Linux teardown oracles passed. Apple posture and memory-watchdog oracles passed under the pinned Python runtime. Extension archives rebuilt deterministically. Server Round 9 and Round 10 tests passed. Those results do not overcome the High defects, the failed full Flutter suite, or missing device evidence.

### Severity table

| ID | Severity | Area | Verified result |
|---|---|---|---|
| DB-01 | High | Browser native host | Production credential gate has an empty allowlist after install |
| DB-02 | High | Firefox native messaging | Raw Firefox add-on ID is ignored |
| DB-03 | High | Linux privacy | Full Winn v3 status, including endpoints and session ID, is logged |
| DB-04 | High | Live crypto payments | Live failure path opens donation modal instead of failing closed |
| DB-05 | Medium | Control plane SQLite | Ubuntu 24.04 can supply an upstream WAL-reset affected SQLite |
| DB-06 | Medium | Android TV and shared Flutter UI | `FocusNode` objects are created repeatedly in `build()` |
| DB-07 | Medium | Linux battery and suspend | Active tunnel blocks both sleep and idle indefinitely |
| DB-08 | Medium | Release state | Full Flutter suite fails because three Go regression tests are untracked |
| DB-09 | Medium | Website CSP | Cloudflare Web Analytics and JSD injections are blocked by CSP |
| DB-10 | Low | Native-host tests | Environment isolation is incomplete and one test waits forever on stdin |

## 2. Scope, state, and method

The repository was already dirty before this report was written. At the final state check it had 148 tracked changes and 45 untracked paths. The audit did not reset or discard them. Test and packaging commands may have refreshed generated build outputs inside this workspace.

The following target classes were inspected:

- Windows x86 and ARM64 runner, named pipe, service boundary, process and Job Object lifetime.
- Linux x86 and ARM64 runner, privileged path custody, subprocess lifetime, signal teardown, firewall and systemd units.
- macOS x86 and ARM64 app and packet tunnel posture, route exclusion, entitlements, and memory watchdog.
- Android phone and Android TV manifests, socket protection, split tunnel, foreground service, wake lock, and TV focus behavior.
- iOS packet tunnel posture and strict memory watchdog. The repository contains no native tvOS application target.
- Chrome, Edge, Firefox, and Safari extension manifests, lifecycle, PAC, permissions, and native host boundary.
- Control-plane and data-plane setup scripts, FastAPI routes, SQLite, firewall chains, tokens, activation, payment, revocation, and email outbox.
- Winn v3, Winn v1 AWG-first fallback, XRay fallback, generation authorization, and anti-downgrade tests.
- Website Worker, headers, DNS, TLS, CSP, rate limiting, payments, and account provisioning.
- Performance posture: buffers, MTU, packet copies, process lifetime, focus allocation, wake and sleep behavior.

Live testing was read-only. It used GET, HEAD, DNS, TLS, and an interactive browser. No payment button that creates an invoice was clicked. No account, payment order, email, or live state mutation was created.

Primary specifications were checked live on 2026-09-13:

- [Microsoft named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Android VpnService](https://developer.android.com/reference/android/net/VpnService)
- [Android VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder)
- [Apple enforceRoutes](https://developer.apple.com/documentation/networkextension/nevpnprotocol/enforceroutes)
- [Chrome extension service worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
- [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [Firefox native messaging arguments](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging)
- [Cloudflare JavaScript Detections and CSP](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/)
- [Cloudflare Web Analytics CSP behavior](https://developers.cloudflare.com/web-analytics/faq/)
- [SQLite WAL-reset defect notice](https://www.sqlite.org/wal.html)
- [Flutter FocusNode lifecycle](https://api.flutter.dev/flutter/widgets/FocusNode-class.html)

## 3. Command evidence

### Passed

| Command | Result |
|---|---|
| `sh tools/verify_rulings.sh` | PASS, all 59 invariants and all 6 Apple rulings |
| `python3 tools/verify_apple_method_channel_contract.py` | PASS |
| `python3 tools/test_apple_standalone_v3_wiring.py` | PASS, 7 tests |
| Pinned Python 3.14 iOS memory watchdog test | PASS, 6 tests |
| Linux shutdown, engine-pipe, and Round 7 focused tests | PASS |
| Windows lifecycle oracle | PASS, 11 tests |
| Windows single-instance oracle | PASS, 4 tests |
| Windows v3 packaging oracle | PASS, 18 tests |
| Chromium extension identity tests | PASS, 22 tests |
| Extension controller tests | PASS, 19 tests |
| Firefox identity tests | PASS, 41 tests |
| `python3 extension/build.py chrome edge firefox safari` | PASS, all four bundles built and verified |
| `python3 extension/tools/test_verify_firefox.py` | PASS, 22 tests |
| `node --check web/_worker.js` | PASS |
| Website security audit | PASS, 56 checks, one explicitly absent-source skip |
| Server Round 9 suite | PASS, 9 tests |
| Server Round 10 suite | PASS, 10 tests |
| `bash -n` on both one-touch server scripts | PASS |
| `flutter analyze --no-pub` | PASS, no issues |
| `go test ./...` | PASS for every enumerated package |
| `go test -race ./cmd/winn3-gateway ./datapath ./internal/carrier ./winn3/...` | PASS |
| Native host documented direct Dart identity test | PASS |

The server tests emitted Python 3.14 `ResourceWarning` messages for SQLite connections allocated by generated `get_db` code during module and test teardown. Every reviewed production `with get_db()` or `closing()` path was not proven to leak. This is an observability warning, not promoted to a vulnerability without a production lifetime reproducer.

### Failed or unavailable

| Command or gate | Result |
|---|---|
| Full `flutter test --no-pub` | FAIL, 1,923 passed, 4 skipped, 1 failed |
| `flutter test --no-pub test/tracked_reference_integrity_test.dart` | FAIL, three untracked Go test files |
| System Python 3.9 iOS memory test | 1 pass, 5 harness errors because `Path.write_text(newline="\n")` needs the pinned newer Python |
| Linux RunArgv runtime tests | 9 skipped because this host is macOS |
| `shellcheck -x` on three large release or server scripts | Exit 1 from warnings and informational findings, no shell parse failure |
| Raw `flutter build apk --release --no-pub` | Correctly refused because release obfuscation and split debug information were absent |
| Authorized Android release producer | Blocked: repository requires Flutter 3.47.1 at `6655482ec06e547f90abf8ae7590466f4415978d`; installed Flutter is 3.44.6 at `ee80f08bbf` |
| Android phone install and launch | UNVERIFIED, no `build/app/outputs/flutter-apk/app-release.apk` exists |
| Windows x86 or ARM64 execution | UNVERIFIED on this macOS host |
| Linux x86 or ARM64 execution | UNVERIFIED on this macOS host |
| Signed Apple device tunnel and sustained 15 MiB measurement | UNVERIFIED |
| Android TV physical remote test | UNVERIFIED |
| Live payment, account, lifetime expiry, or transactional email | UNVERIFIED by policy, no state-changing probe was made |

## 4. Verified findings and exact remediations

### DB-01 High: native host allowlist is never provisioned

**Evidence**

`tools/native_messaging/host/bin/wins_bridge_host.dart:456-485` reads `allowed_origins.txt` beside the executable. If absent, it returns an empty set. `_originAuthorized` at lines 164-165 requires a nonempty exact match. Repository-wide search found no production writer for this file. `tools/native_messaging/install_native_host.sh:433-610` installs the executable and per-browser manifest only. The Windows producer stages the executable and three manifests only.

A framed request using the current Chrome identity returned:

```text
{"v":1,"id":"audit","type":"error","ok":false,"error":"app_not_running"}
native-host refused: caller origin chrome-extension://lnehjdblendkagjbmdclepjalahdhbbn/ is not in the allowed-origins set
```

**Root cause**

The fail-closed origin gate was added, but its deployment dependency was left as a comment. Manifest tests validate what the browser may launch. They do not validate the host's separate runtime allowlist.

**Exact production fix**

Remove the mutable, missing sidecar dependency. Compile the three owner-recorded callers into the native host. Add this code near the imports in `wins_bridge_host.dart`:

```dart
const String kChromeNativeCaller = String.fromEnvironment(
  'WINSVPN_CHROME_NATIVE_CALLER',
);
const String kEdgeNativeCaller = String.fromEnvironment(
  'WINSVPN_EDGE_NATIVE_CALLER',
);
const String kFirefoxNativeCaller = String.fromEnvironment(
  'WINSVPN_FIREFOX_NATIVE_CALLER',
);

Set<String> compiledNativeCallers() {
  final callers = <String>{
    kChromeNativeCaller,
    kEdgeNativeCaller,
    kFirefoxNativeCaller,
  };
  if (callers.length != 3 || callers.any((caller) => caller.isEmpty)) {
    return const <String>{};
  }
  return Set<String>.unmodifiable(callers);
}
```

Replace the sidecar call with:

```dart
final Set<String> origins = compiledNativeCallers();
```

Delete `readAllowedOriginsFromManifestDirectory()` completely. Add these exact options to every `dart compile exe` invocation in `build_native_host.sh` and `build_native_host.ps1`, including both universal macOS slices:

```text
--define=WINSVPN_CHROME_NATIVE_CALLER=chrome-extension://lnehjdblendkagjbmdclepjalahdhbbn/
--define=WINSVPN_EDGE_NATIVE_CALLER=chrome-extension://glgihadopbjoandhoihghddecoibcldf/
--define=WINSVPN_FIREFOX_NATIVE_CALLER=companion@winsvpn.org
```

For Bash, define and expand the arguments as an array so URL punctuation is never re-parsed:

```bash
NATIVE_CALLER_DEFINES=(
  '--define=WINSVPN_CHROME_NATIVE_CALLER=chrome-extension://lnehjdblendkagjbmdclepjalahdhbbn/'
  '--define=WINSVPN_EDGE_NATIVE_CALLER=chrome-extension://glgihadopbjoandhoihghddecoibcldf/'
  '--define=WINSVPN_FIREFOX_NATIVE_CALLER=companion@winsvpn.org'
)

"${DART_BIN}" compile exe "${NATIVE_CALLER_DEFINES[@]}" \
  bin/wins_bridge_host.dart -o "${TEMPORARY}"
```

For PowerShell, pass an array directly to the Dart process:

```powershell
$NativeCallerDefines = @(
    '--define=WINSVPN_CHROME_NATIVE_CALLER=chrome-extension://lnehjdblendkagjbmdclepjalahdhbbn/',
    '--define=WINSVPN_EDGE_NATIVE_CALLER=chrome-extension://glgihadopbjoandhoihghddecoibcldf/',
    '--define=WINSVPN_FIREFOX_NATIVE_CALLER=companion@winsvpn.org'
)
& $DartBin compile exe @NativeCallerDefines bin/wins_bridge_host.dart -o $temporary
if ($LASTEXITCODE -ne 0) {
    throw 'dart compile exe failed for native host.'
}
```

The release producers must obtain those public IDs through `native_host_layout.py recorded-id`, compare them to the owner identity receipt, and pass them to the builder. A missing ID must stop compilation. Do not introduce a default ID.

**Verification**

```bash
rg -n 'allowed_origins\.txt|readAllowedOriginsFromManifestDirectory' tools/native_messaging
python3 tools/native_messaging/test_native_host_registration.py
python3 extension/build.py chrome edge firefox safari
```

Expected: the first command finds no shipping dependency, registration tests finish without a hang, all bundle checks pass, a compiled host invoked with each exact browser argument reaches the app-state gate instead of the origin-allowlist refusal, and a one-character caller mutation remains refused.

### DB-02 High: Firefox caller argument is not recognized

**Evidence**

Firefox documents two arguments: the complete native manifest path and the raw add-on ID. The current parser at `wins_bridge_host.dart:442-454` accepts only `chrome-extension://` and `moz-extension://` strings. This invocation matches Firefox's documented shape:

```text
/Library/Application Support/Mozilla/NativeMessagingHosts/org.winsvpn.bridge.json
companion@winsvpn.org
```

The framed request returned `app_not_running`, and stderr identified the caller as `(none; direct execution)`.

**Root cause**

The implementation copied Chrome's origin model into the Firefox path. Firefox authorizes the raw add-on ID in `allowed_extensions` and passes that ID without a URL scheme.

**Exact production fix**

Add the following complete parser and use it in place of the loop at lines 447-454:

```dart
bool _isAbsoluteFirefoxManifest(String value) {
  final normalized = value.replaceAll('\\', '/');
  final isAbsolute = Platform.isWindows
      ? RegExp(r'^(?:[A-Za-z]:/|//)').hasMatch(normalized)
      : normalized.startsWith('/');
  return isAbsolute &&
      normalized.endsWith('/org.winsvpn.bridge.json');
}

String? browserNativeCaller(List<String> arguments) {
  for (final argument in arguments) {
    final uri = Uri.tryParse(argument);
    if (uri == null || uri.scheme != 'chrome-extension') continue;
    if (!RegExp(r'^[a-p]{32}$').hasMatch(uri.host)) continue;
    if (uri.hasQuery || uri.hasFragment) continue;
    if (uri.path.isNotEmpty && uri.path != '/') continue;
    return 'chrome-extension://${uri.host}/';
  }
  if (arguments.length >= 2 &&
      arguments[1] == kFirefoxNativeCaller &&
      _isAbsoluteFirefoxManifest(arguments[0])) {
    return kFirefoxNativeCaller;
  }
  return null;
}
```

Use it exactly once:

```dart
final String? callerOrigin = browserNativeCaller(args);
```

Add positive tests for POSIX and Windows manifest paths. Add negative tests for a relative manifest path, wrong manifest leaf, wrong add-on ID, URL query, URL fragment, invalid Chromium alphabet, and missing arguments.

**Verification**

Run the native host with a framed request under all positive and negative argument vectors. Expected: the exact Firefox pair reaches the app-state gate. Every mutation is rejected before any loopback proxy socket is opened.

### DB-03 High: Linux writes sensitive Winn v3 status to stderr

**Evidence**

`linux/runner/linux_tunnel_backend.cc:4032-4039` logs `LinuxWinn3EngineStatusJson()` in full on a promotion refusal. `winn_protocol_experimental/datapath/status.go:48-55` defines `session_id`, `gateway_endpoint`, and `local_endpoint` in that document. The same C++ file states at lines 4402-4407 that the status document must never be logged because it contains the customer's real gateway.

**Root cause**

A diagnostic intended to expose counters serializes the entire status object. A safe counter extractor exists, but only the disconnect path uses it.

**Exact production fix**

Add this declaration before the first use:

```cpp
std::string ExtractJsonCounters(const std::string& json,
                                const std::vector<std::string>& keys);
```

Replace lines 4032-4039 with:

```cpp
  const std::string engine_counters = ExtractJsonCounters(
      winsvpn::winn3host::LinuxWinn3EngineStatusJson(),
      {"max_datagram", "queue_depth", "queue_length", "uptime_ms",
       "tx_datagrams", "tx_bytes", "tx_rejected", "rx_datagrams",
       "rx_bytes", "rx_dropped", "rx_oversize", "rx_foreign_sender"});
  std::fprintf(stderr,
               "winn3 promotion refusal diagnostics: pump=%s counters=%s\n",
               winsvpn::winn3host::LinuxWinn3PumpStatsJson().c_str(),
               engine_counters.c_str());
```

Keep the existing `ExtractJsonCounters` definition at lines 4408-4427.

**Verification**

Add a hostile fixture whose status contains sentinel values for `session_id`, `gateway_endpoint`, `local_endpoint`, `carrier_error`, and `opened_at`. Drive the refusal path and capture stderr.

```bash
rg -n 'LinuxWinn3EngineStatusJson\(\)\.c_str\(\)' linux/runner
ctest --test-dir build/linux-runner --output-on-failure
```

Expected: no direct full-status logging call remains. Counter names appear. Every sentinel is absent.

### DB-04 High: live paid crypto fallback can bypass provisioning

**Evidence**

At 2026-09-13 21:27 UTC, the live config endpoint returned:

```json
{"monero_enabled":true,"crypto_enabled":true}
```

In a fresh Edge session, expanding Monthly displayed BTC, Dash, XMR, Monero, and Bitcoin or Dash checkout controls. The reported cannot-click symptom was not reproducible while the endpoint was healthy. No order-creating button was clicked.

The latent defect is still live. Live `setupCryptoPayments()` returns silently on any config error. Its coin handler then executes `openModal(coin, planTitle)` when an automated button was not built. That modal contains the static donation address, not an account-provisioning order.

The live and local bytes prove deployment drift:

| Artifact | Bytes | SHA-256 or CSP hash |
|---|---:|---|
| Live HTML | 399,654 | `f1c24e0f6e06a85bfaf98eb77f5febac5a63a662f2f3766ccd288b45493305e5` |
| Workspace HTML | 399,723 | `a79671f5ad0240675a13745407d96b35aa9f3d163565dbfc09ba08f90aa47672` |
| Live app script | 159,384 bytes | `sha256-/xEynGcgRnJ5g17gUox8eVJMbT6BOetJ909M0cYfk5k=` |
| Workspace app script | 161,113 bytes | `sha256-rsoC5LXzwZ6X10jhP+IqVrjDVLw8L6AFJ+1xcvm1pbA=` |

**Root cause**

Two payment concepts share the same coin controls. The legacy donation modal is treated as a fallback for a paid-plan checkout failure. Separately, the fixed workspace bytes have not reached the live edge.

**Exact production fix**

The workspace already contains the correct fail-closed design. Preserve these exact helper functions in `web/index.html`:

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

Replace the live setup routine with this complete workspace implementation:

```javascript
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

The coin handler's final branch must be exactly:

```javascript
if (!triggered) {
  renderCryptoUnavailable(
    card,
    "Automated crypto checkout is unavailable. Please retry shortly or choose another payment method."
  );
}
```

It must never call `openModal()` from a paid-plan coin handler. The donation modal may remain reachable only through explicitly labeled donation controls.

**Verification and deployment gate**

```bash
node --check web/_worker.js
python3 tools/website_security_audit.py
python3 -c 'import base64,hashlib,pathlib,re; d=pathlib.Path("web/index.html").read_bytes(); s=max(re.findall(br"<script>(.*?)</script>",d,re.S),key=len); print("sha256-"+base64.b64encode(hashlib.sha256(s).digest()).decode())'
curl -fsS https://winsvpn.org/ | python3 -c 'import base64,hashlib,re,sys; d=sys.stdin.buffer.read(); s=max(re.findall(br"<script>(.*?)</script>",d,re.S),key=len); print("sha256-"+base64.b64encode(hashlib.sha256(s).digest()).decode())'
```

Expected before deployment: all 56 website checks pass and the workspace app-script CSP hash is `sha256-rsoC5LXzwZ6X10jhP+IqVrjDVLw8L6AFJ+1xcvm1pbA=`. Expected after an authorized deployment: the live app-script hash equals that approved value. The whole live HTML hash is not the deployment oracle because Cloudflare currently injects request-varying script content. With the config endpoint forced to 500 in a local Worker test, coin selectors remain disabled, an inline error appears, no modal opens, and no POST occurs.

### DB-05 Medium: affected SQLite WAL runtime is not rejected

**Evidence**

The control-plane installer requests Ubuntu's unversioned `python3` packages at `server/wins_control_plane_setup_ONETOUCH.sh:2400`. The generated application enables WAL on security events and the main database at lines 6483-6484 and 7275-7299. It uses multiple writers, background workers, and checkpoints.

SQLite's official WAL page reports a low-probability but serious WAL-reset corruption defect in 3.7.0 through 3.51.2, fixed in 3.51.3 with backports 3.50.7 and 3.44.6. Ubuntu 24.04 currently advertises SQLite 3.45.1 packages. The reviewed local system Python links SQLite 3.51.0, which is affected. Pinned Homebrew Python 3.14.7 links SQLite 3.53.4, which is fixed. The deployed Kansas runtime version was not queried and remains UNVERIFIED.

**Root cause**

The installer pins Python behavior but does not set a minimum safe SQLite library. Busy timeouts and `BEGIN IMMEDIATE` reduce ordinary contention. They do not fix an upstream WAL-reset race.

**Exact production fix**

Add this complete startup guard immediately after importing `sqlite3` in each generated Python service that enables WAL:

```python
def sqlite_wal_reset_fix_present(version_text: str) -> bool:
    try:
        version = tuple(int(part) for part in version_text.split("."))
    except ValueError:
        return False
    if len(version) != 3:
        return False
    if version >= (3, 51, 3):
        return True
    if (3, 50, 7) <= version < (3, 51, 0):
        return True
    if (3, 44, 6) <= version < (3, 45, 0):
        return True
    return False


if not sqlite_wal_reset_fix_present(sqlite3.sqlite_version):
    raise RuntimeError(
        "Refusing WAL startup with SQLite "
        f"{sqlite3.sqlite_version}: install SQLite 3.51.3 or newer, "
        "or an official 3.50.7 or 3.44.6 backport."
    )
```

Upgrade the runtime to SQLite 3.51.3 or newer before restarting the service. Keep the guard after the package upgrade so later base-image drift fails closed.

**Verification**

```bash
python3 - <<'PY'
import sqlite3
print(sqlite3.sqlite_version)
assert tuple(map(int, sqlite3.sqlite_version.split('.'))) >= (3, 51, 3)
PY
```

Expected: the assertion passes on the exact interpreter used by systemd. Then run the full server suites plus a two-process WAL writer and checkpoint stress test under `PYTHONMALLOC=debug`.

### DB-06 Medium: TV focus nodes are created in `build()`

**Evidence**

New `FocusNode(skipTraversal: true)` objects are created at:

- `lib/tv_dpad_support.dart:112`
- `lib/tv_dpad_support.dart:265`
- `lib/vpn_power_control.dart:94`
- `lib/main.dart:16631`
- `lib/main.dart:17172`

Flutter's current API guidance says focus nodes are persistent objects, normally created in `initState()` and disposed in `dispose()`. Recreating them in `build()` loses focus state and leaves old attachments for framework cleanup. TV rebuilds can drop D-pad focus. Repeated dialogs add allocation churn.

**Root cause**

Stateless or builder-local keyboard listeners own lifecycle state. Several handlers are empty, but each listener still allocates and attaches a node.

**Exact production fix**

Add `lib/owned_keyboard_listener.dart` with this complete implementation:

```dart
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

class OwnedKeyboardListener extends StatefulWidget {
  const OwnedKeyboardListener({
    super.key,
    required this.child,
    this.onKeyEvent,
    this.skipTraversal = true,
  });

  final Widget child;
  final ValueChanged<KeyEvent>? onKeyEvent;
  final bool skipTraversal;

  @override
  State<OwnedKeyboardListener> createState() =>
      _OwnedKeyboardListenerState();
}

class _OwnedKeyboardListenerState extends State<OwnedKeyboardListener> {
  late final FocusNode _focusNode;

  @override
  void initState() {
    super.initState();
    _focusNode = FocusNode(skipTraversal: widget.skipTraversal);
  }

  @override
  void dispose() {
    _focusNode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return KeyboardListener(
      focusNode: _focusNode,
      onKeyEvent: widget.onKeyEvent,
      child: widget.child,
    );
  }
}
```

Import it into `tv_dpad_support.dart`, `vpn_power_control.dart`, and `main.dart`. Replace all five `KeyboardListener` constructions listed above with `OwnedKeyboardListener`, preserving each existing `onKeyEvent` body and child unchanged.

**Verification**

```bash
dart format lib/owned_keyboard_listener.dart lib/tv_dpad_support.dart lib/vpn_power_control.dart lib/main.dart
flutter analyze --no-pub
flutter test --no-pub
rg -n 'focusNode: FocusNode\(' lib
```

Expected: analysis and tests pass, and the final search is empty. On Android TV, hold each D-pad direction through repeated state updates and open or close both PIN dialogs 100 times. Focus must remain visible, remote select must fire once, and DevTools allocation tracking must show no retained `FocusNode` growth.

### DB-07 Medium: Linux blocks suspend and idle indefinitely

**Evidence**

`linux/runner/linux_tunnel_backend.cc:940-958` starts a transient user service that runs:

```text
systemd-inhibit --what=sleep:idle --mode=block sleep infinity
```

Every successful tunnel calls it at line 4397. It remains until disconnect. This prevents normal suspend and idle for the full VPN session, increasing laptop battery drain. The Android service now uses only a bounded 60-second startup wake lock, so Linux behavior is inconsistent with the repaired mobile posture.

**Root cause**

A startup protection became a session-wide inhibitor. VPN reconnect-on-resume is conflated with preventing the operating system from sleeping.

**Exact production fix**

Remove the success-path call and retain teardown to clean stale units created by older builds:

```diff
@@
   std::remove(config_path.c_str());
   g_linux_split_tunnel_ready = !g_linux_excluded_apps.empty();
-  StartTunnelPowerProtection();
   g_tunnel_session_committed = true;
   return true;
```

Delete `StartTunnelPowerProtection()` after no callers remain. Keep `StopTunnelPowerProtection()` on disconnect for one release cycle as migration cleanup, then remove it after confirming no supported release can leave the old unit.

**Verification**

```bash
rg -n 'StartTunnelPowerProtection|sleep.*infinity|what=sleep:idle' linux/runner
systemd-inhibit --list
systemctl --user is-active winsvpn-power-inhibit.service
```

Expected after connect: no start function or infinite inhibitor remains, the unit is inactive, suspend succeeds, and resume reconnects or reports disconnected truthfully.

### DB-08 Medium: current release evidence fails its own invariant

**Evidence**

The focused integrity test reports these untracked files:

```text
winn_protocol_experimental/cmd/winn3-gateway/forward_round10_test.go
winn_protocol_experimental/cmd/winn3-gateway/gateway_authority_test.go
winn_protocol_experimental/internal/carrier/h3_receive_window_test.go
```

The test explains the consequence correctly: a clone runs a smaller suite and can report green. The broader Go suite passed only because these files were present locally.

The connected device was `motorola_edge_plus_2023`, serial `ZY22GTV6Z3`. No release APK exists. The authorized producer requires Flutter 3.47.1 at revision `6655482ec06e547f90abf8ae7590466f4415978d`, while the installed SDK is Flutter 3.44.6 at `ee80f08bbf`. The raw Flutter APK command correctly refused a non-obfuscated release.

**Root cause**

Regression tests were added locally but not placed under repository custody. Separately, this host lacks the pinned Android release toolchain, so device acceptance cannot be renewed.

**Exact production fix**

After reviewing that the three tests are intended release gates, place all three under Git custody in the same change as the production code they protect:

```bash
git add -- \
  winn_protocol_experimental/cmd/winn3-gateway/forward_round10_test.go \
  winn_protocol_experimental/cmd/winn3-gateway/gateway_authority_test.go \
  winn_protocol_experimental/internal/carrier/h3_receive_window_test.go
git diff --cached --check
```

Do not weaken the Android producer. Provision the exact pinned Flutter revision and run `tools/build_android_release_macos.sh` through its documented non-root release path.

**Verification**

```bash
flutter test --no-pub test/tracked_reference_integrity_test.dart
flutter test --no-pub
go test ./...
go test -race ./cmd/winn3-gateway ./datapath ./internal/carrier ./winn3/...
adb uninstall org.winsvpn.app
adb install -r build/app/outputs/flutter-apk/app-release.apk
adb shell monkey -p org.winsvpn.app -c android.intent.category.LAUNCHER 1
adb logcat -d | rg -i 'org\.winsvpn\.app|VpnTunnelService|fatal|exception|protect\(|winn'
```

Expected: integrity test passes from a clean clone, full Flutter and Go suites pass, uninstall succeeds or reports the package absent, APK install succeeds, launch is visible, and logcat has no startup, VPN, socket-protection, or foreground-service error.

### DB-09 Medium: Cloudflare injection conflicts with live CSP

**Evidence**

The live response CSP authorizes the live app hash and intended third-party scripts. Cloudflare then injects Web Analytics and a 921-byte inline JavaScript Detections block. Edge reports both as refused. The inline block hash changed across requests, so a static CSP hash is not a valid fix. The live response also injects Cloudflare email-decode code from the same origin.

Cloudflare's current documentation confirms:

- Automatic Web Analytics needs `https://static.cloudflareinsights.com` in `script-src`.
- JavaScript Detections under a strict CSP should use a per-response nonce.
- `unsafe-inline` is discouraged.
- `Cache-Control: no-transform` stops JSD and automatic Web Analytics injection, but also prevents supported body transformations and can affect compression.

**Root cause**

The site owns a hash-based CSP over deterministic HTML. Cloudflare owns post-response script injection with request-varying content. Both systems mutate the script set independently.

**Exact production fix**

Choose one owner for HTML scripts. The immediate safe configuration is:

1. Disable Cloudflare Web Analytics automatic injection for `winsvpn.org`.
2. Disable JavaScript Detections on the public marketing and checkout HTML routes.
3. Keep the current hash-based CSP and do not add `unsafe-inline`.

This preserves compression and the deterministic site hash. If JSD is a required bot signal, replace the app script hashes with a fresh cryptographic nonce on every HTML response, add that nonce to every intentional script tag, and let Cloudflare copy it to injected tags as documented. That migration needs a Worker response-body test and should not be improvised in the dashboard.

**Verification**

```bash
curl -fsSI https://winsvpn.org/ | tr -d '\r' | rg -i 'content-security-policy|cache-control'
curl -fsS https://winsvpn.org/ | rg -n 'cloudflareinsights|challenge-platform|data-cf-beacon'
```

Expected for the immediate configuration: the second command finds no automatically injected analytics or JSD tag. A clean browser console has no CSP refusal from `static.cloudflareinsights.com` or Cloudflare's inline JSD. The site's intentional app script and structured data remain authorized by their exact hashes.

### DB-10 Low: native-host regression suite leaks environment and hangs

**Evidence**

`tools/native_messaging/test_native_host_registration.py:55-64` deletes `WINSVPN_OWNER_IDENTITY_RECEIPT` rather than pointing it to a known missing test file. A machine-wide owner receipt can therefore influence a supposedly isolated test. On this host, the first test observed external identity state.

At lines 919-931, the fallback dummy-host test starts a framed stdin server without sending a frame, closing stdin, or setting a timeout. The suite waited indefinitely until interrupted.

**Root cause**

Absence from the process environment is not isolation when production code has a filesystem fallback. The second test verifies executable selection but forgets the executable's input protocol.

**Exact production fix**

Replace `isolated_store_env` with:

```python
@contextmanager
def isolated_store_env(**values: str):
    keys = (
        "WINSVPN_CHROME_STORE_ID",
        "WINSVPN_EDGE_STORE_ID",
        renderer.OWNER_IDENTITY_ENV,
    )
    previous = {key: os.environ.get(key) for key in keys}
    with tempfile.TemporaryDirectory(prefix="winsvpn-owner-identity-") as raw:
        for key in keys:
            os.environ.pop(key, None)
        os.environ[renderer.OWNER_IDENTITY_ENV] = str(
            Path(raw) / "missing-owner-identity.json"
        )
        os.environ.update(values)
        try:
            yield
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
```

Replace the blocking subprocess at lines 929-931 with:

```python
request = b"{}"
completed = subprocess.run(
    [str(dummy)],
    input=len(request).to_bytes(4, "little") + request,
    check=False,
    capture_output=True,
    timeout=8,
)
```

**Verification**

```bash
python3 tools/native_messaging/test_native_host_registration.py
```

Expected: the suite terminates, isolated cases ignore all external receipts, and timeout is reported as a test failure rather than hanging the audit.

## 5. Platform analysis

### Windows x86 and ARM64

**Verified static posture**

- The named pipe uses an explicit protected DACL granting full access to SYSTEM and Administrators, with read and write for the interactive user. Remote clients are rejected.
- Client authorization uses impersonation and active-console identity checks before processing a request.
- Request size is bounded.
- Tunnel children are created suspended, assigned to a Job Object with kill-on-close, and then resumed. Cleanup paths close process, thread, token, pipe, and job handles.
- Pointer and test seam values use `uintptr_t`, avoiding a visible 32-bit truncation defect on ARM64.
- `WINS_TUNNEL_SERVICE_CORE` keeps privileged service code separate from UI compilation surfaces.
- Windows lifecycle, single-instance, SDDL, and ARM64 packaging oracles passed.

**Findings**

- DB-01 and DB-02 affect the Windows-installed browser host.

**Unverified**

No Windows x86 or ARM64 binary executed on this macOS host. Real DACL inheritance, service control manager identity, WOW64 registry selection, process crash containment, and handle counts under repeated connect or disconnect remain runtime gates.

### Linux x86 and ARM64

**Verified static posture**

- `RunArgv` creates a process group, uses nonblocking pipe reads, applies a 15-second monotonic deadline, reaps with `waitpid(WNOHANG)`, then uses group SIGTERM and bounded SIGKILL.
- Shutdown is connected to `GApplication::shutdown`, SIGINT, and SIGTERM.
- Privileged paths use `validate_root_owned_path` custody checks.
- Firewall work uses owned `WINVPN-*` chains and `iptables-restore --noflush`; no reviewed production path flushes the host's base policy.
- systemd units include meaningful sandbox controls and absolute helper resolution.
- Full Go tests and selected race tests passed.

**Findings**

- DB-03 exposes Winn v3 connection metadata in logs.
- DB-07 prevents sleep and idle across the session.

**Unverified**

Linux-only subprocess and signal tests skipped on macOS. Package installation, root custody against hostile mounts, eBPF helper execution, FD counts under 10,000 reconnects, systemd sandbox enforcement, nftables coexistence, and both x86 and ARM64 artifacts remain target-host gates.

### macOS x86 and ARM64

**Verified static posture**

- The ruled `WinsMacRoutePosture.enforceRoutes` value is `true` and has one guarded source.
- `excludeLocalNetworks` is set to `true` when the tunnel protocol is configured.
- Route audit, persisted preference round trip, method-channel contract, and standalone v3 wiring tests passed.
- Outer endpoint exclusions are installed before full-route carriage.
- Hardened runtime and Network Extension entitlements are present in reviewed project settings.
- QUIC receive windows are bounded: 128 KiB initial stream, 512 KiB maximum stream, 256 KiB initial connection, 2 MiB maximum connection.

**Findings**

- DB-01 affects the macOS companion native host.

**Unverified**

No signed universal app or Network Extension ran. Route socket behavior, sleep or wake reconnect, memory pressure, extension IPC, code signing, and sustained packet throughput remain device gates.

### Android phone and Android TV

**Verified static posture**

- TV declares `android.software.leanback` and `android.hardware.touchscreen` with `required="false"`.
- TV application metadata includes a banner and the TV activity has `LEANBACK_LAUNCHER`; the phone source set does not incorrectly require Leanback.
- AWG and Winn carrier sockets call `VpnService.protect()` and fail closed if protection fails.
- Split-tunnel package exclusion throws on configuration failure rather than silently expanding scope. Disappeared packages are handled separately.
- XRay-dependent Android modes fail closed before DNS, process launch, or performance changes.
- Teardown timeout returns `START_NOT_STICKY`.
- Foreground lifecycle and a bounded 60-second startup wake lock are present. The old full-session Wi-Fi lock is absent.

**Findings**

- DB-06 can destabilize D-pad focus on rebuild.
- DB-08 blocks physical phone smoke evidence for this snapshot.

**Unverified**

The connected Motorola phone was not modified because no authorized release APK existed. Android TV remote, banner rendering, foreground-service behavior on recent Android releases, protected socket routing, split-tunnel isolation, and battery behavior remain physical-device gates.

### iOS and tvOS

**Verified static posture**

- The iOS packet tunnel has a strict 15 MiB physical-footprint watchdog with a one-second cadence and cancellation code 1038.
- Apple route posture and method-channel oracles passed.
- QUIC receive-window bounds reduce untrusted buffering inside the extension.

**Scope correction**

The current Xcode project targets iPhone and iPad device families, plus watch targets. No `appletvos` SDK or tvOS deployment target exists. tvOS D-pad navigation and background wakeup therefore cannot be audited as shipping native tvOS behavior. Website copy identifies tvOS as later scope.

**Unverified**

No signed iOS packet tunnel ran. A passing source-level watchdog test is not proof that real encrypted throughput stays under 15 MiB. Run a physical-device soak with memory footprint, jetsam logs, packet loss, and reconnect captures before release.

### Browser extensions

**Verified static posture**

- Chrome and Edge use Manifest V3 service workers. Initialization failures are recorded for retry rather than becoming unhandled rejections.
- Firefox uses its background event page and enforces privacy settings only when it controls them. Failure triggers the controller's fail-closed path.
- Permissions for proxy, native messaging, webRequest, and authentication are target-specific and verified by bundle tests.
- PAC output is synthesized from bounded local proxy state and has secure fallback behavior.
- Chrome, Edge, Firefox, and Safari bundles rebuilt and passed identity checks.
- Safari correctly reports that the Chromium or Firefox native host route is unavailable. A Safari Web Extension requires app messaging through `SFSafariApplication`, not the other browsers' native manifest.

**Findings**

- DB-01 and DB-02 make credential-bearing native messaging unusable after production installation.
- DB-10 weakens regression confidence.

**Unverified**

No store-signed extension ran in Chrome, Edge, Firefox, or Safari. Service-worker termination recovery, browser upgrade, native-host launch, PAC failover, authentication challenge handling, and Safari app-extension messaging remain real-browser gates.

### Control plane and data planes

**Verified static posture**

- Remote PayPal and administrative calls reviewed in async routes are offloaded with `asyncio.to_thread`, with database connections closed across remote waits.
- Remaining no-await FastAPI routes with synchronous SQLite or file work are `def` routes and use the framework thread pool.
- WAL, busy timeout, and foreign keys are configured on security-event connections. Main database initialization serializes the first WAL transition.
- Activation secrets use secure random generation, are single-use inside admission transactions, and are not burned on node-sync rollback.
- Expiration parsing normalizes offsets, rejects unparseable or past values, and limits duration syntax to ten years.
- Payment capture paths recheck provider completion. BTCPay URLs require HTTPS and the configured origin.
- Activation delivery uses an encrypted durable outbox with lease, backoff, terminal states, and sealed-secret erasure.
- Peer revocation and v3 registry refreshes are durable and transactionally queued.
- Account status requires device ID and bearer authentication.
- Data and control firewall code uses dedicated chains rather than flushing base chains.

**Findings**

- DB-05 requires a runtime SQLite version gate.

**Unverified**

No live server was queried for package versions, SQLite linkage, iptables state, systemd policy, file ownership, WAL health, queue backlog, payment reconciliation, email delivery, or secret reuse. Static and generated-module tests cannot establish current production state.

### Winn v3, Winn v1, AWG, and XRay

**Verified static posture**

- Winn v3 authority refresh, per-packet expiration, static-session key checks, file size cap, stale-session eviction, key rotation on replacement, and durable registry refreshes are present.
- Winn v1 dispatch attempts AmneziaWG first. XRay VLESS WebSocket is a runtime fallback only after the AWG attempt fails.
- Generation authorization and anti-downgrade tests passed in the local Go and Flutter coverage that executed.
- Android disables XRay capability and fails closed for XRay-required plans.
- The full Go suite and the selected race suite passed.

**Findings**

- DB-03 leaks v3 metadata only on the Linux promotion-refusal diagnostic.
- DB-08 means three important authority or receive-window tests are not yet clone-visible.

**Unverified**

No real gateway handshake, AWG failure to XRay fallback, cross-generation denial, packet replay, carrier migration, or multi-hour throughput test ran against a target device and gateway.

### Website, DNS, payment, and provisioning

**Read-only live observations**

- A records: `172.67.185.162`, `104.21.36.50`.
- AAAA records: `2606:4700:3031::6815:2432`, `2606:4700:3037::ac43:b9a2`.
- Nameservers: `isabel.ns.cloudflare.com`, `julio.ns.cloudflare.com`.
- TLS subject: `CN=winsvpn.org`.
- TLS issuer: Google Trust Services WE1.
- Certificate validity: 2026-09-01 11:31:38 UTC through 2026-11-30 12:31:34 UTC.
- Homepage: HTTP/2 200, HSTS two years with subdomains, COOP same-origin, CORP same-origin, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `cf-cache-status: DYNAMIC`.
- Crypto config: HTTP 200 with both automated methods enabled.

**Findings**

- DB-04 is a live code drift and financial workflow defect.
- DB-09 is a live CSP and Cloudflare configuration conflict.

**Provisioning assessment**

The workspace implementation binds payment completion to secret generation, transactional admission, durable activation delivery, and explicit lifetime duration handling. Failure and replay tests passed in the server rounds. No live capture, activation, delivery, refund, or lifetime expiry was exercised, so production provisioning remains UNVERIFIED.

## 6. Performance and memory assessment

### Verified improvements

- Apple QUIC receive windows are bounded well below broad library defaults, limiting extension memory exposure.
- iOS and macOS packet-tunnel watchdogs terminate at the project's strict 15 MiB ceiling.
- Android has no full-session Wi-Fi performance lock and uses a bounded startup wake lock.
- Linux subprocess output is nonblocking and deadline-bound.
- Winn v3 registry and authority files have bounded reads.
- MTU, outer endpoint exclusion, MSS clamping, and packet-size validation paths are present across reviewed platforms.
- Worker rate-bucket storage has expiry pruning and a hard cap.

### Bottlenecks and risks

- DB-07 creates avoidable laptop battery drain and blocks normal suspend.
- DB-06 creates avoidable focus allocation and attachment churn.
- Live HTML is about 400 KB before transport compression. Do not use `Cache-Control: no-transform` as the permanent CSP repair unless the compression cost is measured and accepted.
- SQLite serializes writes by design. WAL and busy timeouts improve concurrency but do not remove the single-writer ceiling or DB-05.
- The native host, platform runners, and packet extensions lack a current repeated-connect FD or handle leak soak in this snapshot.

### Required benchmark gates

Run these on each supported architecture before release:

1. Ten thousand connect or disconnect cycles with handle, FD, child-process, and resident-memory sampling.
2. One-hour sustained small-packet and maximum-MTU traffic with p50, p95, p99 latency, CPU, battery, drops, and allocations.
3. Path-MTU transitions across Wi-Fi, cellular, Ethernet, and IPv6-only networks.
4. Suspend and resume while connected, without any sleep inhibitor.
5. iOS packet-tunnel physical footprint sampled each second under bidirectional load. It must remain strictly below 15 MiB without watchdog cancellation.
6. SQLite multiprocess writers with explicit checkpoints on the exact systemd interpreter and library.
7. Browser service-worker termination every 30 seconds while issuing authenticated proxy requests, with native-host process counts and PAC recovery checked.

## 7. Release exit criteria

Release authority requires all of the following on one exact clean revision:

- DB-01 through DB-09 fixed and covered by negative regression tests. DB-10 should also be fixed so the native-host suite is dependable.
- All intended tests tracked. `git status --short` clean after reproducible generation.
- `tools/verify_rulings.sh`, full Flutter, full Go, selected Go race, server, extension, website, and platform release suites green from a clean clone.
- Pinned toolchains used. No fallback to the installed Flutter 3.44.6 for Android release evidence.
- Android phone and Android TV physical acceptance complete, with uninstall-first procedure and logcat review.
- Windows x86 and ARM64 service, pipe ACL, Job Object, and repeated-lifecycle acceptance complete.
- Linux x86 and ARM64 package, signal, systemd, firewall, eBPF, and suspend acceptance complete.
- Signed macOS and iOS tunnel acceptance complete, including routing and memory measurements.
- Store-signed browser extensions verify native messaging in each browser.
- Live site bytes match approved reviewed bytes, the config-failure crypto path fails closed, and browser console has no site-owned CSP errors.
- Live payment and email tests occur only under an explicit owner-approved test transaction plan. None was authorized in this audit.

Until those gates are satisfied and recorded against immutable bytes, the release decision remains **NO-GO**.

