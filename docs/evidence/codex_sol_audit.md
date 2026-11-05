# Codex Deep Audit Report: 5.6 Sol Pro (OpenRouter openai/flex)

- Model Identifier: `openai/gpt-5.6-sol-pro`
- Reasoning Effort: `xhigh / max`
- Collected: `2026-09-16T11:05:53.357834+00:00`
- Process Exit Code: `0`
- Content Source: `lane report file (/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/sol/docs/evidence/codex_sol_audit.md)`
- Usage Metadata: `{"prompt_tokens": 24393195, "completion_tokens": 96162, "total_tokens": 24489357}`

## Reasoning Trace

```
**Reviewing workspace audits**

I need to conduct an extensive audit of the workspace and ensure there are no em or en dashes in the final report. It’s crucial that I report the exact path, so I’ll plan on using tools for this. While I don’t have a specific timeframe, it’s tokenized. Careful inspection of the repository is necessary, and I’ll start by checking the present working directory, listing files, and executing commands like git status and finding sizes.

**Conducting an audit**

I need to conduct a thorough audit within a specific time frame. I should inspect the existing report, which is deleted but might be accessible through git HEAD for prior information. No modifications are needed, except in the report. Compliance is crucial, so I must avoid using specific language in the report. I'll execute actual tests in a read-only manner. The main goal is to assess the current state and focus on discovering remaining issues, ensuring I'm careful about not exposing any secrets during commands.**Reporting requirements and bugs**

I need to ensure that the report requirements detail exact and complete fixes. If there are unresolved findings, I should provide diffs. It's essential to seek out real bugs. My focus is on Round33, particularly regarding handshake, key synchronization, and performance. The current untracked reports might uncover the latest critical bug. I must read the audit report and handshake audits, treat the evidence carefully, and reiterate the need for clear reporting on fixes.

**Inspecting protocol changes**

I'm considering potential issues in the current Winn protocol. It seems like there might be encoded fail-open tests in the roam_behavior tests, which could be testing specific outcomes. I want to list the recent untracked or modified test names using `git diff --name-only`. The current worktree appears to match another audit, so maybe the findings have been fixed. The audit report references a production path that doesn't match the current date. I need to identify and inspect the relevant differences and source.

**Considering build logs**

I need to record the exact command results and possibly build logs under build/codex. It seems I can pipe logs and summaries before running live. Speaking of time, the current system date is bizarrely 2026, but I should report based on what’s actually happening. I also want to inspect the TV manifests fully. I should use the `cat` command specifically, but maybe I'll need to truncate the output for clarity.

**Interpreting system changes**

I'm looking to interpret some key changes that seem quite complex. We need to be thorough and detail findings, like how the Android kill switch transition resets and closes blocking operations before a new interface. There are concerns about synchronizing peer and registry I/O that need addressing. I see potential high availability issues because the SQLite writer could be held up significantly. I should aim for precise, complete code fixes for the identified problems.**Addressing package build issues**

I need to include a targeted diff or script for fixes, but realistically, I can't code for every issue identified. Our findings should be precise. The package release is currently blocked due to a stale identity receipt and missing esbuild components. This is a significant blocker, and while the severity is medium, the security quality is also at a medium level. The root cause is known, needing an owner-issued identity receipt, which can't be generated. I should communicate that we can't safely provide code fixes for all defects.**Diagnosing CSP drift**

I need to address a medium-level CSP drift problem. It looks like the current index in the repository has changed compared to live, which indicates a CSP difference. I should diagnose the crypto button. The live DOM currently includes certain elements, and the config response returns a size of 200 with likely boolean values. Our next step is to fetch the config body, ensuring it’s safe and doesn't contain any secrets. Let's proceed with that!

**Considering headless support**

I’m thinking that Edge might support headless mode. I need to enable specific commands like Page.enable, Runtime.enable, Log.enable, and Network.enable. Then, I’ll navigate and evaluate JavaScript clicks and states. It feels a bit repetitive, but I should double-check that Edge can indeed handle this headless setup. Let’s break it down and make sure everything runs smoothly!

**Addressing gateway issues**

We have confirmed a significant bug, as the source states that the gateway wasn't shipped, yet it's being used in deployment. This suggests a critical need for a comprehensive production fix. The user needs complete code or exact diffs for every issue. I’m exploring options for a NAT rebind fix that seems complex. I could suggest a massive diff, perhaps integrating gateway architecture, though I should ensure it’s compilable and not just an incomplete fix. I need to inspect the relevant components for effective solutions.**Understanding gateway integration**

I need to grasp how to connect the Plaintext result into the session Driver, given that the package gateway includes tables, Binder, and Result. The gateway takes care of the handshake and core session, and I can create a session driver using NewGatewayFromSession. However, since Gateway.Handle has already decrypted the transport message, the driver requires a method like DeliverPlaintext to process it properly. It seems like deliverFrames might not be exported. I’ll search for "DeliverOpened" and "DeliverPlaintext" to clarify how to integrate these elements effectively.

**Evaluating technical fixes**

I’m thinking about the need for a precise fix related to a complex transaction reservation state. This might call for high performance and availability, but I’m not sure if there’s a fully copyable solution. I could suggest using PostgreSQL immediately. The user wants exact code, so I should be cautious about providing precise diffs or refactoring functions.

There are two critical issues I identified: one involves NAT rebinding and the other is about the mobile resilience of Android’s kill-switch gap. Both seem to present high risks.**Considering a reset fix**

I'm pondering whether an immediate fix could involve a reset process. If the kill switch is armed and the OS isn’t guaranteed to function properly, I might suggest retaining the vpnInterface. If the engines stop, then a new builder.establish could create a new TUN, and afterward, I could close the old one. It’s a thoughtful approach, but I want to ensure it's safe and effective before moving forward.

**Considering code fix**

I’m focusing on the exact code for H1. It seems like there's an immediate fix until the architecture conversion happens. The installer should refuse to forward production due to a known defect, and the control plane must avoid registering v3. This should help eliminate user vulnerabilities. I need to copy the code in installer validation, ensuring it includes a message indicating that product v3 is unavailable for security reasons.

**Creating a concise report**

I’m working on a final report that's under 400 words and should reflect key points like path and byte size. The report's exact size is 48,938 bytes. I’ll categorize findings, aiming for severity levels such as High or Medium while making sure not to verify anything I can't confirm. I need to avoid using em dashes or cliches and include static crypto clicks that aren't replicated. Keeping all this in mind, I’ll draft it carefully.
```

## Audit Findings & Exact Fix Implementations

# WinsVPN Round 33 Independent Audit

**Author:** 5.6 Sol Pro (OpenRouter openai/flex)
**Audit time:** 2026-09-16 UTC
**Workspace:** `/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/sol`
**Commit:** `89be66e75747c0b493583ca9c9efd7787c88a974`
**Audited object:** The current workspace, including staged, unstaged, and untracked files
**Production tree access:** None
**Live testing:** Read-only GET, DNS, TLS, headers, and a headless browser. No order, account, email, deploy, or state-changing request was made.

## 1. Executive verdict

**NO-GO. The ecosystem is not 100 percent sound.**

The strongest remaining defect is in the deployed Winn v3 gateway architecture. Production installation invokes `cmd/winn3-gateway`, but that binary still indexes established sessions by outer `netip.AddrPort`. A carrier or NAT rebinding therefore turns authenticated transport into an unknown-source miss. Full-size packets are dropped while both client and gateway still report carrying. The repository contains a behavioral test that asserts this broken result. The token-indexed, address-independent `winn3/gateway` package and the new `session.NewGatewayFromSession` composition seam exist, but the server binary does not use them.

Two release and availability failures are also open. First, two Firebase mirrors and the advertised GitHub releases mirror return HTTP 404. Only the Cloudflare Pages mirror responds. Second, all four browser archives cannot be reproduced by the mandated build. The build correctly refuses because Chrome and Edge lack a current external owner identity receipt. The extension suite also has three failures and twelve setup errors, partly from that identity gate and partly from the absent frozen esbuild archive.

The live crypto checkout bug is **not reproducible now**. A real headless Microsoft Edge load of `https://winsvpn.org` observed enabled BTC, Dash, and XMR selectors. Clicking the one-month crypto plan expanded the automated row. Clicking XMR opened the email and Monero order panel. The static donation modal stayed hidden. No payment order was submitted. The live crypto config returned both providers enabled. The historical root cause is confirmed in source: the page contains two separate crypto flows. The corrected plan listener opens an automated panel; static `openModal()` is now reachable only from donation-drawer buttons. The coin listener fails closed into retry UI and never falls back to the static address.

A broad set of defenses held under inspection and tests: Windows service separation and named-pipe client checks, Linux process-group teardown, Android socket protection and handoff callbacks, Apple route posture, v3 peer-key identity pinning, signed descriptor validation, registry authority checks, Double VPN egress chains, MSS 1240 clamping, router HMAC and replay protection, PAC fail-closed generation, SQLite WAL, single-use activation secrets, and payment settlement provenance.

### Severity register

| ID | Severity | Domain | Status | Short finding |
|---|---|---|---|---|
| R33-H1 | High | Winn v3 gateway | Open | Authenticated NAT rebind blackholes full-size traffic while both gates remain carrying |
| R33-H2 | High | Browser release | Open, owner-gated | Mandated four-archive build refuses, current archives fail identity custody checks |
| R33-H3 | High | Public availability | Open | Three advertised censorship-bypass mirrors return 404 |
| R33-H4 | High | Android kill switch | Open | App-held blocking interface is closed before replacement tunnel establishment |
| R33-M1 | Medium | Control plane | Open | Admission and v3 registry publication hold the global SQLite writer lock across SSH |
| R33-M2 | Medium | Gateway privacy | Open | Peer registry authorization logs authenticated static public keys and inner addresses |
| R33-M3 | Medium | Apple kill switch | Open design gap | Tunnel self-cancel or provider crash has no on-demand restart posture |
| R33-M4 | Medium | Hub privilege | Open | Internet-facing hub runs as root with fleet SSH custody and CAP_NET_ADMIN |
| R33-M5 | Medium | Web edge | Open operations gap | Pages payment quotas are isolate-local, no repository proof of zone WAF limits |
| R33-M6 | Medium | macOS memory | Open evidence gap | Current Mac code samples footprint, but no strict ceiling and no current load proof |
| R33-L1 | Low | Website deployment | Open | Live CSP and HTML are behind current workspace source |
| R33-L2 | Low | Website gate | Open | Static audit does not test generic GitHub release URLs or live mirror health |
| R33-L3 | Low | Nginx downloads | Open | `/pkg/` child `add_header` directives shadow inherited security headers |
| R33-L4 | Low | Test hygiene | Open | Repository diff has trailing whitespace and full Flutter suite has two integrity failures |
| R33-L5 | Low | Tooling | Open | Apple resolver ordering verifier requires explicit paths but its usage does not document them |
| R33-L6 | Low | tvOS | Product gap, not current release blocker | No native tvOS target exists |

There were no new Critical findings. Absence of a Critical finding is not a release approval.

## 2. Audit limits and evidence quality

The workspace was unusually dirty: 4,051 tracked files, 709 tracked paths modified, 24 untracked paths, and 733 total status entries when inspected. Staged and unstaged diffs overlap on many files. This prevents any honest claim that the audited bytes equal a reviewable commit or a producible release.

No Windows x86, Windows ARM64, Linux x86, Linux ARM64, Android x86, Android ARM64 physical release, iOS production release, tvOS, or AICORE runtime was available for this round. Existing committed physical evidence was reviewed, but it predates the current tree. Native Linux timeout tests were skipped on macOS. Router preflight stopped because `/usr/bin/python3.14` is unavailable. Extension release identity evidence is owner-blocked. Cloudflare dashboard DNS and WAF configuration was not accessible, so public DNS answers and HTTP behavior were measured, not dashboard intent.

Evidence generated by this audit is under `build/codex_sol_audit_round33/`. It contains no credentials.

## 3. Findings and production fixes

## R33-H1: Winn v3 production gateway cannot survive NAT or carrier rebinding

**Severity:** High
**Affected:** Linux gateway, Android roaming, Apple roaming, Windows and Linux path changes, Winn v3 availability
**Root cause:** The deployed binary uses outer address identity instead of the protocol demux token.

### Verified behavior

`winn_protocol_experimental/cmd/winn3-gateway/main.go` states that it is not the shipping-quality gateway and indexes `server.peers` by `netip.AddrPort`. `sessionFor` builds one session per outer tuple. `newSession` closes the response callback over the initial tuple. `readLoop` treats a full-size authenticated datagram from a new tuple as a stranger because it is too large to be an initiation.

The regression is explicit and executable:

```text
TestAuthenticatedFullSizeDataAfterAClientRebindIsAStrangerAndBothGatesStayCarrying
PASS
```

The test proves the bad behavior: the packet is not echoed, the new tuple is not learned, and both gates stay carrying. Command and output are in `gateway_rebind_defect.log`.

This is not a theoretical mismatch. Cellular NAT mappings regularly change during radio transitions. Android's `setUnderlyingNetworks` changes the VPN network hint, but it cannot repair a gateway that binds the cryptographic session to the old source port. No production caller of `carrier.UDP.SetPeer` exists. No production caller of `Loop.Migrate` exists outside library internals. Existing fleet evidence records `migrations=0`.

### Exact production fix

Do not patch this with unauthenticated tuple reassignment. That would let any packet move the return path. Replace the address-keyed front door with the existing `winn3/gateway.Gateway` token-indexed front door, then adopt authenticated sessions through `session.NewGatewayFromSession`.

Required implementation contract:

1. `runServe` constructs one `gateway.Gateway` with the existing shared `core.Responder`, path MTU, rate limits, and a Binder that returns the new session, its receive demux source, and the authenticated client static key.
2. `readLoop` calls `front.Handle(datagram, sourceBytes, now)` before any per-session allocation.
3. On `KindHandshake`, send only `Result.Reply`, construct a frame driver with `session.NewGatewayFromSession`, bind it to the returned `gateway.Entry.ID`, and start its TUN loop.
4. On `KindTransport`, look up the frame driver by `Entry.ID`, deliver the already authenticated plaintext through a new `Driver.DeliverPlaintext` API, then update the reply tuple only after AEAD success. The tuple map is metadata, never authentication authority.
5. On rekey, call `Entry.Rekeyed` from the exact driver epoch-cutover hook.
6. On loop exit, remove the entry from `gateway.Table` and erase all tuple metadata.
7. Delete the address-keyed `server.peers` demultiplexer and replace the bad-behavior test with a test that moves source port every packet and proves continued bidirectional carriage.

A safe targeted API addition is required because `Gateway.Handle` already opens transport ciphertext. Add this complete method beside `Driver.Deliver` in `winn3/session/driver.go`:

```go
// DeliverPlaintext consumes plaintext that was already authenticated and replay
// checked by an external gateway token index. The caller must pass the exact
// wire message length so wide-probe accounting remains identical to Deliver.
func (d *Driver) DeliverPlaintext(plain []byte, wireMessageSize int) ([][]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.Terminal() {
		return nil, ErrClosed
	}
	if d.sess == nil {
		return nil, wrap(ErrState, "plaintext delivery requires an established core session")
	}
	now := d.cfg.Clock.Now()
	d.lastOpened = now
	d.rekeyConfirmAt = time.Time{}
	d.stats.MessagesReceived++
	d.stats.BytesReceived += uint64(wireMessageSize)
	dataAllowedAtOpen := d.dataMayFlow()
	frames, err := core.ParseFrames(plain)
	if err != nil {
		d.beginClose(CloseProtocolError, wrap(ErrProtocol, "peer sent an unparseable frame stream: %v", err))
		return nil, nil
	}
	return d.handleFramesWithDataAdmission(
		now,
		frames,
		wireMessageSize >= d.cfg.MaxMessageSize,
		dataAllowedAtOpen,
	)
}
```

This method is complete, but the full gateway conversion crosses `main.go`, gateway entry ownership, rekey hooks, and forwarding teardown. It must be implemented as one reviewed change. Shipping a partial tuple-rebind patch is unsafe.

Until that integration is complete, the complete fail-closed production containment is to make forwarding mode unstartable. Add this at the top of `validateForwardMode` in `cmd/winn3-gateway/main.go`:

```go
if opts.forward {
	return 0, errors.New(
		"-forward is disabled until cmd/winn3-gateway uses the address-independent token index; " +
			"the current outer-address demultiplexer loses authenticated sessions after NAT rebinding")
}
```

`errors` is already imported. This containment intentionally disables standalone v3 forwarding instead of serving a false-carrying tunnel. The control plane must keep affected nodes withdrawn or explicit v1 while this guard exists. Do not rewrite a served v3 response to v1 at runtime.

### Verification

```bash
cd winn_protocol_experimental
go test -count=100 -race ./cmd/winn3-gateway \
  -run 'TestAuthenticatedFullSizeDataAfterAClientRebind'
go test -count=10 -race ./winn3/gateway ./winn3/session ./winn3/driver ./cmd/winn3-gateway
go test -count=1 -race ./...
```

Expected: the renamed rebind test carries every valid packet after source-port change, returns traffic to the new tuple, leaves one session, increments authenticated peer moves, and reports zero strangers for those packets. Add a physical Wi-Fi-to-cellular and cellular-to-Wi-Fi test on Android and iOS. It must show nonzero migration or authenticated peer-move counters, no UI false carrying interval, no DNS leak, and no packet loss after the bounded handoff window.

## R33-H2: Browser archives cannot be produced from the current tree

**Severity:** High
**Affected:** Chrome, Edge, Firefox, Safari release integrity

`python3 extension/build.py` exits 3. Leakscan, copy-honesty, and bridge-contract gates pass. Gate 4 refuses Chrome and Edge because their origins are not bound to a current external owner-issued identity receipt. This is good fail-closed behavior, but it means the requested packaging claim is false.

The full extension test run reported 553 passed, 3 failed, and 12 errors. The direct Chrome zip identity assertion fails. Other errors occur because the frozen esbuild archive is absent and fetch is disabled. Existing zips pass `unzip -t`, but valid ZIP structure is not source reproducibility or store identity authority.

### Fix

No source code can legitimately mint this evidence. Obtain a current owner-issued receipt at the external path required by `tools/native_messaging/render_host_manifest.py`, provision the pinned esbuild cache, then rebuild. Do not weaken gate 4 and do not treat `store_identity.json` draft IDs as publication authority.

```bash
export WINSVPN_BROWSER_EXTENSION_IDENTITY_RECEIPT=/absolute/external/read-only/browser-extension-store-identity.json
export WINS_EXTENSION_ESBUILD_CACHE=/absolute/external/read-only/esbuild-cache
python3 tools/native_messaging/check_host_manifests.py
python3 extension/build.py
python3 -m pytest -q extension/tools
for archive in extension/dist/*.zip; do unzip -t "$archive"; done
```

Expected: build exit 0, all four target archives regenerated, no test failures or errors, and Chrome and Edge allowed origins equal the receipt IDs exactly.

## R33-H3: Advertised censorship-bypass mirrors are dead

**Severity:** High
**Affected:** Web availability and censorship circumvention

Read-only probes returned:

| Origin | Result |
|---|---|
| `https://winsvpn.pages.dev/` | 200 |
| `https://winsvpn.web.app/` | 404 |
| `https://winsvpn.firebaseapp.com/` | 404 |
| `https://github.com/winsvpn/winsvpn/releases` | 404 |

`web/mirrors.txt`, `_worker.js`, `index.html`, and transactional account email copy advertise these dead origins. A censored user can be directed to a guaranteed failure.

### Exact immediate code fix

Until Firebase and a real GitHub repository are live, replace `web/mirrors.txt` with:

```text
# Win's VPN website mirrors: alternative routing for censorship circumvention.
# One verified HTTPS origin per line. Do not advertise an origin until both its
# root document and releases/downloads.json return the expected WinsVPN content.
https://winsvpn.pages.dev
```

Remove the two Firebase origins from `allowedOrigins` in `web/_worker.js`. Replace the three-entry `censorBypassMirrors` array with:

```js
const censorBypassMirrors = [
  { name: "Cloudflare Pages", url: "https://winsvpn.pages.dev" },
];
```

Replace the notice at `web/index.html` with:

```html
<p class="notice-line"><strong>Save our mirror link.</strong> <span>If winsvpn.org is blocked, use <a class="mirror-link" href="https://winsvpn.pages.dev">winsvpn.pages.dev</a>.</span></p>
```

Remove the GitHub release fallback at the download renderer. Keep unavailable releases unavailable rather than synthesizing a dead URL. Remove dead mirror links from the account email template in the control-plane script.

### Verification

```bash
for url in \
  https://winsvpn.pages.dev/ \
  https://winsvpn.pages.dev/releases/downloads.json; do
  test "$(curl -L -sS -o /dev/null -w '%{http_code}' "$url")" = 200
done
! rg -n 'winsvpn\.web\.app|winsvpn\.firebaseapp\.com|github\.com/winsvpn/winsvpn/releases' \
  web server/wins_control_plane_setup_ONETOUCH.sh
python3 tools/website_security_audit.py
```

Expected: every advertised origin returns 200 and no removed origin remains in public copy or email.

## R33-H4: Android app-held kill switch is released before replacement

**Severity:** High
**Affected:** Android when the user arms the app-level kill switch but OS always-on lockdown is not conclusively active

`executeTunnelTeardown` deliberately retains the active TUN or establishes a blocking TUN. A later `ACTION_CONNECT` calls `resetTunnelBeforeConnect()`, which unconditionally closes `vpnInterface` before either the ordinary builder at line 1463 or the v3 staged builder at line 2687 establishes a replacement. That reopens the physical route during startup. The OS-level lockdown branch can cover this only when the platform conclusively reports this app as always-on with lockdown. The app-held fallback exists specifically for all other armed states.

### Exact targeted fix

Add this field:

```kotlin
@Volatile
private var retainedKillSwitchInterface: ParcelFileDescriptor? = null
```

Replace the close in `resetTunnelBeforeConnect` with:

```kotlin
val mustRetainBlock = KillSwitchPolicy.mustHoldBlockingInterface(
    killSwitchArmed = isKillSwitchArmed(),
    apiLevel = Build.VERSION.SDK_INT,
    alwaysOnPackage = androidKillSwitch.readAlwaysOnVpnPackage(),
    lockdownEnabled = androidKillSwitch.readLockdownEnabled() ?: false,
    ourPackage = packageName,
)
if (mustRetainBlock) {
    retainedKillSwitchInterface?.close()
    retainedKillSwitchInterface = vpnInterface
} else {
    vpnInterface?.close()
}
vpnInterface = null
```

Immediately after each successful replacement `Builder.establish()` and after assigning the new `vpnInterface`, close the old holder:

```kotlin
retainedKillSwitchInterface?.close()
retainedKillSwitchInterface = null
```

In every terminal teardown, after a replacement blocking interface is confirmed or OS lockdown is confirmed, close and null the retained holder. Do not close it on a failed connect unless another blocking interface is already live.

### Verification

Add a fake descriptor owner test that records close order. Expected order: old blocking TUN open, new tunnel establish success, new TUN assigned, old blocking TUN close. On establishment failure: old blocking TUN remains open. Then run:

```bash
./android/gradlew -p android testPhoneDebugUnitTest --no-daemon
flutter test --no-pub test/android_vpn_launch_guard_test.dart
```

A physical test must inspect routes continuously during reconnect with OS lockdown off. No sample may show neither a full tunnel route nor a blocking TUN route.

## R33-M1: Hub admission holds SQLite writer lock across remote node I/O

**Severity:** Medium
**Affected:** Kansas Hub write latency and availability

The old revocation-outbox defect is fixed: its SSH call now runs between two short transactions. However, `_verify_account_sync` opens `BEGIN IMMEDIATE`, mutates authority, then invokes `sync_peer_to_node` and one or two `sync_winn3_registry_to_node` calls before commit. Each remote call can wait 10 to 20 seconds. Since SQLite permits one writer, one slow gateway blocks payment settlement, login mutations, revocation, and administration.

The v3 publication comment intentionally holds this lock to preserve authority ordering. That preserves security but sacrifices fleet-wide write availability.

### Production fix design

Use a durable admission-intent state machine, not an unlocked direct SSH call:

1. Under `BEGIN IMMEDIATE`, validate authority, reserve device or replacement state as `preparing`, assign a monotonic revision, and write AWG and v3 publication jobs into a durable node-mutation outbox. Commit.
2. Drain each node job without a database lock. Node writes must use compare-and-swap revision files so an older job cannot overwrite a newer registry.
3. Under a second short writer transaction, verify account, device token hash, expiration, location, assignment revision, and job acknowledgments are unchanged. Commit `active`, consume the activation secret, and return credentials.
4. On timeout or uncertain acknowledgment, leave the admission retryable and queue reconciliation. Never return a credential until all node acknowledgments match the same revision.

This is the same pattern already used by Double VPN readiness and payment outboxes. It is larger than a safe one-function patch.

### Verification

Create a test whose mocked node call blocks for 15 seconds. During that block, a second SQLite connection must acquire `BEGIN IMMEDIATE` and commit an unrelated payment event in under 250 ms. A stale acknowledgment must fail revision comparison and never activate the device.

## R33-M2: Gateway logs authenticated peer public keys and inner addresses

**Severity:** Medium
**Affected:** Privacy and linkability

`peer_registry.go` prints base64 static public keys for both authorized and unauthorized authenticated identities and prints authorized inner addresses. Public keys are not secret, but they are long-lived account-linked device identifiers. Persisting them in journald conflicts with the no-activity, minimized-metadata posture and gives a gateway log reader a direct client identity timeline.

### Exact fix

Replace `authorize` with:

```go
func (r *peerRegistry) authorize(peer []byte) error {
	if err := r.reload(); err != nil {
		fmt.Fprintln(os.Stderr, "winn3-gateway: peer registry reload failed")
		return err
	}
	if _, ok := r.innerForPeer(peer); !ok {
		return errPeerNotAuthorized
	}
	return nil
}
```

Remove the now-unused `encoding/base64` import if no other site uses it.

### Verification

```bash
cd winn_protocol_experimental
go test -count=1 -race ./cmd/winn3-gateway
! rg -n 'authorized peer: addr=|peer not authorized: key=' cmd/winn3-gateway
```

Expected: tests pass and no key or inner address is printed on authorization.

## R33-M3: Apple cancellation can expose clear traffic after the tunnel goes down

**Severity:** Medium
**Affected:** iOS and macOS disconnect and crash windows

`enforceRoutes=true` and `excludeLocalNetworks=true` are correctly set. `includeAllNetworks` is deliberately false. Those flags protect routing while the provider is active. They are not a post-crash kill switch. The iOS memory watchdog calls `super.cancelTunnelWithError` when sampling fails or footprint reaches 15 MiB. No `isOnDemandEnabled` or `onDemandRules` configuration exists. A provider crash or self-cancel therefore returns the host to ordinary networking.

The Round 33 source correctly narrowed the watchdog to Winn sessions. It did not close the tunnel-down exposure.

### Fix

For users who enable the kill switch, configure `NEOnDemandRuleConnect` before saving the manager and set `isOnDemandEnabled=true`. Provide an explicit user-visible opt-out and test local-network exclusions. The exact AppDelegate insertion after assigning the protocol is:

```swift
if killSwitchRequested {
  let connect = NEOnDemandRuleConnect()
  manager.onDemandRules = [connect]
  manager.isOnDemandEnabled = true
} else {
  manager.onDemandRules = nil
  manager.isOnDemandEnabled = false
}
```

`killSwitchRequested` must come from authenticated local settings, not server configuration. Save, reload, and verify both values before starting.

### Verification

Terminate the PacketTunnel process while traffic generation runs. Expected: no clear-path packet, system reconnects, and the manager reload reports on-demand enabled with one connect rule. This requires physical iOS and macOS testing.

## R33-M4: Hub privilege and SSH custody are concentrated in the web process

**Severity:** Medium
**Affected:** Control-plane blast radius

The hub unit runs `User=root`, grants `CAP_NET_ADMIN`, and makes `/root/.ssh` writable. It also parses Internet-facing JSON and payment webhooks. Any remote-code-execution defect reaches fleet management keys and host network authority.

### Fix design

Split privilege:

1. Run FastAPI as `wins-hub` with no capabilities, `ProtectHome=true`, and writable access only to its database, outbox, and log directories.
2. Move peer and registry mutations to a root helper service over a root-owned Unix socket.
3. Define a closed binary or strict JSON contract containing only node ID, operation, peer public key, allowed inner address, and revision.
4. The helper owns SSH credentials, validates node IDs against a root-owned map, rate-limits calls, and never accepts arbitrary commands or hosts.
5. Return an acknowledgment revision. FastAPI records it through the outbox state machine in R33-M1.

A one-line `User=` change would break required functionality and is not production-ready. Treat the service split as one atomic migration.

## R33-M5: Cloudflare Pages uses isolate-local payment rate limits

**Severity:** Medium
**Affected:** Translation, AI, wallet, Monero, and BTCPay order abuse controls

`requireQuota` uses a Worker binding if available, but the current Pages deployment cannot bind the declared rate-limit namespaces. The live fallback is a per-isolate Map. Attackers distributed across isolates and regions can exceed the nominal 20 per minute. The hub adds its own persistent limits on many paths, reducing impact, but the edge does not provide the stated global bound.

### Fix

Configure zone WAF rate-limit rules for exact routes, at least `/pay/wallet/create-order`, `/pay/wallet/capture`, `/pay/monero/create-order`, `/pay/crypto/create-invoice`, `/api/site/translate`, and `/api/site/ai-chat`. Export a redacted Cloudflare ruleset receipt into release evidence. Alternatively migrate to the documented Worker target only after replacing all placeholder namespace IDs and adding the ASSETS binding.

### Verification

From two regions, send only harmless GET requests to a test route or use a non-production staging zone. Confirm a shared counter and 429 after the configured aggregate threshold. No production payment order should be used as a load test.

## R33-M6: macOS footprint compliance is not demonstrated

**Severity:** Medium
**Affected:** macOS stability claims and Apple memory evidence

macOS now allows unknown available headroom and records `phys_footprint`, which is appropriate because the iOS jetsam constraint does not apply directly. However, unlike iOS, it does not enforce the project 15 MiB ceiling. Existing fleet evidence repeatedly says the memory sample was unavailable or reflects older code. The current tree has no physical high-throughput proof of bounded Mac footprint.

### Fix

Decide the policy. If 15 MiB is truly cross-Apple policy, port the lifecycle-token watchdog to macOS. If it is iOS-only, correct the target requirement and record a Mac-specific cgroup-equivalent or working-set ceiling. Do not claim strict 15 MiB Mac compliance without enforcement and measurements.

### Verification

Run a 30-minute full-duplex test with 64-byte and 1,373-byte packets, rekeys, and handoffs. Sample `TASK_VM_INFO.phys_footprint` each second. Expected result must name peak, p99, allocation rate, drops, and whether the process crossed the selected ceiling.

## R33-L1: Live site is behind the workspace source

**Severity:** Low

The live page is functional and its inline blocks match its own CSP, but `tools/verify_live_deployment.py` reports 8 pass and 1 fail because live CSP differs from `web/_headers`. Live HTML SHA-256 differs from workspace HTML. This is drift, not a live CSP execution failure.

### Fix and verification

After all web findings are resolved and owner deployment approval exists, deploy one clean staged tree through the existing release procedure. Then run:

```bash
python3 tools/verify_live_deployment.py
```

Expected: 9 pass, 0 fail. No deployment was performed in this audit.

## R33-L2: Website gate misses generic dead GitHub and mirror URLs

**Severity:** Low

`website_security_audit.py` passes 56 checks while `web/index.html` contains `github.com/winsvpn/winsvpn/releases/download/` and `mirrors.txt` advertises three 404 origins. Its stale marker only knows the older `winsvpn-downloads` repository string.

### Exact fix

Add:

```python
GITHUB_RELEASE_URL_RE = re.compile(
    r"(?i)github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases(?:/download/|/?$)"
)
```

Inside `public_download_marker_errors`, after the stale-marker loop, add:

```python
        for match in GITHUB_RELEASE_URL_RE.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            errors.append(
                f"{path.relative_to(web_root)}:{line} contains a GitHub releases URL; "
                "GitHub is backup-only until a live immutable release is verified"
            )
```

Add a separate read-only mirror checker to deployment CI. Never make ordinary unit tests depend on public network health.

## R33-L3: `/pkg/` loses inherited security headers

**Severity:** Low

Nginx `add_header` inheritance is all-or-nothing at a child location. `/pkg/` adds Content-Type and Content-Disposition, so the server-level HSTS, nosniff, frame, referrer, and permissions headers are not inherited.

### Exact fix

Replace the block with:

```nginx
location /pkg/ {
    try_files $uri =404;
    access_log off;
    expires 4h;
    default_type application/octet-stream;
    add_header Content-Disposition "attachment" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

Expected live HEAD on a known package: all six headers present.

## R33-L4: Dirty-tree and test-oracle failures

**Severity:** Low

`git diff --check` exits 2 with trailing whitespace in Android Winn v3 source and tests plus an extra EOF line in `carrier/pipe.go`. Full Flutter tests finish at 1,928 passed, 3 skipped, and 2 failed. Both failures are tracked-reference integrity failures caused by current tracked and untracked state. The server Round 10 suite contains one stale oracle that still expects the old writer-lock behavior, even though production correctly removed it.

### Fix

Remove reported trailing whitespace. Stage every production file and every required test, or remove untracked references. Update the Round 10 test to assert that a concurrent writer **can** acquire `BEGIN IMMEDIATE` during mocked peer removal. Do not hide failures with skips.

### Verification

```bash
git diff --check
flutter test --no-pub
python3 -m pytest -q server/test_control_plane_round10.py
```

Expected: all return 0.

## R33-L5: Apple resolver ordering verifier invocation is misleading

**Severity:** Low

Running `python3 tools/verify_apple_resolver_route_ordering.py` reports no resolver loop because the script iterates only over supplied paths. Source ordering is correct on both platforms.

### Fix

Add defaults when `sys.argv[1:]` is empty:

```python
paths = sys.argv[1:] or [
    "ios/PacketTunnel/PacketTunnelProvider.swift",
    "macos/PacketTunnel/PacketTunnelProvider.swift",
]
for path in paths:
```

Replace `for path in sys.argv[1:]:` with that code. Expected no-argument result: two PASS lines and exit 0.

## R33-L6: Native tvOS client does not exist

**Severity:** Low for the present release, product gap for the user-requested all-target scope

The repository ruling explicitly places tvOS after the current release. There is no tvOS Xcode target or PacketTunnel target. Website copy honestly says the native app is unavailable and offers WireGuard or router setup. Flutter D-pad tests cover television UI abstractions, not a tvOS product.

### Fix

Create a distinct Apple TV application and PacketTunnel target with tvOS entitlements, focus-engine UI, background lifecycle tests, App Store metadata, and release gates. Do not add tvOS to current release claims until physical Apple TV carriage and wake tests pass.

## 4. Platform-by-platform assessment

### Windows x86 and ARM64

**Assessment:** No new exploitable defect verified statically. Physical and cross-architecture execution not performed.

Positive findings:

- UI and LocalSystem core are separated by `WINS_TUNNEL_SERVICE_CORE`.
- The pipe uses `ProtectedPrefix\Administrators`, one instance, message mode, nonblocking bounded reads, and `PIPE_REJECT_REMOTE_CLIENTS`.
- Start and stop authority verifies active console PID, exact `wins_vpn.exe` image path, client process liveness, client session, impersonated user type, and successful `RevertToSelf`.
- Pipe clients use `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`.
- Child processes launch suspended into kill-on-close Job Objects. Failed assignment terminates the child directly. Timeout kills the job.
- `sc.exe` resolves through `GetSystemDirectoryW`.
- Windows network refresh infrastructure exists in `windows_split_tunnel.cpp` through address, interface, and route change notifications.

Caveat: `RunCommand` passes a null application name and a full quoted command line. System tools inspected in this path are absolute, but each new caller must preserve that invariant.

Verification run: Windows runtime validation 31 tests passed. Windows ARM64 readiness 8 tests passed.

### Linux x86 and ARM64

**Assessment:** Static hardening is strong. Runtime timeout and FD tests were mostly skipped because this host is macOS.

Positive findings:

- `RunArgv` uses `posix_spawn`, a process group, nonblocking output, monotonic deadline, SIGTERM then SIGKILL, bounded capture, and handle cleanup.
- Root-owned paths are canonicalized with `realpath` and the BPF helper leaf is validated.
- SIGINT, SIGTERM, SIGHUP, and SIGQUIT converge on tunnel shutdown.
- Installed recovery service includes `NoNewPrivileges`, `ProtectSystem=strict`, capability bounds, and restricted address families.

Gaps:

- No production default-route change watcher or socket rebind path was found in `linux_tunnel_backend.cc`. Reconnect is reactive at session failure, not an immediate route re-anchor.
- Nine Linux `RunArgv` dynamic tests skipped on this non-Linux host.

Linux shutdown source test passed. Deployment script validation passed.

### macOS x86 and ARM64

**Assessment:** Route posture and entitlements are good. Current load memory behavior is unverified.

Positive findings:

- `enforceRoutes=true`, `excludeLocalNetworks=true`, and `includeAllNetworks=false` are explicit and re-save verification code exists.
- Resolver IPv4 `/32` routes are appended before assigning copied `ipv4Settings`.
- Release app and extension are sandboxed. Release omits JIT and server entitlement from the app.
- Existing fleet evidence shows promoted full-tunnel carriage and 135.7 Mbps median through an older tree.

Gaps: R33-M3 and R33-M6. No `NWPathMonitor` or `wgBumpSockets` production path was found. Carrier rebinding remains dominated by R33-H1.

### Android x86, ARM64, and Android TV

**Assessment:** Mobile lifecycle and manifest coverage improved materially. Kill-switch replacement order remains unsafe.

Positive findings:

- TV manifest has leanback and touchscreen with `required=false`, a banner, and `LEANBACK_LAUNCHER`.
- Mobile remains installable without leanback requirements.
- VpnService is permission-protected and not exported.
- Winn and AWG sockets call `protect()` and fail closed.
- Xray is refused before DNS or process launch on Android.
- Split-tunnel package application errors throw and stop start.
- Network callback handles availability, loss, capability, and link property changes. Boolean `setUnderlyingNetworks` results are checked on runtime refresh.
- Wake lock is startup-bounded to 60 seconds. No five-second full-session lock exists.

Gap: R33-H4. Also, `applyUnderlyingNetworkHints(builder)` ignores the Builder return value, while runtime refresh checks it. This is a low-risk diagnostic inconsistency because builder application is validated later by tunnel carriage, but it should be made explicit.

Phone JVM build and tests passed.

### iOS and tvOS

**Assessment:** iOS security posture is largely coherent. Physical production throughput and crash-kill-switch behavior are not proven. tvOS is absent.

Positive findings:

- `enforceRoutes=true` and `excludeLocalNetworks=true` are set.
- Resolver route copy ordering is correct.
- iOS watchdog is armed only for Winn, starts immediately, samples physical footprint each second, and cancels at or above 15 MiB or on sample failure.
- Existing committed device evidence reached carrying in a contained dev session with a 12,419,896-byte footprint sample, below 15 MiB.
- Six watchdog tests passed.

Gaps: R33-M3 and R33-L6. Existing iOS evidence did not run sustained production full-tunnel throughput. No current physical proof of the 15 MiB ceiling under high packet rate exists.

### Browser extensions

**Assessment:** Runtime design is defensive. Release packaging is blocked.

Positive findings:

- Chromium and Edge use MV3 service workers. Firefox uses an MV3 event page. Safari uses a nonpersistent background page.
- All listeners register synchronously. Alarm and startup recovery exist. Initialization rejection resets the ready promise.
- Chromium uses mandatory PAC and no in-scope DIRECT fallback. PAC catches exceptions and returns the proxy.
- Firefox rechecks optional host permissions on events and every alarm.
- Native host credentials require authorized origins. Bearer authorization is not used.
- No `innerHTML`, `eval`, `Function`, inline event handlers, em dash, or en dash was found in extension source or manifests.

Gaps: R33-H2. The Firefox fail-closed sink is an in-memory listener and is reconstructed on wake through reconciliation. I did not reproduce a termination interval leak in real Firefox this round.

### Control plane and data plane

**Assessment:** Payment and authority logic is strong, but long database lock scope and root privilege remain.

Positive findings:

- WAL result is checked. NORMAL synchronous, foreign keys, and 30-second busy timeout are applied.
- Activation keys use `secrets.token_urlsafe(32)`, server-peppered HMAC, expiry, and compare-and-set single-use consumption.
- ISO parsing normalizes offsets to UTC. Lifetime is exactly ten calendar years.
- Payment webhooks re-fetch provider state and bind settlement to hub-created order provenance.
- Activation email is an encrypted durable outbox with leases and retry.
- Revocation SSH is no longer under the writer lock.
- Dedicated firewall chains and `iptables-restore --noflush` are used by deployed paths.
- Data-plane MTU and MSS rules cover `awg0`, `amn0`, and `winn3gw0` with MSS 1240. Core clamps MSS 1240.

Gaps: R33-M1, R33-M4, R33-L3. `server/final_iptables_requested.txt` still contains global flush commands. It is not a deployed script but must never become one.

### Shared Dart protocol policy

**Assessment:** Anti-downgrade policy is strongly represented and tested.

- Winn v3 is selected first where a valid signed descriptor and capability exist.
- A refused v3 configuration does not fall through to AWG.
- v1 order is AWG first, Xray second.
- v1 fallback requires exact generation-bound ordinary v3 failure authorization.
- Flutter analyzer passed.
- Full test suite failed only the two repository-integrity tests, not protocol behavior tests.

### Live website, DNS, payments, and provisioning

**Assessment:** The reported crypto click defect is closed on the live page. Availability and deployment custody are not closed.

- A real Edge browser click expanded the one-month automated crypto row. BTC, Dash, and XMR were enabled. Clicking XMR opened the Monero email panel. The static donation modal remained hidden.
- Live `GET /api/site/crypto-config` returned HTTP 200 with both capability booleans true. No order endpoint was called.
- The static donation addresses remain in a separate modal for donation-drawer controls. Plan coin buttons now search the automated row and call `renderCryptoUnavailable` when no provider control exists. They do not call `openModal`.
- Live inline scripts and style are pinned by the live CSP. No CSP violation was observed in the browser log. Edge emitted PayPal Tracking Prevention storage warnings, which are browser privacy interventions rather than CSP failures.
- Public DNS returns Cloudflare A and AAAA addresses. TLS verification passed with a Google Trust Services certificate valid for `winsvpn.org` during the probe window.
- Payment creation, settlement, single-use setup key generation, ten-year lifetime semantics, and transactional delivery are implemented at the hub. Provider settlement is re-fetched and bound to a hub-created order before account grant.
- Cloudflare dashboard record ownership, WAF rules, and cache-rule configuration could not be inspected. Public effects only were measured.

Open findings: R33-H3, R33-M5, R33-L1, and R33-L2.

### Double VPN core

**Assessment:** Static fail-closed architecture is strong. No live AICORE or dual-hop run was performed.

- LUKS is the default. Substitute posture requires explicit operator acceptance and encrypted swap or no swap.
- Core forwarding enters `WINVPN-CORE-EGRESS`, which returns only for the encrypted exit interface or reviewed prefix and drops everything else.
- Authority rules use UTC date windows and terminal DROP.
- Inner traffic is MSS-clamped to 1240.
- Identity and key persistence variables are present. Assignment envelope parsing is strict.
- Control plane has enrollment leases with 409 and `Retry-After: 5`, assignment revisions, readiness acknowledgment, and post-readiness authority revalidation.

Could not verify AICORE address `192.168.50.10`, 92 GB RAM, GPU model, container health, or live fail-closed routing.

### Gemma Smart Router

**Assessment:** Offline contract is solid. Live runtime is unverified.

- Explicit route returns before AI after closed-set eligibility checks.
- Initiation is deterministic.
- Distress uses local Gemma, then Gemini, then deterministic scoring.
- HMAC signs method, path plus raw query, timestamp, nonce, and exact-body SHA-256.
- Minimum secret length is 32. Authorization Bearer is inert.
- Replay journal enforces owner, 0700 parent, 0600 file, one link, 10,000 entries, 16 MiB, and 2,000 ms timeout.
- Output schema forbids extra fields, nonfinite values, invalid route IDs, and more than three snake-case reason codes.
- Router unit binds 127.0.0.1:8090 as `aicore:aicore` with strong syscall and filesystem restrictions.
- vLLM unit binds 127.0.0.1:8002 and grants only NVIDIA devices.

Router tests: 422 passed, 1 skipped. The checked-in receipt is offline only. Preflight could not run without `/usr/bin/python3.14`.

## 5. Performance assessment

### Fresh measurements

On Apple M5 Max:

| Boundary | Result |
|---|---|
| Core batch, 1 packet | 534.16 MB/s, 0 B/op, 0 allocs/op |
| Core batch, 8 packets | 549.16 MB/s, 0 B/op, 0 allocs/op |
| Core batch, 32 packets | 672.21 MB/s, 0 B/op, 0 allocs/op |
| Driver plus batch carrier loop | 93.71 MB/s, 24,434 B/op, 55 allocs/op |

The core crypto work is no longer the immediate bottleneck. The full driver loop is about seven times slower than the 32-packet core boundary and still allocates. Optimize frame assembly, queue handoff, and carrier loop ownership before more ChaCha tuning.

`go test -race` initially hit one 20-second reconnect establishment timeout under concurrent audit load. The isolated test passed three of three in about 0.11 to 0.12 seconds each, and a full rerun passed all targeted packages. This is load sensitivity in the test, not a verified product regression, but it weakens deterministic CI confidence.

### Existing physical evidence

Committed fleet-v4 evidence, from older source:

- Android: 47.8 Mbps baseline, 10.2 Mbps tunneled, 78.6 percent throughput loss.
- Linux: 626.8 Mbps baseline, 137.6 Mbps tunneled, 78.0 percent loss.
- Windows: 644 Mbps baseline, 80.4 to 123.1 Mbps tunneled.
- macOS: 457.7 Mbps median baseline, 135.7 Mbps tunneled.
- iOS: carrying proof only, no full-tunnel speed.

These are not acceptable as proof of zero-packet-drop wire speed for the current tree. They do show that host integration, cloud path, and queueing dominate core crypto.

### Recommended optimization sequence

1. Fix R33-H1. Performance on a route that cannot roam is not product performance.
2. Add end-to-end pprof, trace, syscall, and queue-depth collection at Android TUN, frame host, UDP carrier, gateway front door, Linux TUN, and Apple packet arrays.
3. Remove the 24 KB and 55-allocation driver-batch-loop cost. Reuse frame vectors and output slots after proving no lifetime escape.
4. Preserve small-batch inline crypto. Fresh data confirms its value.
5. Keep `SO_RCVBUF` and `SO_SNDBUF` readback metrics and recvmmsg or sendmmsg batching. Test Android adopted connected sockets on each ABI.
6. Keep MTU 1280 and MSS 1240 for Double VPN and carrier-safe server boundaries. Winn standalone currently advertises path MTU 1450 in some fleet evidence. That is valid only with negotiated minimum and a host MTU apply callback. Test 1280, 1360, 1380, 1420, and 1450 paths plus NAT64.
7. Do not install a fixed five-second keepalive. Winn v3 uses randomized silence and liveness probes. AWG remains 25 seconds. Measure radio wakeups and battery before changing either.
8. Add session-count and packet-rate stress with cgroup memory. Gateway MemoryMax derivation is thoughtful, but its default 64-session address-keyed binary is not the token-index design the memory model assumes.

## 6. Test and command ledger

| Command | Result |
|---|---|
| `python3 tools/verify_live_deployment.py` | 8 pass, 1 fail: live CSP differs from source |
| Headless Edge live crypto interaction | PASS: plan and XMR panel clickable, donation modal hidden |
| Live `GET /api/site/crypto-config` | 200, both providers enabled |
| DNS and TLS inspection | PASS: A and AAAA present, valid Google Trust Services certificate |
| `python3 tools/website_security_audit.py` | 56 pass, 1 skip, 0 fail |
| `python3 extension/build.py` | Refused, exit 3: owner identity receipt missing or stale |
| `python3 -m pytest -q extension/tools` | 553 pass, 3 fail, 12 errors |
| Extension dash scan | 0 files |
| `python3 -m pytest -q router/tests` | 422 pass, 1 skip |
| `router/install_aicore_router.sh --preflight` | Could not run: `/usr/bin/python3.14` missing |
| `bash tools/verify_rulings.sh` | 59 repository and 6 Apple checks passed |
| Linux shutdown source harness | PASS |
| Linux RunArgv dynamic harness | 9 skipped, Linux required |
| iOS memory watchdog tests | 6 passed |
| Apple resolver verifier without arguments | FAIL due tool invocation defect, source ordering manually verified correct |
| Android phone JVM suite | Build successful |
| Windows validation | 31 passed |
| Windows ARM64 readiness | 8 passed |
| Winn v3 targeted race suite, first run | One reconnect timeout |
| Winn v3 isolated reconnect under race | 3 of 3 passed |
| Winn v3 targeted race suite, rerun | All targeted packages passed |
| Gateway authenticated rebind defect test | PASS, confirming the defect |
| Flutter analyze | 0 issues |
| Full Flutter tests | 1,928 passed, 3 skipped, 2 integrity failures |
| Server Round 10 to 12 and payment authority | 40 passed, 1 stale-oracle failure |
| Deployment script validator | 3 roles, 300 heredocs, 36 Python blocks, 58 Bash helpers, 90 units passed |
| Shell syntax and Python compile | PASS |
| `git diff --check` | FAIL, trailing whitespace and EOF defect |

## 7. Release acceptance gates

A release candidate is not acceptable until all of these hold:

1. R33-H1 is replaced by an address-independent gateway and a physical handoff proof.
2. Android has make-before-break blocking-interface replacement when its app kill switch supplies the block.
3. Every advertised mirror is live, content-identified, and monitored.
4. Extension build exits 0 with current owner receipts and pinned esbuild, and all extension tests pass.
5. Hub admission remote I/O no longer holds the global SQLite writer lock.
6. Peer identity logs are removed.
7. Full Flutter, server, race, extension, router, Windows, Apple, and Linux tests pass from a clean immutable tree.
8. Android, iOS, macOS, Windows x86, Windows ARM64, Linux x86, and Linux ARM64 release artifacts run sustained bidirectional tests with MTU sweeps, handoffs, rekeys, DNS leak probes, memory sampling, and teardown verification.
9. Double VPN runs physically through AICORE to at least two exits while the direct underlay is packet-captured and proven dark.
10. Live site equals the reviewed source and the live verifier reports 9 of 9.

## 8. Bottom line

WinsVPN has many serious safeguards. The cryptographic and authorization layers are much stronger than the remaining lifecycle code. Yet the remaining gateway rebind defect strikes the exact mobile-resilience promise under audit: a legitimate authenticated session can move networks, lose all full-size traffic, and still report carrying. Release packaging and censorship mirrors also fail their own gates. Those are release blockers.

