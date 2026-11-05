# Round 36 stage2: claude-opus5

# ROUND 36 TURN 2: ADVERSARIAL CROSS-EXAMINATION (SEAT 2, CLAUDE)

## 0. Procedural note before the substance

Seat 3's verdict as circulated to me terminates mid-F-12, inside the `cmd_rollback` fix block, at the literal string `iptables -S FORWARD 2`. Seat 3 declared 15 findings (4 P0, 8 P1, 3 P2); I received 12. Under 13.5 this is a truncated podium response and gets one retry with an adjusted token budget. F-13, F-14, and F-15 from Seat 3 are absent from my context, I have not voted on them, and my Turn 3 ballot cannot cover them until the Arbiter recirculates. I am not treating their absence as withdrawal.

---

## 1. Steelman: Seat 1 (Antigravity)

Seat 1 read the packet as an operator would, not as a code reviewer would. Where I asked "is this line correct," Seat 1 asked "what is the state of the machine after this line runs." That produced three things I did not get to.

The firewall and forward-mode findings (their F-5, F-10) come from a defensible reading: both flags default to the permissive or inert value, both defaults are justified in the source comment by an appeal to the current state of one specific node ("on the fleet's only node the host INPUT policy is ACCEPT"), and a default chosen to match one host's accident is not a default, it is a hardcoded assumption about a fleet of size one. Seat 1 is right that the shape is wrong. I disagree only about which direction the correction runs.

Their F-7 (missing `MONERO_*` keys in `server/hub-commerce.env.example`) is the kind of finding that only appears if you trace the handoff rather than the file. The Spain script emits three variables the hub must consume; the hub's own template documents four BTCPay variables and none of the Monero ones. That is a real seam, and it is exactly the seam where an operator pastes a secret into the wrong file.

**Strongest single point in Seat 1's verdict: F-18, the untrusted third-party Monero daemon.** `--daemon-address nodes.hashvault.pro:18081 --untrusted-daemon` means a third party learns the payment node's IP address, its uptime pattern, and the block and output ranges a view-only wallet for this organization queries. `--untrusted-daemon` protects the wallet from being lied to; it does nothing about what the daemon operator observes. For a service whose entire proposition is that it does not observe its users, outsourcing the payment node's chain view to a public pool node is a contradiction at the root, and none of the other three of us caught it. I am adopting it.

## 2. Steelman: Seat 3 (Sol Pro)

Seat 3 audited the distance between what a control asserts and what it actually covers, and did it with arithmetic attached. That is the discipline the protocol asks for and it produced the best new findings of the round.

Their F-6 is the clearest example. I looked at `verifyAndroidReleaseEngineInputs` and said "this checks existence, not provenance." Seat 3 looked at the same function and noticed the check is not even sound for existence: `candidates.none(::isSafeNonEmptyReleaseInput)` passes when any candidate is safe, but Gradle packages the release source set's file when one is present. A zero-length or symlinked `src/release/jniLibs/<abi>/libwinnengine.so` sitting next to a valid `src/main` copy satisfies the gate and ships the wrong file. My digest manifest does not fix that on its own, because it would also be free to hash whichever candidate it happened to pick first. The selection has to be corrected before the provenance check means anything. That is a genuine correction to my F-8, not an addition to it.

Their F-8 and F-9 (unvalidated `. "${WINS_DEFAULTS_FILE}"` under `set -a` in the control plane and data plane installers, while a sibling installer in the same tree validates owner, mode, and file type before sourcing) is the strongest kind of finding available in a shell audit: the repository already contains the correct pattern, so the defect is drift, not ignorance, and the fix is a copy.

**Strongest single point in Seat 3's verdict: the fail-open quota chain, F-3 and F-4 together.** The packet states that Cloudflare Rate Limiting bindings are a Workers-only feature and that this site is served by Pages Direct Upload. That is not a hypothesis about production, it is documented in the repository's own comment block. It follows deductively that `env[bindingName]` is undefined in production, that `requireQuota` therefore always falls through to the isolate-local `Map`, and that the isolate-local `Map` is the same structure I showed in my F-27 can be reset by a client that forces eviction. Seat 3 then found the route that has no quota call at all, and attached the count: 366,503,875,925 distinct tile paths across zoom 0 through 19, which I rechecked from first principles as `(4^20 - 1) / 3` with `4^20 = 1,099,511,627,776`. The arithmetic is correct. My F-27 treated the isolate-local limiter as the fallback; Seat 3 proved it is the only thing there.

---

## 3. Position changes, per finding

### Positions I change

**My F-2, split.** Seat 1 (F-3) and Seat 3 (F-7) both raised `QUERY_ALL_PACKAGES` as a standalone P0. I had folded it into the camouflage finding as item 2 of three. Two independent seats treating it as its own defect is the signal that burying it was wrong: the permission is a submission-blocking policy exposure and a fingerprint independent of whether the launcher alias is fixed. Split out as its own finding below.

**My F-3, merged with Seat 3 F-2.** Seat 3 is right that `install -o root -g root -m 0600` on the unit is the deterministic fix for the umask exposure, and that it does not depend on any assumption about systemd's expansion semantics. My `EnvironmentFile` form keeps the secret out of the unit file entirely, which is better if it works, and depends on systemd performing partial `${VAR}` substitution inside a larger argument word (UNVERIFIED-LIVE for the pinned systemd on the Spain node). Merged fix below uses `EnvironmentFile` with an explicit verification command and names Seat 3's inline form as the fallback if that verification fails. I also note that Seat 3's replacement unit reproduces `--disable-rpc-login=0` and `--confirm-external-bind=0`, which my F-4 argues must go; that is a live disagreement, not a merge.

**My F-5, superseded by Seat 3 F-1.** I proposed pinning the clone to a reviewed commit. Seat 3 proposed removing the network fetch from the privileged installer entirely and requiring a pre-staged, clean, commit-verified checkout. Theirs is strictly better: a pin inside the root script still performs a network operation as root before the pin is checked, and a dirty working tree at the pinned commit still passes a `rev-parse` check. I adopt Seat 3's version including the `diff --quiet` and `diff --cached --quiet` assertions, and keep my `verify-tag` warning as an additive line.

**My F-8, corrected by Seat 3 F-6.** Selection soundness first, then digest provenance. Both, in that order, in one function.

**My F-9, fix replaced by Seat 1 F-4.** I proposed gating the exported receiver with `android:permission`. Seat 1 proposed deleting the receiver and its intent filter, moving the trigger into the calculator UI digit sequence. Seat 1 is right and my fix was half a measure: `android:permission` constrains the caller's permission, not its identity, the manifest literal `9467` remains a readable product fingerprint in `aapt dump badging` output regardless of any permission, and the calculator surface already exists as an input path. Deletion removes the export, the fingerprint, and the third-party trigger in one edit. One correction to Seat 1's evidence: their quoted block contains `<action android:name="android.intent.action.MAIN" />` inside the intent filter, which does not appear in the manifest text I was given. The deletion must be applied against the actual file, not against the quoted block.

**My F-13 and F-14, arithmetic accepted from Seat 3 F-5, expression kept.** Seat 3 reached the identical two defects independently (`cmd_deploy` never calls `verdict`; the Python `fails` counter is written and never read). Their `result = "PASS" if fails == 0` is cleaner than my conjunction only if every one of `carrying`, `ok_inner`, and `ok_nat` is recorded through `rec()`. The packet shows `rec("tcp-9111-connect", ...)`, `rec("seam-port", ...)`, and `rec("client-rx-packets>0", ...)` but does not show a `rec()` call for the handshake, inner-ICMP, and NAT-ICMP booleans themselves. I keep the conjunction `fails == 0 and carrying and ok_inner and ok_nat`, which is correct under both readings, and adopt their point that every early `seam-port` exit must print receipts first.

**My F-27 and F-28, both upgraded.** F-27 gains Seat 3's F-3 and F-4 as the reason the isolate-local limiter matters at all. F-28 gains Seat 3's F-11: `pacToken` reads `endpoint.host` and `endpoint.port` without ever calling `validateEndpoint`, so the file's "final assertion" is not on the path that builds the PAC script. Their throw and my pinned-constant equality check are complementary and both go in.

### Positions I hold, against an opposing seat

**Against Seat 1 F-5 (flip `WINN3_GATEWAY_MANAGE_FIREWALL` to 1).** The diagnosis is right, the remedy inverts the blast radius. Flipping this default causes the next run of the installer on the fleet's only data plane node to apply a default-drop INPUT policy derived from a rule set the script has never exercised on that host, and Seat 1's own residual risk concedes the lockout. The correct shape is neither default: make the script refuse to run without an explicit setting, and print the host's current INPUT policy in the refusal. Counter-proposal below as a P2.

**Against Seat 1 F-10 (flip `WINN3_GATEWAY_FORWARD` to 1).** Same structure. This flag selects between an in-process reflector and a real forwarder, which is a datapath behavior change on a live node requiring `CAP_NET_ADMIN` and `/dev/net/tun`. Silently defaulting it to forwarding is worse than silently defaulting it to reflecting, because the failure mode is a node that believes it is carrying traffic. Counter-proposal: require the operator to state it.

**Against Seat 3 on severity for the quota findings.** Seat 3 rates the quota fail-open and the unmetered map tile route P0. I rate both P1. The distinction I am drawing: P0 in this audit has meant user exposure or traffic compromise, and these two are cost exhaustion and availability, with no user data leaving and no traffic intercepted. I will vote AGREE on P0 for the quota chain if Seat 3 supplies the monthly spend ceiling on the translate and AI upstream keys and it is low enough that a single client can exhaust it inside one billing period, since at that point key exhaustion takes the public download and support path down and the severity argument carries. That is the falsifiable condition.

### Positions I refute

**Seat 1 F-12 (`wvMatch` negative index) is refuted.** The expression `host.substring(host.length - rule.length - 1)` is guarded by `host.length > rule.length` on the same boolean chain, evaluated left to right with short-circuit. `host.length > rule.length` implies `host.length >= rule.length + 1`, so the index is at minimum 0 and never negative. JavaScript's `String.prototype.substring` also clamps a negative argument to 0, so even without the guard there is no defect, only a different comparison. The proposed `slice` rewrite is a readability change with no behavioral difference. No finding. I note that the real defect in this file is on the rule side, not the host side, which is my F-6: the rules are never normalized, so `wvMatch` is asked to compare a canonical host against a non-canonical rule and correctly returns false.

**Seat 1 F-13 (strip brackets from IPv6 PAC tokens) is refuted, and it introduces a defect.** A PAC return value of the form `PROXY host:port` has no delimiter other than the colon. Emitting `PROXY ::1:1080` gives the browser's PAC result parser no way to find the port boundary. Bracketed IPv6 literals are what Chromium's PAC result parser accepts, and Seat 1 tagged the claim UNVERIFIED-LIVE in their own text. Applying this diff would break the loopback proxy on any IPv6 endpoint. The correct change to `pacToken` is Seat 3's F-11, which I have merged.

**Seat 1 F-17 (`specialUse|systemExempted`) is refuted.** `systemExempted` is reserved for apps holding a specific system exemption category, and declaring a foreground service type requires holding the matching `FOREGROUND_SERVICE_*` permission for each type in the combination. Adding it to a `BIND_VPN_SERVICE` service with no exemption grant adds a permission requirement, a policy declaration obligation, and a plausible review rejection, in exchange for nothing the tunnel needs. `specialUse` alone is the correct declaration for a VPN foreground service. No finding.

**Seat 1 F-19 (flip the enabled-platforms define to include iOS and macOS) is refuted as a finding.** Enabling a protocol on platforms whose engine is neither built nor signed is a feature request, and the proposed base64 edit would ship a platform gate that opens onto code that does not exist in the packet. Seat 1's own residual risk states the Darwin engine must be compiled and signed first. The defensible Apple-domain finding this round is the documentation gap, which is my F-25 in the revised list. No finding.

**Seat 1 F-6, partially refuted on the path choice only.** The defect is the same one I filed. Their replacement default `/var/log/winsvpn/router_decisions.jsonl` does not satisfy `_validate_private_ancestors`, which requires the parent at exactly `0o700`; `/var/log/winsvpn` is created by the server scripts as a conventional log directory and nothing in the packet holds it at 0700. Their fix therefore converts a guaranteed failure into a probable one. `StateDirectory=` with `StateDirectoryMode=0700` is what makes the mode an enforced property of the unit rather than a hope about the filesystem. My path stands.

---

## 4. REVISED FINAL FINDINGS

### P0

---

**F-1 | Domain E | Third-party analytics and advertising endpoints are authorized on the public origin**
**Severity:** P0. **File:** `web/_headers`, global block, `Content-Security-Policy`.
**Evidence:** `script-src 'self' 'sha256-...' 'sha256-...' https://www.googletagmanager.com https://connect.facebook.net ...; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://stats.g.doubleclick.net https://www.facebook.com ...; img-src 'self' data: https: https://www.facebook.com ...`
Unanimous with Seat 1 F-1 on both defect and remedy. Every visit to the download origin is reported to Google and Meta with source IP, outside the tunnel, which is the enumeration event the product overview names as the worst outcome. GTM in `script-src` makes the two inline hashes ornamental, and `img-src ... https:` permits a pixel from any host.
**Fix.** Replace the global CSP line with:
```
  Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://applepay.cdn-apple.com https://pay.google.com; frame-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://pay.google.com; form-action 'self' https://www.paypal.com https://www.paypalobjects.com; upgrade-insecure-requests
```
Delete the corresponding `<script>` tags and pixel markup from `web/index.html`, recompute both inline-script hashes and the inline-style hash (the edit changes them), and paste the new digests into the line above. Seat 1's diff omits this recomputation step; without it the site's own inline scripts are blocked. Then gate it in `tools/verify_live_deployment.py`:
```python
FORBIDDEN_CSP_HOSTS = (
    "googletagmanager.com", "connect.facebook.net", "google-analytics.com",
    "doubleclick.net", "googleadservices.com", "facebook.com",
)
for host in FORBIDDEN_CSP_HOSTS:
    checks += 1
    if host in repo_csp or host in live_csp:
        failures.append(f"tracker host {host!r} is authorized by a CSP; remove it")
```
**Operator action required.** Decide whether conversion analytics is being given up permanently. If the owner wants retention metrics, the replacement is first-party aggregate counting in the Worker with no third-party origin in any CSP directive.
**Residual risk.** PayPal and Google Pay frames still observe checkout visitors, which is intrinsic to hosted checkout. Cloudflare still sees every request at the edge.

---

**F-2 | Domain A | `QUERY_ALL_PACKAGES` is declared with no stated use**
**Severity:** P0. **File:** `android/app/src/main/AndroidManifest.xml`.
**Evidence:** `<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" tools:ignore="QueryAllPackagesPermission" />`
Split out of my Turn 1 F-2 at the insistence of Seat 1 F-3 and Seat 3 F-7. The manifest documents a rationale for its other permissions and none for this one, and the existing `<queries>` block already scopes browser intents to `http` and `https`. The permission also proves the enumeration capability it grants is available to every other app on the device, which is the same capability that defeats the launcher camouflage.
**Fix.** Delete the three-line declaration. If a split-tunnel package picker later needs specific visibility, add only the exact `<package android:name="..."/>` or `<intent>` entries it requires under the existing `<queries>` block.
**Operator action required.** Before deleting, grep the Kotlin and Dart sources for `getInstalledPackages`, `getInstalledApplications`, and `queryIntentActivities`; if the split-tunnel picker uses one of them, the picker moves to a system app-picker intent in the same change.
**Residual risk.** Hidden code not in this packet may depend on broad enumeration, so a device test of the split-tunnel screen is required before publication. Play policy treatment is UNVERIFIED-LIVE.

---

**F-3 | Domain A | The calculator camouflage is cosmetic: package identity and a product-labelled alias survive it**
**Severity:** P0. **File:** `android/app/src/main/AndroidManifest.xml` (`activity-alias .LauncherReal`), `android/app/build.gradle.kts` (`applicationId = "org.winsvpn.app"`).
**Evidence:** `android:name=".LauncherReal" android:enabled="true" ... android:label="Win's VPN"`
Unchanged from Turn 1 except that the permission item is now F-2. A disabled component is still returned by `getPackageInfo(..., MATCH_DISABLED_COMPONENTS)`, so both aliases are enumerable in either camouflage state, and the default install state ships `.LauncherReal` enabled, showing the product name on the home screen until the user opts in.
**Fix.** In the manifest:
```xml
<activity-alias
    android:name=".LauncherReal"
    android:enabled="true"
    android:icon="@mipmap/ic_launcher"
    android:label="@string/launcher_real_label"
    android:targetActivity=".RealLauncherActivity"
    android:exported="true">
```
with `<string name="launcher_real_label">Calculator</string>` in `values/strings.xml`, and the un-camouflaged product name rendered only inside the Flutter UI after PIN entry. Extend `CamouflageLatchedSurfaceTest` with an assertion that no attribute in any `android/app/src/*/AndroidManifest.xml` contains the literal `Win's VPN`.
**Residual risk.** `org.winsvpn.app` cannot change without losing the update path for installed users, and stays visible in `pm list packages` and Settings. State that limit in-app so users do not over-trust the disguise, and treat a neutral package identifier as a requirement for any future separate listing.

---

**F-4 | Domain F | Monero RPC password is written into a systemd unit under the root umask and printed to console and log**
**Severity:** P0. **File:** `server/spain_crypto_payments_setup.sh`, `setup_monero_service()` and `print_summary()`.
**Evidence:** `--rpc-login ${rpc_user}:${rpc_pass} \\` inside a `cat >` heredoc writing `/etc/systemd/system/monero-wallet-rpc.service`, and `printf 'MONERO_WALLET_RPC_PASS="%s"\n' "${rpc_pass}"`.
Merged with Seat 3 F-2, which reached the same defect and contributed the mode fix. The script writes `${creds_file}` at 0600 and then copies the same secret into a unit file created under the stock 0644 umask, and prints it to stdout, which lands in terminal scrollback and in `LOG_FILE=/var/log/winsvpn/spain_crypto_setup.log` when teed.
**Fix, preferred form.** Keep the secret out of the unit file and install the unit at 0600 regardless:
```bash
    install -o root -g root -m 0600 /dev/null /etc/systemd/system/monero-wallet-rpc.service
    cat > /etc/systemd/system/monero-wallet-rpc.service <<'EOF'
[Unit]
Description=Win's VPN Monero View-Only Wallet RPC
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=monero-wallet
Group=monero-wallet
UMask=0077
EnvironmentFile=/etc/winsvpn/commerce/monero/monero_rpc_auth.env
ExecStart=/usr/local/bin/monero-wallet-rpc \
    --wallet-dir /var/lib/monero/wallet \
    --rpc-bind-ip 127.0.0.1 \
    --rpc-bind-port 18083 \
    --restricted-rpc \
    --rpc-login ${MONERO_WALLET_RPC_USER}:${MONERO_WALLET_RPC_PASS} \
    --daemon-address 127.0.0.1:18081 \
    --trusted-daemon \
    --log-file /var/log/winsvpn/monero-wallet-rpc.log \
    --max-log-file-size 10485760
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectProc=invisible
ProcSubset=pid
ReadWritePaths=/var/lib/monero /var/log/winsvpn
MemoryHigh=512M
MemoryMax=768M

[Install]
WantedBy=multi-user.target
EOF
    chmod 0600 /etc/systemd/system/monero-wallet-rpc.service
```
In `print_summary()`:
```bash
    printf 'MONERO_WALLET_RPC_USER="%s"\n' "${rpc_user}"
    printf 'MONERO_WALLET_RPC_PASS: read from %s on the Spain node (never printed)\n' "${creds_file}"
```
**Operator verification, then branch.** Run `systemctl show -p ExecStart monero-wallet-rpc.service` after `daemon-reload` and confirm the `--rpc-login` argument shows the expanded user and password rather than a literal `${MONERO_WALLET_RPC_USER}`. Partial `${VAR}` substitution inside a larger argument word is UNVERIFIED-LIVE for the pinned systemd. If the expansion does not occur, fall back to Seat 3's form: interpolate `${rpc_user}:${rpc_pass}` into a `mktemp` file and `install -o root -g root -m 0600` it into place, which keeps the 0600 guarantee and drops the expansion dependency.
**Operator action required.** Rotate the existing password on the live node after applying, since the current one is already in at least one terminal history and one log file.
**Residual risk.** `--rpc-login` is a command-line option, so the credential stays in `/proc/<pid>/cmdline` under either form. `ProtectProc=invisible` hides other processes from this unit, not this unit from other accounts; `hidepid=2` on `/proc` is the host-wide complement and should be proposed separately. Root compromise reads it either way.

---

**F-5 | Domain F | Wallet RPC authentication may be disabled by the supplied flags, and the endpoint is publicly proxied**
**Severity:** P0. **File:** `server/spain_crypto_payments_setup.sh`, `setup_monero_service()` and `setup_nginx_proxy()`.
**Evidence:** `--disable-rpc-login=0 \\` and `--confirm-external-bind=0` in the ExecStart, alongside `location /monero-rpc { proxy_pass http://127.0.0.1:18083/json_rpc; ... proxy_pass_header Authorization; }` reachable as `https://btcpay.winsvpn.org/monero-rpc`.
Held against Seat 3, whose F-2 replacement unit reproduces both flags verbatim. These are presence-style switches in the Monero CLI (UNVERIFIED-LIVE for the pinned release's boost program_options binding). Either the parser treats presence as assertion and login is off, in which case the nginx block republishes an unauthenticated JSON-RPC endpoint to the internet through the Cloudflare tunnel, or it rejects an explicit value on a zero-token switch and the unit never starts. The script asserts neither: `verify_services` prints `Monero RPC probe result: ${monero_test}` and continues on `|| true`. Seat 1's F-2 independently reached the nginx half.
**Fix.** Delete both flags (the F-4 unit above already omits them) and convert the probe into a gate:
```bash
    info "Asserting Monero RPC rejects unauthenticated calls..."
    local unauth_code
    unauth_code="$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST http://127.0.0.1:18083/json_rpc \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' || true)"
    if [[ "${unauth_code}" != "401" ]]; then
        err "Monero RPC answered an unauthenticated request with HTTP ${unauth_code}; expected 401. Refusing to proceed."
        exit 1
    fi
```
Close the proxy at the edge as well, which is Seat 1's `allow`/`deny` verbatim plus `satisfy all`:
```nginx
    location /monero-rpc {
        satisfy all;
        allow 127.0.0.1;
        deny all;
        proxy_pass http://127.0.0.1:18083/json_rpc;
    }
```
and reach the endpoint from the Kansas hub over the management tunnel per F-22.
**Residual risk.** The wallet is view-only and restricted, so the worst case is payment-flow enumeration rather than fund theft. Enumeration still links a donor address set to this organization.

---

**F-6 | Domain F | A privileged installer clones and executes unpinned upstream shell code as root**
**Severity:** P0. **File:** `server/spain_crypto_payments_setup.sh`, `setup_btcpay_server()`.
**Evidence:** `git clone https://github.com/btcpayserver/btcpayserver-docker.git "${BTCPAY_DOCKER_DIR}"` followed by `( cd "${BTCPAY_DOCKER_DIR}"; source "${env_file}"; . ./btcpay-setup.sh -i )`.
My Turn 1 F-5, with Seat 3's F-1 remedy adopted in place of mine. Whatever sits on the default branch at run time is sourced into a root shell on the one host holding the store credentials, in a repository that pins Xray by archive digest and extracted-binary digest and Monero by SHA-256. My commit-pin fix still performed a network fetch as root before any pin was checked and would accept a dirty tree at the right commit; Seat 3's removes the fetch and checks the tree.
**Fix.**
```bash
setup_btcpay_server() {
    info "Configuring BTCPay Server from reviewed staging..."

    : "${BTCPAY_REVIEWED_COMMIT:?BTCPAY_REVIEWED_COMMIT must be the reviewed 40-character commit}"
    [[ "${BTCPAY_REVIEWED_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || {
        err "BTCPAY_REVIEWED_COMMIT must be exactly 40 lowercase hexadecimal characters"
        exit 1
    }
    [[ -d "${BTCPAY_DOCKER_DIR}/.git" ]] || {
        err "Pre-stage the reviewed BTCPay checkout at ${BTCPAY_DOCKER_DIR}; this installer does not clone code"
        exit 1
    }

    local actual_commit
    actual_commit="$(git -C "${BTCPAY_DOCKER_DIR}" rev-parse HEAD)"
    [[ "${actual_commit}" == "${BTCPAY_REVIEWED_COMMIT}" ]] || {
        err "BTCPay checkout is ${actual_commit}, expected ${BTCPAY_REVIEWED_COMMIT}"
        exit 1
    }
    git -C "${BTCPAY_DOCKER_DIR}" diff --quiet || {
        err "BTCPay checkout has uncommitted modifications; re-stage from the reviewed commit"
        exit 1
    }
    git -C "${BTCPAY_DOCKER_DIR}" diff --cached --quiet || {
        err "BTCPay checkout has staged modifications; re-stage from the reviewed commit"
        exit 1
    }
    if ! git -C "${BTCPAY_DOCKER_DIR}" verify-commit "${BTCPAY_REVIEWED_COMMIT}" >/dev/null 2>&1; then
        warn "BTCPay commit ${BTCPAY_REVIEWED_COMMIT} carries no verifiable signature; the pin is the only control."
    fi

    # Existing environment generation and reviewed setup invocation follow.
}
```
Delete the `git clone` branch. Record the reviewed commit and its review date beside the Xray and Monero pin constants.
**Operator action required.** Stage the checkout on the Spain node from a reviewed commit before running the installer, and export `BTCPAY_REVIEWED_COMMIT` to that 40-hex value.
**Residual risk.** A pinned commit that was already malicious still executes. The pin converts open-ended exposure into a one-time review decision, which is the right shape and not immunity.

---

**F-7 | Domain G | PAC host rules are never normalized, so listed-mode routing silently misses the exact sites the user protected**
**Severity:** P0. **File:** `extension/src/core/pac.js`, `buildPac()`.
**Evidence:** `var LISTED = [${listed}];` built from `(settings.listed || []).map(lit)`, against a matcher that canonicalizes only the host: `var h = ("" + host).toLowerCase(); if (h.charAt(h.length - 1) === ".") { h = h.substring(0, h.length - 1); }`
Unchanged. Neither other seat reached it; Seat 1 examined the same file and filed a non-defect on the comparison (refuted above) while the rule side went unexamined. A rule saved as `Example.com`, `example.com.`, or a Unicode domain never equals the lowercase punycode host, so `wvAny` returns false and `return wvAny(LISTED, h) ? P : "DIRECT"` sends the protected request over the direct path, silently, for precisely the hosts the user cared about.
**Fix.**
```js
function normRule(rule) {
  let v = String(rule || '').trim().toLowerCase();
  while (v.endsWith('.')) v = v.slice(0, -1);
  if (!v) return '';
  try {
    // new URL() applies IDNA/punycode and strips any stray userinfo, port or path.
    const parsed = new URL('https://' + v);
    if (parsed.username || parsed.password) return '';
    v = parsed.hostname;
  } catch (_) {
    return '';
  }
  while (v.endsWith('.')) v = v.slice(0, -1);
  return v;
}

export function buildPac(settings, endpoint) {
  const tokenLit = lit(pacToken(endpoint));
  const listed = (settings.listed || []).map(normRule).filter(Boolean).map(lit).join(',');
  const excluded = (settings.excluded || []).map(normRule).filter(Boolean).map(lit).join(',');
  const listedMode = settings.mode === MODE_LISTED;
```
Apply `normRule` in the options and popup save paths, reject a rule that normalizes to the empty string with a visible message, and show the normalized form back to the user at save time.
**Residual risk.** A rule that normalizes to a host the user did not intend, through a typo or a homograph, still routes the wrong thing. Echoing the normalized form in the UI is what bounds that.

---

**F-8 | Domain C | The live data plane runs an installer that exists in no commit**
**Severity:** P0. **File:** `server/wins_winn3_gateway_install.sh`, header comment.
**Evidence:** `the installer deployed on the fleet's only data plane matches NO commit in this repository. The on-host copy is 275,860 bytes; the committed one is 367,410.`
Unanimous with Seat 1 F-15. Roughly 92 kB of divergence between reviewed source and the code that built the production node. Every finding in this round about data-plane posture is a claim about the committed file, not about production, until the on-host artifact is captured.
**Fix.** Proposal only, no fleet mutation assumed:
```bash
# On the operator workstation, over the existing management channel.
scp root@<data-plane>:/root/wins_data_plane_setup_ONETOUCH.sh /tmp/onhost_data_plane.sh
sha256sum /tmp/onhost_data_plane.sh server/wins_data_plane_setup_ONETOUCH.sh
git checkout -b reconcile/data-plane-onhost
mkdir -p server/deployed
cp /tmp/onhost_data_plane.sh server/deployed/wins_data_plane_setup_ONETOUCH.onhost.sh
git add server/deployed/wins_data_plane_setup_ONETOUCH.onhost.sh
git commit -m "Capture on-host data plane installer as found, for reconciliation"
diff -u server/deployed/wins_data_plane_setup_ONETOUCH.onhost.sh \
        server/wins_data_plane_setup_ONETOUCH.sh > docs/evidence/data_plane_divergence.diff
```
Then work the diff hunk by hunk into the committed script, and record `sha256sum` of the installed installer in the node registration payload so future divergence is detected rather than discovered.
**Operator action required.** The `scp` above is the only fleet-touching step and it is read-only. Decide whether the capture happens before or after the Turn 3 certification, since no data-plane finding can be certified as true of production until it does.
**Residual risk.** The captured copy may already carry an unauthorized modification. Treat the diff as untrusted input and review each hunk on its merits.

---

### P1

---

**F-9 | Domain E | Paid upstream routes fail open because the rate-limiter binding does not exist on Pages**
**Severity:** P1 (Seat 3 filed P0; severity is the open item stated in section 3). **File:** `web/_worker.js`, `requireQuota` and the translation and AI chat handlers; `web/wrangler.jsonc`.
**Evidence:** `NOT USED BY THE CURRENT LIVE DEPLOYMENT ... Cloudflare Rate Limiting bindings (the ratelimits block below) are a Workers-only feature`, against a `requireQuota` that falls through to the isolate-local `Map` when `env[bindingName]` is undefined. The source already records a conditional distributed-cost and quota-exhaustion gap for translation and AI chat.
Accepted from Seat 3 F-3, with Seat 1 F-8 supplying the zone-level remedy. My F-31 shows the isolate-local fallback is itself resettable, so the effective limit today is no limit.
**Fix.**
```javascript
async function requireQuota(
  request,
  env,
  bindingName,
  keyPrefix,
  limit = 20,
  windowMs = 60_000,
  bindingRequired = false
) {
  const ip = connectingClientIp(request);
  if (!ip) {
    return json({ error: "ip_unavailable" }, 503, corsHeaders(request));
  }

  const limiter = env[bindingName];
  if (limiter && typeof limiter.limit === "function") {
    try {
      const outcome = await limiter.limit({ key: `${keyPrefix}:${ip}` });
      return outcome.success
        ? null
        : json({ error: "rate_limited" }, 429, corsHeaders(request));
    } catch (_) {
      if (bindingRequired && env.ZONE_RATE_LIMIT_CONFIRMED !== "1") {
        return json({ error: "quota_unavailable" }, 503, corsHeaders(request));
      }
    }
  } else if (bindingRequired && env.ZONE_RATE_LIMIT_CONFIRMED !== "1") {
    return json({ error: "quota_unavailable" }, 503, corsHeaders(request));
  }

  return isolateLocalRateLimited(keyPrefix, ip, limit, windowMs)
    ? json({ error: "rate_limited" }, 429, corsHeaders(request))
    : null;
}
```
Pass `true` as the last argument from the translation and AI chat handlers. The `ZONE_RATE_LIMIT_CONFIRMED` escape is my addition to Seat 3's design: a hard 503 with no way back leaves the operator no path to restore the feature after configuring the control, and the variable name makes the assertion visible in the Cloudflare dashboard.
**Operator action required.** Configure zone-level Cloudflare WAF rate limiting on `winsvpn.org` for `/api/site/translate`, `/api/site/ai-chat`, `/api/site/wallet/*`, and `/api/site/crypto/*` at 20 requests per minute per connecting IP, confirm the rule is active, then set `ZONE_RATE_LIMIT_CONFIRMED=1` in the Pages environment. Until that is done, translation and AI chat return 503, which is the intended state.
**Residual risk.** Carrier-grade NAT clustering in high-traffic regions can trigger the zone rule for legitimate users during bursts. Tune the threshold against observed traffic rather than lowering it below the documented per-user need.

---

**F-10 | Domain E | The map tile route performs upstream fetches with no quota check at all**
**Severity:** P1 (Seat 3 filed P0). **File:** `web/_worker.js`, `handleMapTile`.
**Evidence:** `handleMapTile` validates coordinates and performs an upstream `fetch` with no call to any quota function.
Accepted from Seat 3 F-4. I rechecked their arithmetic from first principles: the accepted coordinate space across zoom 0 through 19 is `sum(4^z, z=0..19) = (4^20 - 1)/3`, and with `4^20 = 1,099,511,627,776` that is `366,503,875,925` distinct paths. The cache cannot absorb first-fetch work across that set, so a single client can drive unbounded upstream requests.
**Fix.**
```javascript
  const quotaFailure = await requireQuota(
    request,
    env,
    "RATE_LIMITER_MAP_TILE",
    "map-tile",
    120,
    60_000,
    true
  );
  if (quotaFailure) return quotaFailure;
```
placed immediately after the method checks and before coordinate validation and cache lookup. Do not add a fake namespace identifier to `web/wrangler.jsonc` to make the binding appear present.
**Operator action required.** Add `/api/site/map-tile*` to the same zone-level rule as F-9 at 120 requests per minute per IP. The map is unavailable until that rule exists and `ZONE_RATE_LIMIT_CONFIRMED=1` is set.
**Residual risk.** A configured distributed limit still permits traffic up to its allowance, and a botnet spread across many source IPs stays under a per-IP rule. Per-IP limiting bounds the single-client case only.

---

**F-11 | Domain A | The release engine gate validates the wrong candidate and checks no provenance**
**Severity:** P1. **File:** `android/app/build.gradle.kts`, `verifyAndroidReleaseEngineInputs()`.
**Evidence:** the gate accepts when any candidate satisfies `isSafeNonEmptyReleaseInput`, and the check itself is `Files.isRegularFile(...) && file.length() > 0L`. Git status shows ` M` on all six `libwinnengine.so` copies and all three `libxray.so` copies.
Merged: Seat 3 F-6 supplies the selection defect, my Turn 1 F-8 supplies the provenance defect. Seat 3's correction comes first, because hashing a candidate the build does not package proves nothing.
**Fix.** One function doing both:
```kotlin
fun verifyAndroidReleaseEngineInputs() {
    val expected = groovy.json.JsonSlurper()
        .parse(file("../../tools/android-engine-digests.json")) as Map<*, *>
    val missing = mutableListOf<String>()
    for (abi in androidReleaseAbis) {
        for (engine in androidReleaseStagedEngines) {
            val releaseCandidate = file("src/release/jniLibs/$abi/$engine")
            val mainCandidate = file("src/main/jniLibs/$abi/$engine")
            val selected =
                if (Files.exists(releaseCandidate.toPath(), LinkOption.NOFOLLOW_LINKS)) {
                    releaseCandidate
                } else {
                    mainCandidate
                }
            if (!isSafeNonEmptyReleaseInput(selected)) {
                missing += "$abi/$engine selected from ${selected.relativeTo(projectDir)}"
                continue
            }
            val actual = java.security.MessageDigest.getInstance("SHA-256")
                .digest(selected.readBytes())
                .joinToString("") { "%02x".format(it) }
            val want = expected["$abi/$engine"] as? String
            if (want == null || want != actual) {
                throw GradleException(
                    "Engine $abi/$engine digest $actual does not match the reviewed digest in " +
                        "tools/android-engine-digests.json. Rebuild with " +
                        "tools/build_winn_protocol_engine.sh and update the manifest deliberately.",
                )
            }
        }
    }
    if (missing.isNotEmpty()) {
        throw GradleException("Unsafe or missing release engine inputs: ${missing.joinToString(", ")}")
    }
}
```
Add Seat 3's unit fixture where an unsafe release file shadows a valid main file and assert rejection. `tools/android-engine-digests.json` is produced by the pinned build script and committed in the same change as the binaries.
**Operator action required.** The nine modified native objects in the working tree must be rebuilt from the pinned toolchain and their digests written into the manifest in one commit, or reverted. Do not generate the manifest from the current uncommitted blobs, which would certify whatever is there.
**Residual risk.** A compromised workstation can update the manifest and the blob together. Reproducible builds from the pinned Go toolchain answer that, and the freshness gate already reads `tools/toolchain-pins.json`.

---

**F-12 | Domain A | The secret-code receiver is exported, third-party triggerable, and spells the product name**
**Severity:** P1. **File:** `android/app/src/main/AndroidManifest.xml`, `SecretCodeReceiver` block.
**Evidence:** `<receiver android:name=".SecretCodeReceiver" android:exported="true"> <intent-filter> <action android:name="android.provider.Telephony.SECRET_CODE" /> <data android:scheme="android_secret_code" android:host="9467" />`
Fix replaced with Seat 1 F-4's. The host `9467` is `W-I-N-S` on a keypad, readable by `aapt dump badging` on a pulled APK, and the receiver has no `android:permission`, so any local app can deliver an explicit intent naming the component. My permission-gate fix left the fingerprint in place and constrained the caller's permission rather than its identity.
**Fix.** Delete the receiver declaration and its intent filter from the manifest:
```xml
        <receiver android:name=".SecretCodeReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.provider.Telephony.SECRET_CODE" />
                <data android:scheme="android_secret_code" android:host="9467" />
            </intent-filter>
        </receiver>
```
Remove `SecretCodeReceiver.kt` along with it. Keep reveal strictly on the calculator digit-sequence path already in the Flutter UI, where the trigger value lives in encrypted preferences rather than in a manifest literal. Add a unit assertion that no manifest in `android/app/src/` contains the string `android_secret_code`.
**Correction to Seat 1's evidence.** Their quoted block includes `<action android:name="android.intent.action.MAIN" />` inside the intent filter, which is not present in the manifest text supplied to me. Apply the deletion against the actual file and confirm no other component depends on the receiver class.
**Residual risk.** Users who currently launch by dialing the code must switch to the calculator sequence. That migration needs a one-time in-app notice shipped in the release before the one that removes the receiver, or those users lose their entry path with no explanation.

---

**F-13 | Domain A | The watch command service is exported with no caller check**
**Severity:** P1. **File:** `android/app/src/main/AndroidManifest.xml`, `WatchCommandService`.
**Evidence:** `<service android:name=".WatchCommandService" android:exported="true"> <intent-filter> <action android:name="com.google.android.gms.wearable.MESSAGE_RECEIVED" />` with the comment `the Data Layer only routes between nodes running this same package signed with this same certificate`.
Unchanged; neither other seat reached it. The comment describes a real routing guarantee and then relies on it to justify an export the Data Layer does not protect. A co-resident app can `startService` with that action and forged extras, which for this threat model is a locally triggerable disconnect at a chosen moment.
**Fix.**
```kotlin
class WatchCommandService : WearableListenerService() {
    override fun onMessageReceived(event: MessageEvent) {
        if (event.path != "/winsvpn/cmd") return
        handleCommand(event.data)
    }

    // Any other delivery path is not the Data Layer. Refuse it.
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action != "com.google.android.gms.wearable.MESSAGE_RECEIVED" &&
            action != "com.google.android.gms.wearable.BIND_LISTENER"
        ) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        return super.onStartCommand(intent, flags, startId)
    }
}
```
Add an instrumented test that sends an explicit intent with a forged payload and asserts no tunnel state change.
**Residual risk.** `WearableListenerService` binder validation is a Play services implementation detail (UNVERIFIED-LIVE for the pinned `play-services-wearable:19.0.0`). The `onStartCommand` refusal is the part that lives in this repository and does not depend on it.

---

**F-14 | Domain A | The `qa` build type is signed with the production key and bypasses every release gate**
**Severity:** P1. **File:** `android/app/build.gradle.kts`, `buildTypes { create("qa") { ... } }` and `gradle.taskGraph.whenReady`.
**Evidence:** `signingConfig = if (unsignedReleaseRequested) null else signingConfigs.getByName("release")` against a gate matching only `task.name == "assembleRelease" || ... || task.name.startsWith("signRelease")`.
Unchanged. With the `formFactor` dimension the qa variants are `assemblePhoneQa`, `packageTvQa`, `signPhoneQaBundle`; none match, so all three verifications skip, minification defaults off, Dart obfuscation is unrequired, and the artifact carries the genuine release signature.
**Fix.**
```kotlin
gradle.taskGraph.whenReady {
    val signingSensitive = allTasks.any { task ->
        task.project.path == appProjectPath &&
            Regex("^(assemble|bundle|package|sign)(Phone|Tv)?(Release|Qa)").containsMatchIn(task.name)
    }
    if (signingSensitive) {
        verifyAndroidReleaseEngineInputs()
        verifyAndroidReleaseIdentityAndApi36()
        verifyAndroidReleaseR8AndFlutterObfuscation(allTasks)
    }
    if (signingSensitive && !hasCompleteEnvironmentSigning && !unsignedReleaseRequested) {
        throw GradleException(
            "Missing Android release signing input. Use the owner-only current-user DPAPI preseed or the complete WINS_ANDROID_* process environment; never use a repository-local properties file or the Android debug key.",
        )
    }
}
```
**Operator decision required.** If QA must not carry release obfuscation, create `signingConfigs.create("qa")` backed by a separate QA key instead of reusing the upload key. One of the two has to happen; reusing the upload key under relaxed gates is the state being fixed.
**Residual risk.** Broadening the gate makes QA builds require the full engine set and obfuscation flags, slowing the QA loop. That is the correct trade against a production-key artifact with no gates.

---

**F-15 | Domain B | Profile validation accepts a carrier class the dialer refuses, producing a silent downgrade**
**Severity:** P1. **File:** quoted in `server/wins_control_plane_setup_ONETOUCH.sh` at `WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT`; the defect lives in `winn_protocol_experimental/winn3/` and the client host profile parser.
**Evidence:** `the client's winn3DialCarrier hard-refuses carrier.ClassTLS ... but winn3Profile validate() ACCEPTS class=tls at load, so the refusal only fires at dial time. An operator provisioning with defaults therefore believed the node had a TLS cover hop it does not have`
Unchanged. Neither other seat filed a domain B finding grounded in source; Seat 1's two B-domain items are both about installer defaults rather than the engine. Removing `tls` from one default constant treats the symptom while the validator stays wrong for hand-written profiles, hub descriptors, and the verify harness.
**Fix.**
```go
// winn3/session (or wherever winn3Profile.validate lives)
func (p *winn3Profile) validate() error {
    switch p.Carrier.Class {
    case carrier.ClassUDP:
    case carrier.ClassTLS:
        // ClassTLS is not dialable by this client: the v3 host profile carries no
        // trust anchors, no ECH list and no client certificate. Refuse at load so
        // the failure is a provisioning error, not a silent winn/1 downgrade.
        return fmt.Errorf("carrier class %q is not dialable by this build", p.Carrier.Class)
    default:
        return fmt.Errorf("unknown carrier class %q", p.Carrier.Class)
    }
    return nil
}
```
Add a table test asserting that the set of classes `validate()` accepts equals the set `winn3DialCarrier` handles. This changes the validator only; the dial path is untouched and the frozen datapath is not modified.
**Operator action required.** Sweep stored `protocol_params` for `class=tls` before rollout, since any node already provisioned that way starts failing at profile load rather than at dial.
**Residual risk.** The behavior change is intended and is a provisioning break for exactly the nodes that were already silently downgrading.

---

**F-16 | Domain C | `cmd_deploy` records firewall failures and then exits zero**
**Severity:** P1. **File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy()`.
**Evidence:** `local_jump_receipts` calls `FAIL "WINN3GW-FORWARD chain missing"` and `FAIL "FORWARD jumps wrong ..."`, and the function ends with `RECEIPT` plus two `NOTE` lines. `verdict` is never called.
Unanimous with Seat 3 F-5 on both defect and fix. A deploy leaving the NAT MASQUERADE rule missing reports success and returns 0.
**Fix.**
```bash
  RECEIPT "deploy ${ROLE}: binary $(sha256sum "$GW_INSTALL" | cut -c1-16)… installed; env+unit+credentials+peers in place; firewall oneshot enabled; ip_forward=1"
  NOTE "next: on the hub VM run  bash deploy_and_verify.sh verify-hub ${ROLE}"
  NOTE "then here:              bash deploy_and_verify.sh verify-node ${ROLE}"
  NOTE "on failure: bash deploy_and_verify.sh rollback ${ROLE}"
  verdict
}
```
**Residual risk.** A deploy that now exits non-zero leaves the node in the partially configured state it was already in. The `rollback` subcommand is the recovery path and is named in the output above.

---

**F-17 | Domain C | The hub verifier counts failures into a variable the exit status ignores**
**Severity:** P1. **File:** `winn3-nodes/deploy_and_verify.sh`, embedded Python in `cmd_verify_hub()`.
**Evidence:** `def rec(name, ok, detail=""): global fails ... if not ok: fails += 1` and `result = "PASS" if (carrying and ok_inner and ok_nat) else "FAIL"`.
Unanimous with Seat 3 F-5 on the defect. I keep my conjunction rather than their `fails == 0` alone: the packet shows `rec()` calls for `tcp-9111-connect`, `seam-port`, and `client-rx-packets>0`, and does not show `rec()` calls for the three booleans in the verdict expression, so `fails == 0` by itself may not cover them. The conjunction is correct under either reading.
**Fix.**
```python
    print(f"RECEIPT {role} endpoint={endpoint}:9111 handshake=1 inner={int(ok_inner)} nat={int(ok_nat)}")
    result = "PASS" if (fails == 0 and carrying and ok_inner and ok_nat) else "FAIL"
    print(f"RESULT {role}: {result} (recorded_failures={fails} handshake={int(carrying)} "
          f"icmp-inner={int(ok_inner)} icmp-nat={int(ok_nat)}; log verify-{role}.status.log)")
    sys.exit(0 if result == "PASS" else 1)
```
Adopted additionally from Seat 3: every early `seam-port` failure branch must print its receipts before exiting, matching the no-handshake branch, so a short-circuit exit is not silent.
**Residual risk.** The TCP probe now blocks a PASS on nodes where the cover listener is deliberately absent. If such a configuration is valid, make the probe conditional on the staged env rather than dropping it from the verdict. ICMP success proves the tested target at one instant, not long-session stability.

---

**F-18 | Domain C | Rollback leaves the FORWARD and NAT jumps in place when default-route discovery fails**
**Severity:** P1. **File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_rollback`.
**Evidence:** removal of both `FORWARD` jumps and the NAT `POSTROUTING` jump sits inside `if [[ -n "$wan_if" ]]`, although none of those three deletion commands reference `$wan_if`. Chain deletion errors are suppressed and the script still prints a rollback receipt.
Accepted from Seat 3 F-12. A rollback on a node where the default route cannot be determined reports success and leaves the forwarding path wired.
**Fix.**
```bash
while iptables -w 10 -D FORWARD -i "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
while iptables -w 10 -D FORWARD -o "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done

if [[ -n "$wan_if" ]]; then
  while iptables -w 10 -D INPUT -i "$iface" -d "$INNER_V4" \
      -p tcp --dport 53 -j WINN3GW-INPUT 2>/dev/null; do :; done
fi

if iptables -S FORWARD | grep -q 'WINN3GW-FORWARD'; then
  FAIL "rollback left a WINN3GW-FORWARD jump in the FORWARD chain"
fi
if iptables -t nat -S POSTROUTING | grep -q 'WINN3GW-NAT-POSTROUTING'; then
  FAIL "rollback left a WINN3GW-NAT-POSTROUTING jump in nat POSTROUTING"
fi
verdict
```
Seat 3's text was truncated at the verification command; the absence assertion and `verdict` call above are my completion of it and are the part that makes the receipt honest.
**Residual risk.** A rollback that now exits non-zero signals residual firewall state the operator must clear by hand. That is the intended outcome; the current silent success is what hides it.

---

**F-19 | Domain C | Installers source a defaults file under `set -a` with no owner, mode, or file-type check**
**Severity:** P1. **File:** `server/wins_control_plane_setup_ONETOUCH.sh` (initial `WINS_DEFAULTS_FILE` load) and `server/wins_data_plane_setup_ONETOUCH.sh` (defaults and secrets loads).
**Evidence:** `. "${WINS_DEFAULTS_FILE}"` executed under `set -a` with no validation, while `server/wins_core_server_setup_ONETOUCH.sh` in the same tree performs ownership, mode, regular-file, and symlink checks before sourcing.
Accepted from Seat 3 F-8 and F-9, merged into one finding because it is one helper applied in three places. The repository already contains the correct pattern, so this is drift.
**Fix.** Add to both installers and call before every sourced file:
```bash
wins_require_trusted_env_file() {
  local path="$1" label="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "[ERR] ${label} must be a real regular file: ${path}" >&2
    exit 1
  }
  [[ "$(stat -c '%u' "${path}")" == "0" ]] || {
    echo "[ERR] ${label} must be owned by root: ${path}" >&2
    exit 1
  }
  [[ -z "$(find "${path}" -prune -perm /077 -print -quit)" ]] || {
    echo "[ERR] ${label} must have mode 600 or stricter: ${path}" >&2
    exit 1
  }
}
```
```bash
if [[ -f "${WINS_DEFAULTS_FILE}" ]]; then
  wins_require_trusted_env_file "${WINS_DEFAULTS_FILE}" "WINS_DEFAULTS_FILE"
  set -a
  . "${WINS_DEFAULTS_FILE}"
  set +a
fi
```
Apply the same call inside `overlay_wins_secrets_file` and before sourcing `NODE_ENV_FILE` and `WINS_SECRETS_FILE` in the data plane installer.
**Residual risk.** Root-owned configuration is still executable shell syntax, so a mistaken or malicious root edit still runs with installer privileges. The fix removes untrusted file type and permission states, not root authority.

---

**F-20 | Domain F | The payment node's chain view is outsourced to a third-party public Monero daemon**
**Severity:** P1. **File:** `server/spain_crypto_payments_setup.sh`, `setup_monero_service()`.
**Evidence:** `--daemon-address nodes.hashvault.pro:18081 \\` and `--untrusted-daemon \\`
Accepted from Seat 1 F-18, which is the strongest finding in their verdict and which I missed. `--untrusted-daemon` stops the remote node from lying to the wallet; it does nothing about what the remote node observes. The operator of `nodes.hashvault.pro` learns the Spain payment node's IP address, its uptime pattern, and the block and output ranges a view-only wallet belonging to this organization requests. For an organization whose privacy claim is the product, that is a standing disclosure to an uncontracted third party.
**Fix.**
```bash
    --daemon-address 127.0.0.1:18081 \
    --trusted-daemon \
```
in the ExecStart (already reflected in F-4 above), and provision a local pruned daemon:
```bash
setup_monero_daemon() {
    info "Provisioning local pruned monerod..."
    install -d -o monero-wallet -g monero-wallet -m 0700 /var/lib/monero/daemon
    cat > /etc/systemd/system/monerod.service <<'EOF'
[Unit]
Description=Win's VPN local pruned Monero daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=monero-wallet
Group=monero-wallet
UMask=0077
ExecStart=/usr/local/bin/monerod --non-interactive --prune-blockchain \
    --data-dir /var/lib/monero/daemon \
    --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18081 \
    --no-igd --hide-my-port \
    --log-file /var/log/winsvpn/monerod.log --max-log-file-size 10485760
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/monero /var/log/winsvpn

[Install]
WantedBy=multi-user.target
EOF
    chmod 0600 /etc/systemd/system/monerod.service
    systemctl daemon-reload
    systemctl enable --now monerod.service
}
```
Call it before `setup_monero_service` and make wallet RPC startup wait on the daemon's readiness rather than racing it.
**Operator decision required.** A pruned Monero node needs roughly 60 GB of disk and several days of initial sync on the Spain host. Confirm the disk budget before applying, or accept the third-party disclosure explicitly and record it as a known exposure. Those are the only two honest options; the current state is the third-party disclosure without the record.
**Residual risk.** The local daemon still reveals to its peers that this IP runs a Monero node, which is far less specific than revealing which outputs a particular wallet scans. Initial sync from the public network happens once, from the Spain IP.

---

**F-21 | Domain F | The Monero log file is unwritable by the service user**
**Severity:** P1. **File:** `server/spain_crypto_payments_setup.sh`, `setup_monero_service()`.
**Evidence:** `/var/log/winsvpn` is created by root; the unit declares `User=monero-wallet` and `--log-file /var/log/winsvpn/monero-wallet-rpc.log`. `ReadWritePaths` adjusts the systemd sandbox and creates nothing.
Accepted from Seat 1... this one is Seat 3 F-10. The wallet RPC cannot create its log file in a root-owned directory, so the payment path is dead on first start and the script's `|| true` probe does not catch it.
**Fix.** Before starting the service:
```bash
local monero_log="/var/log/winsvpn/monero-wallet-rpc.log"
if [[ ! -e "${monero_log}" ]]; then
    install -o monero-wallet -g monero-wallet -m 0600 /dev/null "${monero_log}"
fi
chown monero-wallet:monero-wallet "${monero_log}"
chmod 0600 "${monero_log}"
```
and assert both writability and service state:
```bash
runuser -u monero-wallet -- test -w "${monero_log}" || {
    err "Monero service log is not writable by monero-wallet"
    exit 1
}
systemctl is-active --quiet monero-wallet-rpc.service || {
    journalctl -u monero-wallet-rpc.service -n 30 --no-pager >&2
    exit 1
}
```
**Residual risk.** The service can fill the configured 10 MiB active log plus any external rotations. Any logrotate config must preserve `monero-wallet` ownership, or the same failure returns after the first rotation.

---

**F-22 | Domain F | The hub reaches the wallet RPC through the public edge, and the payment host is published in certificate transparency**
**Severity:** P1. **File:** `server/spain_crypto_payments_setup.sh`, `setup_btcpay_server()` and `print_summary()`.
**Evidence:** `export BTCPAY_HOST="btcpay.winsvpn.org"` and `MONERO_WALLET_RPC_URL="https://btcpay.winsvpn.org/monero-rpc"`.
Unchanged; Seat 1 F-2 independently reached the routing half and proposed the same management-tunnel remedy. CT logs are public and append-only, so any certificate naming this host permanently publishes that the product runs a BTCPay instance and gives a censor a name to block (UNVERIFIED-LIVE: whether the tunnel config issues an edge certificate naming this host or uses a wildcard). Separately, routing wallet RPC through the public hostname terminates TLS at Cloudflare on every payment call.
**Fix.**
```bash
    printf 'MONERO_WALLET_RPC_URL="http://%s:18083/json_rpc"  # over the hub-to-Spain management tunnel, not the public edge\n' "${WINS_SPAIN_TUNNEL_ADDR:?set to the Spain node management-tunnel address}"
```
and drop the `/monero-rpc` nginx location entirely per F-5.
**Operator decision required.** Choose whether checkout moves to a domain that does not share the product's registrable domain. That is a registration and DNS decision, not a code change, and it is the part that removes the CT association.
**Residual risk.** A separate commerce domain does not hide the association from anyone who reads the checkout page. It removes the passive, indexed, zero-effort association that an automated censor consumes.

---

**F-23 | Domain F | The nginx proxy rewrites the request URI, which breaks HTTP Digest authentication**
**Severity:** P1. **File:** `server/spain_crypto_payments_setup.sh`, `setup_nginx_proxy()`.
**Evidence:** `location /monero-rpc { proxy_pass http://127.0.0.1:18083/json_rpc; ... proxy_pass_header Authorization; }` against a service whose header documents `HTTP Digest Authentication`.
Unchanged. Digest binds the `uri` field of the client's `Authorization` header to the request target: the client computes over `/monero-rpc`, the wallet RPC recomputes over `/json_rpc`, and the comparison fails in a 401 loop no retry escapes (UNVERIFIED-LIVE: whether the pinned Monero release enforces the `uri` field strictly, which most digest implementations do). `verify_services` only exercises the loopback endpoint, so it never touches the proxied path.
**Fix.** If a loopback-only proxy is still wanted for BTCPay's convenience, preserve the path:
```nginx
    location /json_rpc {
        allow 127.0.0.1;
        deny all;
        proxy_pass http://127.0.0.1:18083/json_rpc;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_pass_header Authorization;
        proxy_pass_header WWW-Authenticate;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }
```
and extend `verify_services` to probe through the proxy, asserting 401 without credentials and 200 with them.
**Residual risk.** None beyond the endpoint continuing to exist. If the hub moves to the tunnel path per F-22, delete the proxy location instead of fixing it.

---

**F-24 | Domain C | `apt-get install docker` installs the wrong package**
**Severity:** P1. **File:** `server/spain_crypto_payments_setup.sh`, `require_dependencies()`.
**Evidence:** `for pkg in curl bzip2 tar jq docker nginx; do if ! command -v "$pkg" ...` then `apt-get install -y -qq "${missing[@]}"`.
Unchanged. The loop conflates command names with package names; on Debian and Ubuntu the Docker Engine package is `docker.io` or `docker-ce`, and the package literally named `docker` is unrelated (UNVERIFIED-LIVE: current archive contents for the pinned release). `git` is used by `setup_btcpay_server` and is absent from the list, which is the same gap twice.
**Fix.**
```bash
require_dependencies() {
    info "Verifying base dependencies..."
    declare -A pkg_for=(
        [curl]=curl [bzip2]=bzip2 [tar]=tar [jq]=jq
        [docker]=docker.io [nginx]=nginx [git]=git
    )
    local missing=()
    for cmd in "${!pkg_for[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("${pkg_for[$cmd]}")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Installing missing packages: ${missing[*]}"
        apt-get update -qq
        apt-get install -y -qq "${missing[@]}"
    fi
    command -v docker >/dev/null 2>&1 || { err "docker is still unavailable after install"; exit 1; }
    if ! docker compose version >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y -qq docker-compose-plugin
    fi
    docker compose version >/dev/null 2>&1 || { err "docker compose plugin unavailable"; exit 1; }
}
```
**Operator decision required.** `docker.io` and `docker-ce` differ in version cadence. Pick one and record it next to the Xray and Monero pins.
**Residual risk.** The dependency versions are still whatever the archive holds at run time, unlike the digest-pinned Xray and Monero artifacts.

---

**F-25 | Domain C | Unprotected swap is detected and then tolerated**
**Severity:** P1. **File:** `server/wins_data_plane_setup_ONETOUCH.sh`, `wins_early_swap_source_is_protected` and its caller.
**Evidence:** `wins_early_swap_source_is_protected()` resolves the backing device and checks `lsblk -spno TYPE ... | grep -x crypt`, and the caller warns rather than aborting when `swapoff` fails.
Accepted from Seat 1 F-9, with the remedy bounded. A node that holds gateway static keys, admission keys, and cover certificate keys in memory, with swap on an unencrypted block device, can page that material to persistent storage. The detection helper exists precisely because someone understood this; the caller then downgrades the result to a warning.
**Fix.**
```bash
    swapoff "${swap_dev}" || {
        if [[ "${WINS_ALLOW_UNPROTECTED_SWAP:-0}" == "1" ]]; then
            echo "[WARN] Unprotected swap ${swap_dev} could not be disabled; continuing because WINS_ALLOW_UNPROTECTED_SWAP=1. Key material may reach unencrypted storage." >&2
        else
            echo "[ERR] Could not disable unprotected swap device ${swap_dev}. Aborting to keep key material out of unencrypted storage." >&2
            echo "[ERR] Either enable full-disk encryption on the backing device, or re-run with WINS_ALLOW_UNPROTECTED_SWAP=1 to accept the exposure." >&2
            exit 1
        fi
    }
```
I add the override to Seat 1's bare `exit 1`: a low-RAM node that genuinely needs swap must still be installable, and the environment variable turns an invisible tolerance into a recorded operator decision.
**Operator decision required. ** Confirm the data plane node's swap backing device is encrypted. If it is not and swap cannot be disabled, set the variable deliberately and record the exposure.
**Residual risk.** Pages written before this installer ran are already on disk. Disabling swap now does not erase them; only re-provisioning the host onto an encrypted volume does.

---

**F-26 | Domain D | The default decision-log path cannot satisfy the module's own filesystem checks**
**Severity:** P1. **File:** `router/security.py`, `decision_log_path()` and `_validate_private_ancestors()`.
**Evidence:** `os.environ.get("DECISIONS_FILE", "/tmp/router_decisions.jsonl")` against `if stat.S_IMODE(parent_info.st_mode) != 0o700: raise RuntimeError(f"{label} directory permissions must be 0700")`.
Defect unanimous with Seat 1 F-6; their replacement path is refuted above because `/var/log/winsvpn` is not held at 0700 by anything in the packet, which converts a certain failure into a likely one. `main.py` exposes `LAST_LOG_ERROR` because this failure was already observed.
**Fix.**
```python
def decision_log_path() -> Path:
    return _absolute_file_path(
        os.environ.get("DECISIONS_FILE", "/var/lib/winsvpn-router/router_decisions.jsonl"),
        "DECISIONS_FILE",
    )
```
```ini
[Service]
StateDirectory=winsvpn-router
StateDirectoryMode=0700
UMask=0077
Environment=DECISIONS_FILE=/var/lib/winsvpn-router/router_decisions.jsonl
Environment=SMART_ROUTER_NONCE_JOURNAL_PATH=/var/lib/winsvpn-router/replay-nonces.sqlite3
```
`StateDirectory` with `StateDirectoryMode` makes 0700 a property systemd enforces at every start rather than a hope about the filesystem. Add a startup assertion beside `replay_journal_ready()` that opens and closes the decision log once, so a misconfigured path fails at boot.
**Operator action required.** Grep fleet env files for `DECISIONS_FILE=/tmp` and remove those overrides, since an explicit setting survives this change.
**Residual risk.** Deployments not yet moved to the updated unit keep the old behavior until the unit ships.

---

**F-27 | Domain D | The router security boundary is an exact-path allowlist rather than deny-by-default**
**Severity:** P1. **File:** `router/security.py` (`PROTECTED_PATHS`), `router/main.py` (`DeadlineRouterSecurityMiddleware.__call__`).
**Evidence:** `if scope["type"] != "http" or scope.get("path") not in router_security.PROTECTED_PATHS: await self.app(scope, receive, send); return`
Unchanged; no other seat reached it. Authentication applies to seven fixed strings, so every route outside that set, present or future, is served unauthenticated, and `StrictJSONMiddleware` inherits the same set.
**Fix.**
```python
# router/security.py
PUBLIC_PATHS = {"/favicon.ico", "/livez"}   # unauthenticated by explicit decision only
```
```python
# router/main.py, in DeadlineRouterSecurityMiddleware.__call__
if scope["type"] != "http" or scope.get("path") in router_security.PUBLIC_PATHS:
    await self.app(scope, receive, send)
    return
```
Apply the same inversion in `StrictJSONMiddleware`, protecting every `POST`, `PUT`, and `PATCH` whose path is not in `PUBLIC_PATHS`. Keep `PROTECTED_PATHS` as a test fixture asserting each of the seven still resolves to an authenticated route.
**Residual risk.** Anything relying on an unlisted unauthenticated route breaks at deploy. `/livez` is carved out so an external health check has a target that does not require HMAC signing.

---

**F-28 | Domain E | A version bump silently disables every download on the site**
**Severity:** P1. **File:** `web/_worker.js`, `downloadManifestBoundPaths()`.
**Evidence:** `payload.release_id !== "v1.0.16+33"` inside the early return yielding an empty `authorized` set, combined with the `/downloads` branch returning `{ action: "not_found" }` for any unauthorized path.
Unchanged. The pin is publication authority and should stay; the failure mode is that a regenerated manifest turns every download URL into a silent 404, which for a user on a censored network is indistinguishable from interference.
**Fix.**
```js
const EXPECTED_RELEASE_ID = "v1.0.16+33"; // generated by tools/sync_release_id.py

export function downloadManifestBoundPaths(payload) {
  const authorized = new Set();
  if (!payload || payload.schema !== "winsvpn-download-manifest-v1" || !Array.isArray(payload.artifacts)) {
    return authorized;
  }
  if (payload.release_id !== EXPECTED_RELEASE_ID) {
    console.warn(
      `download manifest release_id ${String(payload.release_id)} does not match the deployed worker pin ${EXPECTED_RELEASE_ID}; serving no downloads`
    );
    return authorized;
  }
  return authorized;
}
```
Add `tools/sync_release_id.py` deriving `EXPECTED_RELEASE_ID` from `pubspec.yaml` and failing the release gate when `web/_worker.js`, `android/app/build.gradle.kts`, and `web/releases/downloads.json` disagree.
**Residual risk.** A stale Worker against a fresh manifest still serves nothing. The warning is the difference between a five-minute diagnosis and an outage of unknown cause.

---

**F-29 | Domain G | The browser extension announces the product while the app disguises it**
**Severity:** P1. **File:** `extension/manifest/base.jsonc`.
**Evidence:** `"name": "Win's VPN Companion"` and `"description": "Sends chosen sites through the Win's VPN desktop tunnel..."`
Unchanged. The Android client presents as a calculator; the extension on the same user's desktop is named in the browser extension page, the profile directory, and any forensic inventory. The disguise is as strong as its least disguised component.
**Fix.**
```jsonc
  "name": "Site Routing Helper",
  "version": "1.0.16",
  "description": "Routes chosen sites through a local desktop proxy. Does nothing unless that desktop application is running.",
```
Keep the existing `optional_host_permissions` reasoning and the leakscan gate. Add an assertion to `tools/leakscan.py` that no packaged file contains the product name.
**Operator decision required.** This trades store discoverability for disguise. Discoverability moves to the website download page (UNVERIFIED-LIVE: whether Chrome Web Store and AMO permit a listing name unrelated to the developer's other properties). The owner makes this call; the extension is where the cost of the disguise is lowest.
**Residual risk.** Users who search the store by product name will not find it.

---

**F-30 | Domain E | The PWA manifest makes an unqualified no-logs claim the site's own text contradicts**
**Severity:** P1. **File:** `web/manifest.json`.
**Evidence:** `"description": "AI-powered, no-logs VPN protection made in America."` against `publicFallbackAnswer` in `web/_worker.js`: `The service may keep limited account, device-count, payment, referral, security, and legal-acceptance metadata`.
Unchanged. The Worker's statement is careful and accurate; the manifest strips every qualifier, and the manifest is what an installed-app surface displays.
**Fix.**
```json
    "description": "Privacy and anti-censorship VPN. No logs of browsing history, DNS queries, traffic contents, or destinations. Limited account and payment metadata is retained to operate the service.",
```
Align `app_store/*/metadata/en-US/short_description.txt` to the same wording, and add a check to `tools/verify_live_deployment.py` that the live `manifest.json` description equals the repository's.
**Residual risk.** A longer description may truncate in some install prompts (UNVERIFIED-LIVE: current enforcement posture on VPN no-logs claims). Truncation of an accurate sentence beats a complete inaccurate one.

---

**F-31 | Domain C | Staged gateway secrets are never removed after deploy**
**Severity:** P1. **File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy()` and `cmd_stage_help()`.
**Evidence:** `keys/<role>/winn3-gateway-static.key (SECRET 600)` and `keys/<role>/winn3-gateway-admission.key (SECRET 600)` staged into `[ROOT]/winn3-stage/`, installed with `install -m 600 ...`, with no removal of the staged originals. `cmd_rollback` shreds the installed copies only.
Unchanged. A rolled-back node still holds the gateway static key, the admission key, and the cover certificate keys in the staging directory.
**Fix.** At the end of `cmd_deploy`, after the installed copies verify:
```bash
  for secret in winn3-gateway-static.key winn3-gateway-admission.key \
                cover/winn-leaf-key.pem cover/cover-key.pem cover/ech-server-keys.json; do
    if [[ -f "$STAGE/$secret" ]]; then
      shred -u "$STAGE/$secret" 2>/dev/null || rm -f "$STAGE/$secret"
    fi
  done
  RECEIPT "staged secret material shredded from $STAGE"
```
Mirror the loop into `cmd_rollback` so a rollback after a failed deploy also clears staging, and state in `cmd_stage_help` that the staging directory is consumed rather than retained.
**Residual risk.** `shred` does not guarantee extent overwrite on copy-on-write or log-structured filesystems. Full-disk encryption covers that case and should be confirmed present on the gateway nodes.

---

**F-32 | Domain C | Forty audit receipt files are deleted in the working tree**
**Severity:** P1. **File:** `docs/evidence/codex_astra_audit_round{2..20}.md`, `docs/evidence/codex_sol_audit_round{2..20}.md`.
**Evidence:** git status shows ` D` on all forty, alongside ` M docs/blueprints/DEBATE_PROTOCOL.md` and ` M docs/evidence/codex_astra_audit.md`.
Unchanged. Section 13.6 requires every round's output to persist locally and certification to bind to a receipt manifest. Deleting nineteen rounds of receipts per podium while the protocol document is itself being edited removes the chain those certifications rest on, and the working-tree state cannot be distinguished from an accident.
**Fix.** Do not commit the deletion. Restore and archive:
```bash
git restore --source=HEAD --staged --worktree -- docs/evidence/
git checkout -b evidence/archive-rounds-2-20
mkdir -p docs/evidence/archive
git mv docs/evidence/codex_astra_audit_round*.md docs/evidence/archive/
git mv docs/evidence/codex_sol_audit_round*.md   docs/evidence/archive/
git commit -m "Archive audit rounds 2-20 receipts under docs/evidence/archive (no content removed)"
```
**Operator decision required.** If the removal was intentional, section 13.7.6 applies: write a tombstone per artifact recording location, reason, digest of the removed text, digest of the resulting artifact, identity, timestamp, and removal class, before the deletion is committed.
**Residual risk.** The archive grows without bound. A retention window for old receipts is a separate deliberate change with its own tombstones.

---

**F-33 | Domain H | Apple platforms have no camouflage equivalent**
**Severity:** P1. **File:** `apple/WinsTunnelCore/WinsPacketTunnelEngine.swift`, `apple/WinsTunnelCore/WinsTunnelConfig.swift`, `apple/EngineWrappers/WinsXrayVlessWsTransport.m` (all modified; bodies not in this packet).
**Evidence:** Domain A ships a full disguise mechanism (`activity-alias .LauncherDecoy`, `DISGUISED_DISPLAY_NAME`, `SecretCodeReceiver`); nothing in the packet's Apple inventory or in `app_store/` indicates any equivalent.
Unchanged, and it is the defensible Apple-domain finding this round. Seat 1's F-19 proposed enabling the winn3 engine on Apple platforms, which is refuted above as a feature request against code that does not exist in the packet. A user who follows the product's Android threat guidance and then installs the iOS build gets a device naming the product on the home screen, in Settings, and in the VPN configuration list (UNVERIFIED-LIVE: current App Store policy does permit alternate icons but not alternate display names).
**Fix.** Add to `SECURITY_NOTES_FINAL.md` and to the in-app first-run notice:
```markdown
## Camouflage availability by platform
- Android, Android TV, Wear OS: launcher label and icon camouflage available (opt-in).
- iOS, macOS, watchOS: no camouflage. The app name is visible on the home screen,
  in Settings, and in the system VPN configuration list.
- Windows, Linux: see the desktop notes; the installed program name is visible.
Users in a jurisdiction where possession of circumvention software is itself a risk
should treat the Apple builds as fully attributable.
```
Evaluate the alternate-app-icon API as a partial measure in a later round.
**Residual risk.** Documentation does not reduce the exposure; it stops a user from relying on protection that is not there. That is the whole of what this round can deliver for H, and domain H stays inventory-only until the Swift bodies are in a packet.

---

**F-34 | Domain C | Two assignment lines in the deployment scripts are not valid shell as presented**
**Severity:** P1. **File:** `server/wins_data_plane_setup_ONETOUCH.sh`, near `ADMIN_TOKEN_DEFAULT=""`.
**Evidence:** `ADMIN_TOKEN: \"[REDACTED]\"` and `NODE_TOKEN: \"[REDACTED]\"s/^NODE_TOKEN="\(.*\)"$/\1/p' "${NODE_ENV_FILE}" | tail -n 1)"`
Unchanged, still filed as verify-first rather than asserted. The second line shows a redaction pass having overwritten the left half of a `sed -n '...p'` command substitution, and the same pass turned `MONERO_CLI_VERSION="v[IP_2]"` in the Spain script into an IP alias where a version string belongs, which confirms the redactor rewrites content outside its intended class. If the literals are in the repository, `ADMIN_TOKEN:` parses as a command name and `set -Eeuo pipefail` aborts the installer before provisioning anything.
**Fix.** Confirm, then repair only if confirmed:
```bash
bash -n server/wins_data_plane_setup_ONETOUCH.sh && echo "parses clean"
grep -n 'ADMIN_TOKEN:\|NODE_TOKEN:' server/wins_data_plane_setup_ONETOUCH.sh
```
If present, the intended lines are:
```bash
ADMIN_TOKEN="${ADMIN_TOKEN:-$ADMIN_TOKEN_DEFAULT}"
NODE_TOKEN="${NODE_TOKEN:-$NODE_TOKEN_DEFAULT}"
if [[ -z "${NODE_TOKEN}" && -r "${NODE_ENV_FILE}" ]]; then
  NODE_TOKEN="$(sed -n 's/^NODE_TOKEN="\(.*\)"$/\1/p' "${NODE_ENV_FILE}" | tail -n 1)"
fi
```
**Arbiter action required.** Add `bash -n` over every shell file and `python -m py_compile` over every Python file to the packet build, after redaction, so a packet can never present broken code as evidence to three podiums at once.
**Residual risk.** If these are redaction artifacts the finding costs one `bash -n` run. If they are real it is the difference between a working installer and one that dies partway through.

---

### P2

---

**F-35 | Domain E | Rate-bucket eviction lets a limited client reset its own counter**
**Severity:** P2. **File:** `web/_worker.js`, `pruneRateBuckets()` and `isolateLocalRateLimited()`.
**Evidence:** `while (rateBuckets.size > RATE_BUCKET_CAP) { rateBuckets.delete(rateBuckets.keys().next().value); }` and `if ((rateBuckets.size & 127) === 0) pruneRateBuckets(now);`
Unchanged in substance, upgraded in importance by F-9: Seat 3 proved this fallback is the only limiter in production, so its resettability is not academic. Eviction is insertion-ordered and drops the oldest key, which is frequently an actively limited client, and the prune trigger tests a size congruence that a growing and shrinking map can step over.
**Fix.**
```js
function pruneRateBuckets(now) {
  for (const [key, bucket] of rateBuckets) {
    if (bucket.reset <= now) rateBuckets.delete(key);
  }
  if (rateBuckets.size > RATE_BUCKET_CAP) {
    // Evict the buckets closest to expiry, never the ones actively over limit.
    const byReset = [...rateBuckets.entries()].sort((a, b) => a[1].reset - b[1].reset);
    for (let i = 0; rateBuckets.size > RATE_BUCKET_CAP && i < byReset.length; i++) {
      if (byReset[i][1].count <= 1) rateBuckets.delete(byReset[i][0]);
    }
    while (rateBuckets.size > RATE_BUCKET_CAP) {
      rateBuckets.delete(rateBuckets.keys().next().value);
    }
  }
}

let pruneCounter = 0;
function isolateLocalRateLimited(keyPrefix, ip, limit, windowMs) {
  const now = Date.now();
  if ((++pruneCounter & 127) === 0) pruneRateBuckets(now);
}
```
**Residual risk.** Isolate-local limiting stays isolate-local. The zone rule in F-9 is the actual control; this stops the fallback from being trivially resettable.

---

**F-36 | Domain G | The endpoint module documents a pinned host the code does not enforce, and `pacToken` never asserts it**
**Severity:** P2. **File:** `extension/src/core/endpoint.js`, `validateEndpoint()` and `pacToken()`.
**Evidence:** the header states `the host comes from a constant compiled into this extension`, while `validateEndpoint()` accepts any host passing `isLoopbackHost` (all of `127.0.0.0/8` and `::1`); and `pacToken` reads `endpoint.host` and `endpoint.port` directly without calling `validateEndpoint` at all.
Merged: my Turn 1 F-28 plus Seat 3 F-11. Seat 3's half is the sharper one, because a "final assertion" that is not on the path `buildPac` takes is not an assertion. Seat 1's F-13 proposed stripping IPv6 brackets from this same function, which is refuted above as a defect-introducing change.
**Fix.**
```js
export function pacToken(endpoint) {
  const checked = validateEndpoint(endpoint);
  if (!checked.ok) {
    throw new TypeError('invalid loopback proxy endpoint');
  }
  endpoint = checked.endpoint;

  const bare = endpoint.host.startsWith('[') && endpoint.host.endsWith(']')
    ? endpoint.host.slice(1, -1)
    : endpoint.host;
  const host = bare.includes(':') ? `[${bare}]` : bare;
  return `PROXY ${host}:${endpoint.port}`;
}
```
and inside `validateEndpoint`, keep both the pin and the class check:
```js
if (endpoint.host !== LOOPBACK_HOST) {
  return { ok: false, reason: 'endpoint host is not the pinned loopback constant' };
}
if (!isLoopbackHost(endpoint.host)) {
  return { ok: false, reason: 'endpoint host is not a numeric loopback address' };
}
```
Keep the bracketing exactly as written. Add Seat 3's tests: `buildPac` throws for a routable host, port 0, port 65536, a non-integer port, and a non-HTTP kind.
**Residual risk.** Seat 3's residual risk carries over and matters: the background caller must treat the thrown error as a failed connection and must not install `PAC_ALL_DIRECT` as an automatic fallback, since that would convert a validation failure into a full traffic leak. That caller is not in this packet and is added to the deep-dive list.

---

**F-37 | Domain E | The Pages preview origin is a trusted CORS origin for payment routes**
**Severity:** P2. **File:** `web/_worker.js`, `allowedOrigins`.
**Evidence:** `"https://winsvpn.pages.dev",` in the set consumed by `corsHeaders()` and `paymentOriginGuard()`.
Unchanged. Preview and production share one allowlist, so any deployment on the project's `pages.dev` host can drive the payment POST routes with credentials echoed back by CORS, on a host outside the organization's certificate and DNS control.
**Fix.**
```js
const allowedOrigins = new Set([
  "https://winsvpn.org",
  "https://www.winsvpn.org",
  "https://winsvpn.com",
  "https://www.winsvpn.com",
]);
for (const extra of String(env.EXTRA_ALLOWED_ORIGINS || "").split(",")) {
  const value = extra.trim();
  if (value.startsWith("https://")) allowedOrigins.add(value);
}
```
**Residual risk.** An operator who sets `EXTRA_ALLOWED_ORIGINS` in production reintroduces the gap, but the variable name makes it visible in the Cloudflare dashboard, which the hardcoded entry did not.

---

**F-38 | Domain E | Cached public config responses do not declare `Vary: Origin`**
**Severity:** P2. **File:** `web/_worker.js`, `corsHeaders()` and `publicConfigCacheKey()`.
**Evidence:** `const variant = allowedOrigins.has(origin) ? origin : "no-origin";` partitions the Worker's own cache by origin, while the response headers carry no `Vary`.
Accepted from Seat 1 F-16. The Worker cache key is correct; any intermediate or browser cache in front of it is not told the response varies by request origin, so an `Access-Control-Allow-Origin` value computed for one origin can be replayed to another.
**Fix.**
```js
  headers["vary"] = "Origin";
  return headers;
```
as the last statement of `corsHeaders()`, before the return.
**Residual risk.** None identified. Intermediate caches partition correctly once the header is present.

---

**F-39 | Domain C | A checksum staged beside the binary it checks provides integrity, not authenticity**
**Severity:** P2. **File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy()` and `cmd_verify_hub()`.
**Evidence:** `(cd "$STAGE" && sha256sum -c "$BIN_SRC.sha256") || die "gateway binary sha256 mismatch"`, where `cmd_stage_help` instructs copying the binary and its `.sha256` together over the same channel.
Unchanged. Anyone able to replace the binary in transit or in staging replaces the sidecar in the same motion. The check detects truncation and nothing adversarial.
**Fix.**
```bash
role_facts() {
  case "${1:-}" in
    demo-gw-a)
      ROLE=demo-gw-a; GW_ID=demo-gw-a; ENDPOINT=[IP_3]
      SUBNET=10.10.0.0/24; INNER_V4=10.10.0.1; CLIENT_V4=10.10.0.2
      VERIFY_HOSTPORT=52711
      GW_SHA256="${WINN3_GATEWAY_SHA256:?export the reviewed gateway binary digest}" ;;
```
```bash
  local actual
  actual="$(sha256sum "$BIN_SRC" | awk '{print $1}')"
  [[ "$actual" == "$GW_SHA256" ]] || die "gateway binary $actual does not match the reviewed digest $GW_SHA256"
```
**Residual risk.** The reviewed digest still has to reach the node, now through the committed script rather than a sidecar file, which is the intended place for it.

---

**F-40 | Domain C | The replay journal has a documented replacement hazard and no guard**
**Severity:** P2. **File:** `server/wins_winn3_gateway_install.sh`, `provision_replay_journal` and the `WINN3_REPLAY_JOURNAL_DIR` comment block.
**Evidence:** `Do not delete or replace the journal while the service is running: on Unix an open file descriptor can keep writing an unlinked inode that a restart cannot reload. Stop the service before journal recovery.`
Unchanged. The hazard is stated precisely and enforced by nothing, and the property lost is exactly the one the durable journal exists to provide.
**Fix.** In `provision_replay_journal`, before any write that would replace the journal inode:
```bash
  if systemctl is-active --quiet winn3-gateway.service; then
    if [[ -e "${WINN3_REPLAY_JOURNAL_PATH}" ]]; then
      err "winn3-gateway.service is active and ${WINN3_REPLAY_JOURNAL_PATH} exists."
      err "Replacing the journal inode under a running process silently disables durable replay refusal."
      err "Run: systemctl stop winn3-gateway.service, then re-run this installer."
      exit 1
    fi
  fi
```
**Residual risk.** A re-install that now refuses costs one stop-and-retry cycle, against silently losing the replay guarantee.

---

**F-41 | Domain D | SQLite sidecar files are not permission-checked**
**Severity:** P2. **File:** `router/security.py`, `replay_journal_ready()` and `DurableReplayGuard`.
**Evidence:** `_validate_private_regular_file(path, maximum_bytes, "nonce journal")` applied to the journal path only, while the connection uses WAL-style access (`BEGIN IMMEDIATE`, a `replay_state` table, a busy timeout).
Unchanged. SQLite creates `-wal` and `-shm` beside the database with modes derived from the process umask, so a service under the default 022 produces 0644 sidecars next to a carefully 0600 main file. Content is nonce hashes and timestamps, so impact is limited, but the module's stated posture is that every file it owns is 0600.
**Fix.** `UMask=0077` in the unit (already present in the F-26 block), plus:
```python
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(path) + suffix)
            if sidecar.exists():
                _validate_private_regular_file(
                    sidecar, maximum_bytes, f"nonce journal{suffix}", enforce_size=False
                )
```
**Residual risk.** Sidecars are recreated on each connection, so a unit restarted without `UMask=0077` recreates the exposure. The assertion turns that into a visible failure.

---

**F-42 | Domain E | The live-deployment verifier has two parsing weaknesses that can invert its verdict**
**Severity:** P2. **File:** `tools/verify_live_deployment.py`, `repo_header()` and `inline_blocks()`.
**Evidence:** `for raw in HEADERS_FILE.read_text(encoding="utf-8").splitlines(): line = raw.strip(); if line.lower().startswith(prefix): return line[len(prefix):].strip()` and `INLINE_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.S | re.I)`.
Unchanged, and load-bearing for F-1: the CSP gate proposed there runs through this parser. `repo_header` returns the first matching header anywhere in `web/_headers`, including a path-scoped block, and `[^>]*` terminates at the first `>` even inside a quoted attribute value.
**Fix.**
```python
def repo_header(name: str) -> str:
    """The value of `name` in the repository's GLOBAL web/_headers block ("/*")."""
    prefix = f"{name.lower()}:"
    in_global = False
    for raw in HEADERS_FILE.read_text(encoding="utf-8").splitlines():
        if raw and not raw[0].isspace():
            in_global = raw.strip() == "/*"
            continue
        if not in_global:
            continue
        line = raw.strip()
        if line.lower().startswith(prefix):
            return line[len(prefix):].strip()
    raise SystemExit(f"{HEADERS_FILE} declares no global {name} header")
```
```python
INLINE_SCRIPT_RE = re.compile(
    r"""<script\b((?:[^>"']|"[^"]*"|'[^']*')*)>(.*?)</script\s*>""", re.S | re.I
)
INLINE_STYLE_RE = re.compile(
    r"""<style\b((?:[^>"']|"[^"]*"|'[^']*')*)>(.*?)</style\s*>""", re.S | re.I
)
```
**Residual risk.** Regex HTML parsing stays approximate. The checker compares a repository build against a deployed one produced by the same generator, so approximation is tolerable as long as it is identical on both sides, which these patterns are.

---

**F-43 | Domain C | Gateway deploy changes the node-wide default queueing discipline**
**Severity:** P2. **File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy()`.
**Evidence:** the heredoc writing `/etc/sysctl.d/60-winn3-gateway-pps.conf` containing `net.core.default_qdisc = fq`, applied with `sysctl -p`, and a rollback path that states `sysctls ... left in place: one-way by design`.
Unchanged. `net.core.default_qdisc` is global and changes the queueing behavior of interfaces created after it, including any AmneziaWG interface brought up later on a node whose downlink datapath is under a freeze directive.
**Fix.** Remove `net.core.default_qdisc = fq` from the drop-in and scope the change:
```bash
  if ip link show winn3gw0 >/dev/null 2>&1; then
    tc qdisc replace dev winn3gw0 root fq || NOTE "tc qdisc replace on winn3gw0 failed; leaving kernel default"
  fi
```
Keep the backlog and budget knobs, which are receive-path and do not alter existing interfaces' queueing discipline.
**Residual risk.** Per-interface `tc` state does not survive an interface recreate. Moving the `tc` call into the gateway unit's `ExecStartPost` is the durable form and is a change to the gateway unit, not to the datapath.

---

**F-44 | Domain G | Extension version is decoupled from the release identity**
**Severity:** P2. **File:** `extension/manifest/base.jsonc`.
**Evidence:** `"version": "1.0.0"` against `versionName = "1.0.16"` / `versionCode = 33` and `release_id !== "v1.0.16+33"`.
Unchanged. Three ship channels carry three opinions about which release this is, so support cannot map a reported extension version to a build and the evidence pipeline cannot bind the extension artifact to the rest.
**Fix.**
```jsonc
  "version": "__RELEASE_VERSION__",
```
with the merge step substituting `1.0.16` from `pubspec.yaml`, and the release gate asserting equality across `pubspec.yaml`, `android/app/build.gradle.kts`, `web/_worker.js`, and the generated extension manifests. Same generator as F-28.
**Residual risk.** Chrome and Firefox version grammars differ from `major.minor.patch+build` (UNVERIFIED-LIVE for currently accepted formats). Use the `major.minor.patch` prefix for the extension and record the build number in a separate manifest key.

---

**F-45 | Domain E | The AI chat's secret-request filter is a protocol-name oracle**
**Severity:** P2. **File:** `web/_worker.js`, `containsSecretRequest()`.
**Evidence:** `/\b(secret|token|...|xray|amnezia|awg|wireguard|port\s+\d+|control\s+hub\s+ip|server\s+ip|protocol\s+stack|underlying\s+protocol)\b/i` paired with a distinctive refusal string.
Unchanged. The refusal is distinguishable from the generic answer, so the keyword list is binary-searchable from the public endpoint, which confirms from outside the exact set of technologies the operator considers sensitive.
**Fix.**
```js
function publicFallbackAnswer(message) {
  const q = String(message || "").toLowerCase();
  if (containsSecretRequest(q)) {
    // Identical to the generic closing answer, so the refusal is not a signal.
    return "I can help with setup, free server access, premium access, privacy, downloads, server selection, referrals, and connection troubleshooting.";
  }
  return "I can help with setup, free server access, premium access, privacy, downloads, server selection, referrals, and connection troubleshooting.";
}
```
**Residual risk.** Timing may differ marginally between the filtered and unfiltered paths. Both are local string operations on the same request, far below network noise.

---

**F-46 | Domain F | The hub commerce template omits the Monero variables the Spain node emits**
**Severity:** P2. **File:** `server/hub-commerce.env.example`.
**Evidence:** the template documents `BTCPAY_URL`, `BTCPAY_STORE_ID`, `BTCPAY_API_KEY`, `BTCPAY_WEBHOOK_SECRET` and no Monero keys, while `print_summary()` in the Spain script emits `MONERO_WALLET_RPC_URL`, `MONERO_WALLET_RPC_USER`, and `MONERO_WALLET_RPC_PASS` for the hub to consume.
Accepted from Seat 1 F-7. An undocumented handoff is where an operator pastes a secret into the wrong file.
**Fix.**
```diff
 BTCPAY_WEBHOOK_SECRET=
+
+# Monero wallet RPC, produced by server/spain_crypto_payments_setup.sh on the Spain node.
+# URL must be the management-tunnel address, never the public btcpay hostname (see F-22).
+# Set all three or none. Never commit real values; this file is a template.
+MONERO_WALLET_RPC_URL=
+MONERO_WALLET_RPC_USER=
+MONERO_WALLET_RPC_PASS=
```
Add the same all-or-none validation the BTCPay block already receives, and confirm the hub setup script parses the three into `/root/vpn_auth.env`.
**Residual risk.** Adding the keys to a template invites an operator to fill them in a file that may not be gitignored. Confirm the example file's real counterpart is ignored before shipping this.

---

**F-47 | Domain C | Two installer flags default to a value chosen from one node's current state**
**Severity:** P2. **File:** `server/wins_winn3_gateway_install.sh`, `WINN3_GATEWAY_MANAGE_FIREWALL` and `WINN3_GATEWAY_FORWARD`.
**Evidence:** `WINN3_GATEWAY_MANAGE_FIREWALL="${WINN3_GATEWAY_MANAGE_FIREWALL:-0}"` justified by `on the fleet's only node the host INPUT policy is ACCEPT`, and `WINN3_GATEWAY_FORWARD=0 (the default...): an IN-PROCESS REFLECTOR. It forwards nothing to the internet`.
This is my counter-proposal to Seat 1 F-5 and F-10, both of which I refuse as written. Seat 1's diagnosis is correct: a default justified by one host's accident is not a default. Their remedy flips each value, which applies a default-drop INPUT policy to the fleet's only data plane node with no SSH allowlist verified first, and silently converts a reflector into a forwarder requiring `CAP_NET_ADMIN` and `/dev/net/tun`. Both changes mutate production on the next installer run. The correct shape is that neither value is assumed.
**Fix.**
```bash
: "${WINN3_GATEWAY_MANAGE_FIREWALL:?set to 0 (leave host firewall alone) or 1 (apply the WINVPN-INPUT chain). No default: the correct value depends on this host's INPUT policy.}"
: "${WINN3_GATEWAY_FORWARD:?set to 0 (in-process reflector) or 1 (forward to the internet; requires CAP_NET_ADMIN and /dev/net/tun). No default: this selects the datapath.}"

if [[ "${WINN3_GATEWAY_MANAGE_FIREWALL}" == "1" ]]; then
  current_policy="$(iptables -S INPUT | awk '/^-P INPUT/ {print $3}')"
  echo "[INFO] host INPUT policy is currently ${current_policy}; this run will install the WINVPN-INPUT chain."
  iptables -S INPUT | grep -qE -- '--dport (22|2222)' || {
    echo "[ERR] No existing INPUT rule accepts SSH on 22 or 2222. Applying a drop policy now would lock this host out." >&2
    echo "[ERR] Add an explicit SSH accept rule first, then re-run." >&2
    exit 1
  }
fi
```
**Operator decision required.** Set both variables explicitly in the node's staged environment. For the fleet's current data plane node, the values that preserve today's behavior are `WINN3_GATEWAY_MANAGE_FIREWALL=0` and `WINN3_GATEWAY_FORWARD=0`; changing either is a deliberate datapath or firewall change that belongs in its own maintenance window with console access available.
**Residual risk.** Every existing automation invoking these installers without the variables now fails until updated. That is the point: the failure is loud and happens before the host is touched.

---

**F-48 | Domain C | Dual-auth credential presence is never asserted at deploy**
**Severity:** P2. **File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy()`.
**Evidence:** `[[ -f "$CRED_DIR/winn3-gateway-static.key" ]] || die "static key missing"` with no equivalent assertion for dual-auth material, against the release define `base64("WINS_WINN3_DUAL_AUTH=true")` applied to both release and debug targets in `android/app/build.gradle.kts`.
Accepted from Seat 1 F-11, with the filename dependency removed. If every shipped client has dual auth enabled and a gateway lacks the corresponding key material, handshakes fail after deploy reports success.
**Fix.** Derive the requirement from the staged environment rather than a guessed filename:
```bash
  if grep -qE '^WINN3_GATEWAY_DUAL_AUTH=1' "$STAGE/winn3-gateway.env"; then
    for f in "$STAGE"/winn3-gateway-dual-auth-*.key; do
      [[ -f "$f" ]] || die "WINN3_GATEWAY_DUAL_AUTH=1 is staged but no winn3-gateway-dual-auth-*.key is present"
    done
  fi
```
**Verification required before applying.** The exact dual-auth key filenames are not in this packet; Seat 1's `winn3-gateway-dual-auth-ed.key` is unconfirmed. Run `ls /etc/winn/credentials/` on a working gateway and pin the glob to what is actually there. UNVERIFIED-LIVE until then.
**Residual risk.** A present file is not a valid key. Presence checking catches the provisioning omission, not a corrupt or wrong-curve seed.

---

**F-49 | Domain D | Storage worker admission fails fast instead of waiting inside the request deadline**
**Severity:** P2. **File:** `router/main.py`, storage slot acquisition.
**Evidence:** `_STORAGE_SLOTS = threading.BoundedSemaphore(_STORAGE_MAX_WORKERS)` and `if not _STORAGE_SLOTS.acquire(blocking=False): raise TimeoutError("storage worker capacity exhausted")`.
Accepted from Seat 1 F-14 at P2, not P1. This is availability tuning, not a security boundary: a momentary burst rejects requests that a sub-deadline wait would have served.
**Fix.**
```python
    acquire_timeout = min(max(0.0, remaining), 0.25)
    if not _STORAGE_SLOTS.acquire(blocking=True, timeout=acquire_timeout):
        raise TimeoutError("storage worker capacity exhausted")
```
**Verification required.** `remaining` must be the deadline residual already computed in this scope. If it is not in scope at that point, compute it from the request deadline before the call rather than introducing a fixed sleep, which would ignore the deadline the middleware exists to enforce.
**Residual risk.** A 250 ms bounded wait under sustained saturation adds latency to requests that will be rejected anyway. Cap it at the smaller of the residual and 250 ms exactly as written so it can never outlive the deadline.

---

## 5. Items carried to Turn 3 as unresolved

- **Severity of F-9 and F-10.** I hold P1, Seat 3 holds P0. Resolvable with the monthly spend ceiling on the translate and AI keys.
- **Seat 3's F-13, F-14, F-15.** Not received. Arbiter retry required under 13.5 before my Turn 3 ballot can be complete.
- **UNVERIFIED-LIVE claims needing Arbiter verification under 13.3.** Monero CLI binding for `--disable-rpc-login` and `--confirm-external-bind` on the pinned release (F-5); systemd partial `${VAR}` expansion inside an ExecStart argument (F-4); Debian and Ubuntu package name for Docker Engine on the pinned release (F-24); Chrome Web Store and AMO listing-name policy (F-29); App Store alternate display name policy (F-33); Play restricted-permission policy for `QUERY_ALL_PACKAGES` (F-2); `play-services-wearable:19.0.0` binder validation (F-13); dual-auth key filenames (F-48).
- **Domains B and D remain under-evidenced.** My Turn 1 scope note stands. Domain B has one finding grounded in a quote from a deployment script and zero primary source; neither other seat improved on that. The deep-dive list from Turn 1 is unchanged, with the extension background caller from F-36 added as item 7.
