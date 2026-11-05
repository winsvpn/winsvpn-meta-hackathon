# Round 36 stage1: claude-opus5

# ROUND 36 TURN 1: INDEPENDENT PODIUM VERDICT

**Scope note before findings.** This packet contains no Go source (domain B), no hub application source (domain D), and no Apple source bodies (domain H). Findings in those domains are derived only from what the packet actually shows: deployment scripts that quote engine behavior, test filenames, and the git status list. I have not inferred code I cannot see, and I say so explicitly where a domain is under-evidenced.

---

## P0

### F-1 | Domain E | Third-party analytics and advertising endpoints are authorized on the public origin
**File:** `web/_headers` (global block, Content-Security-Policy line)
**Evidence:** `script-src 'self' 'sha256-...' 'sha256-...' https://www.googletagmanager.com https://connect.facebook.net ...; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://stats.g.doubleclick.net https://www.facebook.com ...; img-src 'self' data: https: https://www.facebook.com https://www.google-analytics.com https://www.google.com https://www.googleadservices.com`

Every visitor to the download and purchase origin has that visit reported to Google and Meta, with source IP and a persistent identifier. For a user in Myanmar, "fetched the Win's VPN site" is exactly the enumeration event the product overview names as the worst outcome, and the report leaves the browser outside the tunnel. Google Tag Manager in `script-src` also makes the two inline-script hashes ornamental: GTM injects arbitrary script by design, so the policy grants remote code execution to a tag container. `img-src ... https:` permits a pixel from any host.

**Fix.** Replace the global CSP line in `web/_headers` with:

```
  Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://applepay.cdn-apple.com https://pay.google.com; frame-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://pay.google.com; form-action 'self' https://www.paypal.com https://www.paypalobjects.com; upgrade-insecure-requests
```

Then delete the corresponding `<script>` tags and pixel markup from `web/index.html`, recompute both inline-script hashes and the inline-style hash (the edit changes them), and paste the new digests into the line above. Add a gate to `tools/verify_live_deployment.py` next to `REQUIRED_LIVE_MARKERS`:

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

**Residual risk.** PayPal and Google Pay frames still observe checkout visitors; that is intrinsic to hosted checkout. Cloudflare still sees every request at the edge.

---

### F-2 | Domain A | The calculator camouflage is cosmetic: package identity and a product-labelled alias survive it
**File:** `android/app/src/main/AndroidManifest.xml` (activity-alias `.LauncherReal`), `android/app/build.gradle.kts` (`applicationId = "org.winsvpn.app"`)
**Evidence:** `android:name=".LauncherReal" android:enabled="true" ... android:label="Win's VPN"` and `<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" tools:ignore="QueryAllPackagesPermission" />`

Three manifest-resident strings defeat the disguise against anyone holding the handset: the application id `org.winsvpn.app`, the alias label `Win's VPN`, and the alias pair itself. A disabled component is still returned by `PackageManager.getPackageInfo(..., MATCH_DISABLED_COMPONENTS)`, so the decoy and real aliases are both enumerable regardless of camouflage state. This app declares `QUERY_ALL_PACKAGES`, which proves any other installed app can run the same enumeration against it. The default install state is worse than the documented design: `.LauncherReal` ships `enabled="true"` and `.LauncherDecoy` ships `enabled="false"`, so a fresh install shows the product name on the home screen until the user opts in.

**Fix.** Three edits, all in this repository.

1. In `AndroidManifest.xml`, remove the product string from the manifest and take the real label from a neutral resource:
```xml
<activity-alias
    android:name=".LauncherReal"
    android:enabled="true"
    android:icon="@mipmap/ic_launcher"
    android:label="@string/launcher_real_label"
    android:targetActivity=".RealLauncherActivity"
    android:exported="true">
```
with `<string name="launcher_real_label">Calculator</string>` in the default `values/strings.xml` and the un-camouflaged product name rendered only inside the Flutter UI after PIN entry.

2. Delete the `QUERY_ALL_PACKAGES` permission line entirely. The `<queries>` block already present (VIEW over `http`/`https`) covers the only stated need, and removing it also removes a restricted-permission declaration from the store submission (UNVERIFIED-LIVE: current Play restricted-permission policy).

3. Extend `CamouflageLatchedSurfaceTest` (named in the manifest comment) with an assertion that no manifest attribute anywhere in `android/app/src/*/AndroidManifest.xml` contains the literal `Win's VPN`.

**Residual risk.** `org.winsvpn.app` is unchangeable for the existing Play listing without losing the update path for installed users. That identifier remains visible in `pm list packages`, Settings storage entries, and any local enumeration. State this limit in-app so users do not over-trust the disguise, and treat a neutral package identifier as a requirement for any future separate listing.

---

### F-3 | Domain F | Monero RPC password is written into a systemd unit and printed to the console and log
**File:** `server/spain_crypto_payments_setup.sh`, `setup_monero_service()` and `print_summary()`
**Evidence:** `--rpc-login ${rpc_user}:${rpc_pass} \\` inside the heredoc writing `/etc/systemd/system/monero-wallet-rpc.service`, and `printf 'MONERO_WALLET_RPC_PASS="%s"\n' "${rpc_pass}"`

The script takes care to write `${creds_file}` at mode 0600, then copies the same secret into a unit file created by `cat >` under the root umask (0644 on a stock Ubuntu image), and into the process argument vector, which is world-readable through `/proc/<pid>/cmdline`. `print_summary` then writes the cleartext password to stdout, which lands in the operator's terminal scrollback and in `LOG_FILE=/var/log/winsvpn/spain_crypto_setup.log` whenever the run is teed.

**Fix.** In `setup_monero_service()`, stop interpolating the secret and load it from the credentials file instead:

```bash
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

In `print_summary()`, replace the password line with a pointer:

```bash
    printf 'MONERO_WALLET_RPC_USER="%s"\n' "${rpc_user}"
    printf 'MONERO_WALLET_RPC_PASS: read from %s on the Spain node (never printed)\n' "${creds_file}"
```

Rotate the existing password on the live node after applying, since the current one is already in at least one terminal history and one log file.

**Residual risk.** `--rpc-login` is a command-line option, so the credential still appears in the argument vector of the running process. `ProtectProc=invisible` hides other processes from this unit but does not hide this unit from other local accounts; the reliable complement is mounting `/proc` with `hidepid=2`, which is a host-wide change and should be proposed separately. Root-level compromise reads the secret either way.

---

### F-4 | Domain F | Wallet RPC authentication may be disabled by the supplied flags, and the endpoint is publicly proxied
**File:** `server/spain_crypto_payments_setup.sh`, `setup_monero_service()` and `setup_nginx_proxy()`
**Evidence:** `--disable-rpc-login=0 \\` and `--confirm-external-bind=0` in the ExecStart, alongside `location /monero-rpc { proxy_pass http://127.0.0.1:18083/json_rpc; ... proxy_pass_header Authorization; }` reachable as `https://btcpay.winsvpn.org/monero-rpc`

`--disable-rpc-login` and `--confirm-external-bind` are presence-style switches in the Monero CLI (UNVERIFIED-LIVE: exact boost program_options binding for the pinned Monero release). Two outcomes are possible and both are bad. If the parser treats presence as assertion, login is switched off and the wallet RPC accepts unauthenticated JSON-RPC, which the nginx block then republishes to the internet through the Cloudflare tunnel with no authentication of its own. If the parser rejects an explicit value on a zero-token switch, the unit fails to start and the payment path is dead on arrival. The script never asserts which happened: `verify_services` prints `Monero RPC probe result: ${monero_test}` and continues on `|| true`.

**Fix.** Delete both flags from the ExecStart (the diff in F-3 already omits them), and convert the probe into a gate that proves authentication is enforced:

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

Separately, require authentication at the proxy edge as well, so a wallet-RPC misconfiguration is not internet-reachable on its own:

```nginx
    location /monero-rpc {
        satisfy all;
        allow 127.0.0.1;
        deny all;
        proxy_pass http://127.0.0.1:18083/json_rpc;
        ...
    }
```
and reach the endpoint from the Kansas hub over the management tunnel rather than through the public hostname (see F-19).

**Residual risk.** The wallet is view-only and the RPC is restricted, so the worst case is payment-flow enumeration rather than fund theft. Payment enumeration still links a donor address set to this organization.

---

### F-5 | Domain C | Root executes an unpinned remote script cloned at install time
**File:** `server/spain_crypto_payments_setup.sh`, `setup_btcpay_server()`
**Evidence:** `git clone https://github.com/btcpayserver/btcpayserver-docker.git "${BTCPAY_DOCKER_DIR}"` followed by `( cd "${BTCPAY_DOCKER_DIR}"; source "${env_file}"; . ./btcpay-setup.sh -i )`

Whatever is on that default branch at run time is sourced into a root shell on the payment gateway. There is no tag, no commit pin, and no signature check, in a repository that elsewhere pins Xray by archive digest and by extracted-binary digest, and pins the Monero CLI by SHA-256. The payment node is the single host holding the store credentials, so it is the node least able to absorb an upstream compromise or a hijacked release.

**Fix.**

```bash
BTCPAY_DOCKER_REF="${BTCPAY_DOCKER_REF:?set to a reviewed btcpayserver-docker tag}"
BTCPAY_DOCKER_COMMIT="${BTCPAY_DOCKER_COMMIT:?set to the full 40-hex commit for that tag}"

setup_btcpay_server() {
    info "Configuring BTCPay Server Docker deployment..."

    if [[ ! -d "${BTCPAY_DOCKER_DIR}/.git" ]]; then
        git clone --no-checkout https://github.com/btcpayserver/btcpayserver-docker.git "${BTCPAY_DOCKER_DIR}"
    fi
    git -C "${BTCPAY_DOCKER_DIR}" fetch --tags origin
    git -C "${BTCPAY_DOCKER_DIR}" checkout --detach "${BTCPAY_DOCKER_COMMIT}"
    local head
    head="$(git -C "${BTCPAY_DOCKER_DIR}" rev-parse HEAD)"
    if [[ "${head}" != "${BTCPAY_DOCKER_COMMIT}" ]]; then
        err "btcpayserver-docker HEAD ${head} does not match the reviewed commit ${BTCPAY_DOCKER_COMMIT}"
        exit 1
    fi
    if ! git -C "${BTCPAY_DOCKER_DIR}" verify-tag "${BTCPAY_DOCKER_REF}" >/dev/null 2>&1; then
        warn "btcpayserver-docker tag ${BTCPAY_DOCKER_REF} carries no verifiable signature; commit pin is the only control."
    fi
    ...
}
```

Record the reviewed tag, commit, and review date beside the Xray pin constants so the two supply-chain pins live in one place.

**Residual risk.** A pinned commit that was already malicious is still executed. The commit pin converts an open-ended exposure into a one-time review decision, which is the correct shape but not immunity.

---

### F-6 | Domain G | PAC host rules are never normalized, so listed-mode routing silently misses the exact sites the user protected
**File:** `extension/src/core/pac.js`, `buildPac()`
**Evidence:** `var LISTED = [${listed}];` built from `(settings.listed || []).map(lit)`, against a matcher that lowercases and de-dots only the host: `var h = ("" + host).toLowerCase(); if (h.charAt(h.length - 1) === ".") { h = h.substring(0, h.length - 1); }`

The host side is canonicalized and the rule side is not. A rule saved as `Example.com`, `example.com.`, or a Unicode domain never equals the lowercase punycode host the resolver passes, so `wvAny` returns false. In listed mode that means `return wvAny(LISTED, h) ? P : "DIRECT"`, and the request the user deliberately added to the tunnel leaves over the direct path. The failure is silent, it targets precisely the hosts the user cared about, and the file's own header argues that a direct fallback is the bug class it exists to prevent. Unicode entry is not hypothetical for a Myanmar user base.

**Fix.** Normalize at generation, and at save time so the popup shows what will actually match.

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
  ...
}
```

Apply `normRule` in the options and popup save paths as well, so a rule that normalizes to the empty string is rejected with a visible message rather than stored and ignored.

**Residual risk.** A rule that normalizes to a different host than the user intended (a typo, a homograph) still routes the wrong thing. Showing the normalized form back in the UI at save time is what bounds that.

---

### F-7 | Domain C | The live data plane runs an installer that exists in no commit
**File:** `server/wins_winn3_gateway_install.sh` (header comment, "WHY THIS IS A SEPARATE SCRIPT")
**Evidence:** `the installer deployed on the fleet's only data plane matches NO commit in this repository. The on-host copy is 275,860 bytes; the committed one is 367,410.`

Roughly 92 kB of divergence between the reviewed source and the code that actually built the production node. Every audit in this tree, this one included, reasons about the committed file. The repository's own test inventory concedes the situation (`server/test_hub_hand_patch_reconciliation.py`). Until the on-host artifact is captured and reconciled, no finding about data-plane posture can be asserted as true of production, and no rollback target is known.

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

Then work the diff hunk by hunk into the committed script, and add a boot-time check that records `sha256sum` of the installed installer into the node registration payload so future divergence is detected rather than discovered.

**Residual risk.** The captured copy may already carry an unauthorized modification. Treat the diff as untrusted input and review each hunk on its merits rather than adopting it wholesale.

---

## P1

### F-8 | Domain A | Modified native engine blobs sit uncommitted in the release source sets
**File:** `android/app/src/release/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/libwinnengine.so`, `android/app/src/main/jniLibs/*/libxray.so`
**Evidence:** git status shows ` M` on all six `libwinnengine.so` copies (profile and release) and all three `libxray.so` copies, with `ShippedEngineFreshnessTest.kt` and `prepare_android_winn_assets.sh` modified alongside.
**Evidence:** `verifyAndroidReleaseEngineInputs()` in `android/app/build.gradle.kts` checks only `Files.isRegularFile(...) && file.length() > 0L`.

The release gate proves the files exist and are non-empty. It proves nothing about which toolchain produced them or which source revision they correspond to. Nine modified native objects in the working tree, unreviewed and uncommitted, are exactly the bytes a release build would package.

**Fix.** Add a provenance assertion next to the existence check:

```kotlin
fun verifyAndroidReleaseEngineInputs() {
    val expected = groovy.json.JsonSlurper()
        .parse(file("../../tools/android-engine-digests.json")) as Map<*, *>
    val missing = mutableListOf<String>()
    for (abi in androidReleaseAbis) {
        for (engine in androidReleaseStagedEngines) {
            val candidates = listOf(
                file("src/release/jniLibs/$abi/$engine"),
                file("src/main/jniLibs/$abi/$engine"),
            )
            val present = candidates.firstOrNull(::isSafeNonEmptyReleaseInput)
            if (present == null) { missing += "$abi/$engine"; continue }
            val actual = java.security.MessageDigest.getInstance("SHA-256")
                .digest(present.readBytes())
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
    ...
}
```

`tools/android-engine-digests.json` is produced by the pinned build script and committed in the same change as the binaries, so a blob can never move without a reviewed digest moving with it.

**Residual risk.** The digest manifest and the blob can still be updated together by a compromised workstation. Reproducible builds from the pinned Go toolchain are the answer to that, and the freshness gate already reads `tools/toolchain-pins.json`, so the input is available.

---

### F-9 | Domain A | The secret-code receiver is exported, third-party triggerable, and spells the product name
**File:** `android/app/src/main/AndroidManifest.xml`, `SecretCodeReceiver` block
**Evidence:** `<receiver android:name=".SecretCodeReceiver" android:exported="true"> <intent-filter> <action android:name="android.provider.Telephony.SECRET_CODE" /> <data android:scheme="android_secret_code" android:host="9467" />`

Two defects share one line. The host `9467` is `W-I-N-S` on a phone keypad, so the camouflage trigger is itself a manifest-resident product fingerprint readable by `aapt dump badging` on a pulled APK. The receiver is also `exported="true"` with no `android:permission`, so any locally installed app can deliver an explicit intent naming the component with the same action and drive whatever the receiver does, without going through the dialer.

**Fix.** Gate the receiver on the system-only broadcast permission and move the trigger out of the manifest literal:

```xml
<receiver
    android:name=".SecretCodeReceiver"
    android:exported="true"
    android:permission="android.permission.CONTROL_INCALL_EXPERIENCE">
    <intent-filter>
        <action android:name="android.provider.Telephony.SECRET_CODE" />
        <data android:scheme="android_secret_code" android:host="@string/secret_code_host" />
    </intent-filter>
</receiver>
```

Set `secret_code_host` per build from a value that does not encode the product name, and in `SecretCodeReceiver.onReceive`, treat the broadcast as a request to show the normal PIN prompt only. It must not by itself reveal, unhide, or change any state. Add a unit assertion that the resolved host string is not in the set of keypad encodings of `WINS`, `WIN`, `VPN`.

**Residual risk.** `android:permission` on a receiver constrains the sender's permission, not its identity (UNVERIFIED-LIVE: which permission the platform dialer actually holds on API 36 for this broadcast). Verify on device that the legitimate dialer path still fires before shipping, and keep the PIN as the only thing that actually reveals state.

---

### F-10 | Domain A | The watch command service is exported with no caller check
**File:** `android/app/src/main/AndroidManifest.xml`, `WatchCommandService`
**Evidence:** `<service android:name=".WatchCommandService" android:exported="true"> <intent-filter> <action android:name="com.google.android.gms.wearable.MESSAGE_RECEIVED" />` with the comment `the Data Layer only routes between nodes running this same package signed with this same certificate`

The comment describes the Data Layer's routing guarantee, which is real, and then relies on it to justify an export that the Data Layer does not protect. An exported service with no permission attribute accepts an explicit `startService` from any local app carrying that action and forged extras. If the handler acts on the intent, a co-resident app can start or stop the tunnel, which for this threat model is a locally triggerable disconnect at a chosen moment.

**Fix.** Make the class a `WearableListenerService` subclass and act only on its validated callbacks, never on raw intents:

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

Add an instrumented test that sends an explicit intent to the component with a forged payload and asserts no tunnel state change.

**Residual risk.** `WearableListenerService` binder validation is a Google Play services implementation detail (UNVERIFIED-LIVE for the pinned `play-services-wearable:19.0.0`). The `onStartCommand` refusal above is the part that lives in this repository and does not depend on that.

---

### F-11 | Domain A | The `qa` build type is signed with the production key and bypasses every release gate
**File:** `android/app/build.gradle.kts`, `buildTypes { create("qa") { ... } }` and `gradle.taskGraph.whenReady`
**Evidence:** `signingConfig = if (unsignedReleaseRequested) null else signingConfigs.getByName("release")` against a gate that matches only `task.name == "assembleRelease" || ... || task.name.startsWith("signRelease") || ...`

With the `formFactor` dimension in place the qa variants are named `assemblePhoneQa`, `packageTvQa`, `signPhoneQaBundle`, and so on. None of those strings appear in the gate, so `requestsReleaseArtifact` is false and `verifyAndroidReleaseEngineInputs`, `verifyAndroidReleaseIdentityAndApi36`, and `verifyAndroidReleaseR8AndFlutterObfuscation` all skip. A new build type also defaults to `isMinifyEnabled = false` and no Dart obfuscation requirement, so the qa artifact ships unshrunk, unobfuscated Dart, possibly without the complete engine set, carrying the genuine release signature. Anything signed with that key is indistinguishable from a store build to every downstream verifier.

**Fix.** Match on the build type rather than an enumerated name list, and give qa its own identity:

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

If QA must not require Dart obfuscation, create a distinct `signingConfigs.create("qa")` backed by a separate QA key rather than reusing the upload key.

**Residual risk.** Broadening the gate makes QA builds require the full engine set and obfuscation flags, which slows the QA loop. That is the correct trade against a production-key artifact with no gates.

---

### F-12 | Domain B | Profile validation accepts a carrier class the dialer refuses, producing a silent downgrade
**File:** quoted in `server/wins_control_plane_setup_ONETOUCH.sh` at `WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT`; the defect lives in `winn_protocol_experimental/winn3/` (`carrier` and `driver`) and in the client host profile parser
**Evidence:** `the client's winn3DialCarrier hard-refuses carrier.ClassTLS ... but winn3Profile validate() ACCEPTS class=tls at load, so the refusal only fires at dial time. An operator provisioning with defaults therefore believed the node had a TLS cover hop it does not have`

Accept-at-load and refuse-at-dial is the shape that produced the outcome described: an operator sizes a deployment around a cover hop that never engages, and every client silently falls back to winn/1 at connect time. Removing `tls` from one default constant treats the symptom. The validator is still wrong, and any hand-written profile, any hub descriptor, and the verify harness in `winn3-nodes/deploy_and_verify.sh` can all re-enter the same state.

**Fix.** Make the validator agree with the dialer, in the profile loader:

```go
// winn3/session (or wherever winn3Profile.validate lives)
func (p *winn3Profile) validate() error {
    ...
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
    ...
}
```

Add a table test asserting that the set of classes `validate()` accepts equals the set `winn3DialCarrier` handles, so the two cannot drift again. This is a read of the frozen datapath and a change to the validator only; the dial path is untouched.

**Residual risk.** Any node already provisioned with `class=tls` in its descriptor starts failing at profile load rather than at dial. That is the intended behavior change, and it needs a fleet sweep of stored `protocol_params` before rollout.

---

### F-13 | Domain C | `cmd_deploy` records firewall failures and then exits zero
**File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy()`
**Evidence:** `local_jump_receipts` is called, which does `FAIL "WINN3GW-FORWARD chain missing"` and `FAIL "FORWARD jumps wrong ..."`, and the function then ends with `RECEIPT "deploy ${ROLE}: ..."` and two `NOTE` lines. `verdict` is never called.

`FAILURES` is incremented and discarded. A deploy that leaves the NAT MASQUERADE rule missing, or leaves duplicate FORWARD jumps, reports `RECEIPT deploy ...` and returns 0, so a supervisor script treats it as success. `cmd_verify_node` calls `verdict`; `cmd_deploy` does not.

**Fix.**

```bash
  RECEIPT "deploy ${ROLE}: binary $(sha256sum "$GW_INSTALL" | cut -c1-16)… installed; env+unit+credentials+peers in place; firewall oneshot enabled; ip_forward=1"
  NOTE "next: on the hub VM run  bash deploy_and_verify.sh verify-hub ${ROLE}"
  NOTE "then here:              bash deploy_and_verify.sh verify-node ${ROLE}"
  verdict
}
```

**Residual risk.** A deploy that now exits non-zero leaves the node in the partially configured state it was already in. The existing `rollback` subcommand is the recovery path and should be named in the failure output.

---

### F-14 | Domain C | The hub verifier counts failures into a variable the exit status ignores
**File:** `winn3-nodes/deploy_and_verify.sh`, embedded Python in `cmd_verify_hub()`
**Evidence:** `def rec(name, ok, detail=""): global fails ... if not ok: fails += 1` and, at the end, `result = "PASS" if (carrying and ok_inner and ok_nat) else "FAIL"`

`fails` is written and never read. The concrete consequence: `rec("tcp-9111-connect", tcp_ok, ...)` and `rec("client-rx-packets>0", ...)` can both record FAIL while the script exits 0, because the verdict expression names only three of the five recorded checks. TCP 9111 reachability is the cover-listener check, which matters most for the detectability posture this product is built around.

**Fix.**

```python
    print(f"RECEIPT {role} endpoint={endpoint}:9111 handshake=1 inner={int(ok_inner)} nat={int(ok_nat)}")
    result = "PASS" if (fails == 0 and carrying and ok_inner and ok_nat) else "FAIL"
    print(f"RESULT {role}: {result} (recorded_failures={fails} handshake={int(carrying)} "
          f"icmp-inner={int(ok_inner)} icmp-nat={int(ok_nat)}; log verify-{role}.status.log)")
    sys.exit(0 if result == "PASS" else 1)
```

**Residual risk.** The TCP probe now blocks a PASS on nodes where the cover listener is deliberately absent. If such a node configuration is valid, make the probe conditional on the staged env rather than dropping it from the verdict.

---

### F-15 | Domain C | Staged gateway secrets are never removed after deploy
**File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy()` and `cmd_stage_help()`
**Evidence:** `keys/<role>/winn3-gateway-static.key (SECRET 600)`, `keys/<role>/winn3-gateway-admission.key (SECRET 600)` staged into `[ROOT]/winn3-stage/`, and `install -m 600 -o root -g root winn3-gateway-static.key "$CRED_DIR/winn3-gateway-static.key"` with no subsequent removal of the staged originals.

`cmd_rollback` carefully shreds the installed copies (`shred -u /etc/winn/credentials/winn3-gateway-static.key`). The staged copies in `[ROOT]/winn3-stage/` and the cover private keys under `cover/` survive both deploy and rollback, so a node that has been rolled back still holds the gateway static key, the admission key, and the cover certificate keys on disk.

**Fix.** At the end of `cmd_deploy`, after the installed copies are verified:

```bash
  for secret in winn3-gateway-static.key winn3-gateway-admission.key \
                cover/winn-leaf-key.pem cover/cover-key.pem cover/ech-server-keys.json; do
    if [[ -f "$STAGE/$secret" ]]; then
      shred -u "$STAGE/$secret" 2>/dev/null || rm -f "$STAGE/$secret"
    fi
  done
  RECEIPT "staged secret material shredded from $STAGE"
```

Mirror the same loop into `cmd_rollback` so a rollback on a node where deploy never completed also clears the staging directory, and add a line to `cmd_stage_help` stating that the staging directory is consumed rather than retained.

**Residual risk.** `shred` on a copy-on-write or log-structured filesystem does not guarantee overwrite of the original extents. Full-disk encryption is the control that covers that case, and the gateway nodes should be confirmed to have it.

---

### F-16 | Domain D | The default decision-log path cannot satisfy the module's own filesystem checks
**File:** `router/security.py`, `decision_log_path()` and `_validate_private_ancestors()`
**Evidence:** `os.environ.get("DECISIONS_FILE", "/tmp/router_decisions.jsonl")` against `if stat.S_IMODE(parent_info.st_mode) != 0o700: raise RuntimeError(f"{label} directory permissions must be 0700")`

`/tmp` is mode 1777 on every Linux distribution this fleet runs. Any decision-log write routed through the module's private-file helpers raises `RuntimeError` on the ancestor check, so the router's default configuration either logs nothing or fails the request path that logs. The default is also wrong on its own terms: a shared, predictable, world-writable directory is not where routing decisions for a censorship-circumvention service belong, and `main.py` exposes `LAST_LOG_ERROR` precisely because this failure was observed.

**Fix.**

```python
def decision_log_path() -> Path:
    return _absolute_file_path(
        os.environ.get("DECISIONS_FILE", "/var/lib/winsvpn-router/router_decisions.jsonl"),
        "DECISIONS_FILE",
    )
```

Provision the directory in the router unit so it exists with the right owner and mode before the process starts:

```ini
[Service]
StateDirectory=winsvpn-router
StateDirectoryMode=0700
UMask=0077
Environment=DECISIONS_FILE=/var/lib/winsvpn-router/router_decisions.jsonl
Environment=SMART_ROUTER_NONCE_JOURNAL_PATH=/var/lib/winsvpn-router/replay-nonces.sqlite3
```

Add a startup assertion beside `replay_journal_ready()` that opens and closes the decision log once, so a misconfigured path fails at boot rather than on the first routed request.

**Residual risk.** Existing deployments with an explicit `DECISIONS_FILE` in `/tmp` keep the old behavior until the unit is updated. Grep the fleet env files for `DECISIONS_FILE=/tmp` as part of the change.

---

### F-17 | Domain D | The router security boundary is an exact-path allowlist rather than deny-by-default
**File:** `router/security.py` (`PROTECTED_PATHS`), `router/main.py` (`DeadlineRouterSecurityMiddleware.__call__`)
**Evidence:** `if scope["type"] != "http" or scope.get("path") not in router_security.PROTECTED_PATHS: await self.app(scope, receive, send); return`

Authentication is applied to a fixed set of seven strings. Every route that is not in that set, present today or added tomorrow, is served unauthenticated. The module already contains a favicon handler that this allowlist does not cover, and `StrictJSONMiddleware` inherits the same set, so any future POST route silently loses both HMAC verification and strict JSON parsing. A security boundary that requires an author to remember to register each new route fails in the direction of exposure.

**Fix.** Invert the check:

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

Apply the same inversion in `StrictJSONMiddleware` (protect every `POST`/`PUT`/`PATCH` whose path is not in `PUBLIC_PATHS`). Keep `PROTECTED_PATHS` as a test fixture asserting that each of the seven names still resolves to an authenticated route.

**Residual risk.** Anything currently relying on an unlisted unauthenticated route breaks at deploy. `/livez` is carved out above so an external health check has a target that does not require HMAC signing.

---

### F-18 | Domain E | A version bump silently disables every download on the site
**File:** `web/_worker.js`, `downloadManifestBoundPaths()`
**Evidence:** `payload.release_id !== "v1.0.16+33"` inside the early return that yields an empty `authorized` set, combined with `if (canonical === "/downloads" || canonical.startsWith("/downloads/")) { if (authorizedPaths.has(canonical)) return { action: "asset" }; return { action: "not_found" }; }`

The release identifier is a literal in the Worker. `android/app/build.gradle.kts` pins the same identity independently (`versionCode = 33`, `versionName = "1.0.16"`). They agree today. When the app moves to the next build and the manifest is regenerated, the Worker rejects the manifest wholesale and every download URL becomes a 404, with no log line and no distinguishable signal from "artifact not published yet". For users in a censored network, a silent 404 on the download page is indistinguishable from interference.

**Fix.** Keep the pin (it is publication authority and should stay), but make the mismatch loud and make the pin generated rather than hand-typed:

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
  ...
}
```

Add `tools/sync_release_id.py` to derive `EXPECTED_RELEASE_ID` from `pubspec.yaml` and fail the release gate when `web/_worker.js`, `android/app/build.gradle.kts`, and the generated `web/releases/downloads.json` disagree.

**Residual risk.** A stale Worker deployment against a fresh manifest still serves nothing. The `console.warn` makes it visible in Cloudflare logs, which is the difference between a five-minute diagnosis and an outage of unknown cause.

---

### F-19 | Domain F | The hub reaches the wallet RPC through the public edge, and the payment host is published in certificate transparency
**File:** `server/spain_crypto_payments_setup.sh`, `setup_btcpay_server()` and `print_summary()`
**Evidence:** `export BTCPAY_HOST="btcpay.winsvpn.org"` and `MONERO_WALLET_RPC_URL="https://btcpay.winsvpn.org/monero-rpc"`

Two consequences. Certificate transparency logs are public and append-only, so issuing any certificate for `btcpay.winsvpn.org` permanently publishes the fact that this product runs a BTCPay instance and gives an adversary a name to resolve and block (UNVERIFIED-LIVE: whether the Cloudflare tunnel configuration issues an edge certificate naming this host, or uses a wildcard). Separately, routing the hub's wallet RPC calls through `https://btcpay.winsvpn.org` means Cloudflare terminates TLS on every call, so payment amounts, addresses, and transaction identifiers are visible in cleartext at a third-party edge for a service whose entire proposition is that it does not observe its users.

**Fix.** Keep the public BTCPay hostname for browser checkout, which needs it, and take the wallet RPC off the public path entirely.

```bash
    printf 'MONERO_WALLET_RPC_URL="http://%s:18083/json_rpc"  # over the hub-to-Spain management tunnel, not the public edge\n' "${WINS_SPAIN_TUNNEL_ADDR:?set to the Spain node management-tunnel address}"
```

and in the nginx block, drop the `/monero-rpc` location as shown in F-4. For the hostname, use a name that does not share the product's registrable domain, for example a dedicated domain registered for commerce, so the CT record carries no link to the VPN.

**Residual risk.** Moving the payment host to a separate domain does not hide the association from anyone who reads the checkout page. It removes the passive, indexed, zero-effort association from CT logs, which is the part an automated censor consumes.

---

### F-20 | Domain F | The nginx proxy rewrites the request URI, which breaks HTTP Digest authentication
**File:** `server/spain_crypto_payments_setup.sh`, `setup_nginx_proxy()`
**Evidence:** `location /monero-rpc { proxy_pass http://127.0.0.1:18083/json_rpc; ... proxy_pass_header Authorization; }` against a service configured with `--rpc-login` (HTTP Digest, per the file header: `Monero Wallet RPC (view-only, restricted RPC, HTTP Digest Authentication)`)

Digest authentication binds the `uri` field of the client's `Authorization` header to the request target. A client authenticating against `https://btcpay.winsvpn.org/monero-rpc` computes the digest over `/monero-rpc`, while the wallet RPC receives a request for `/json_rpc` and recomputes over that. The comparison fails and the caller sees a 401 loop it cannot escape by retrying (UNVERIFIED-LIVE: whether the pinned Monero release enforces the `uri` field strictly, which most digest implementations do). The script's own `verify_services` only exercises the loopback endpoint directly, so it never touches the proxied path where the mismatch lives.

**Fix.** The endpoint should not be public at all (F-4, F-19). If a loopback-only proxy is still wanted for BTCPay's convenience, preserve the path:

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

and extend `verify_services` to probe through the proxy, not only the loopback service, asserting a `401` without credentials and a `200` with them.

**Residual risk.** None specific to this change beyond the endpoint continuing to exist. If the hub is moved to the tunnel path per F-19, delete the proxy location entirely instead.

---

### F-21 | Domain C | `apt-get install docker` installs the wrong package
**File:** `server/spain_crypto_payments_setup.sh`, `require_dependencies()`
**Evidence:** `for pkg in curl bzip2 tar jq docker nginx; do if ! command -v "$pkg" ...` then `apt-get install -y -qq "${missing[@]}"`

On Debian and Ubuntu the binary is `docker` but the package providing Docker Engine is `docker.io` or `docker-ce` from the upstream repository. The Debian package literally named `docker` is a different program (UNVERIFIED-LIVE: current Debian/Ubuntu archive contents for the pinned release). The loop conflates the command name with the package name for all six entries, so a host missing Docker installs something unrelated, `docker compose version` then fails, and the script proceeds to `apt-get install -y -qq docker-compose-plugin` against an engine that is not installed.

**Fix.** Map commands to packages explicitly:

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

Note that `git` is used by `setup_btcpay_server` and is absent from the current dependency list, which is a second instance of the same gap.

**Residual risk.** `docker.io` and `docker-ce` differ in version cadence. Pick one deliberately and record it next to the Xray and Monero pins.

---

### F-22 | Domain G | The browser extension announces the product while the app disguises it
**File:** `extension/manifest/base.jsonc`
**Evidence:** `"name": "Win's VPN Companion"` and `"description": "Sends chosen sites through the Win's VPN desktop tunnel. Not a VPN on its own; it does nothing unless the desktop app is connected."`

The Android client goes to considerable lengths to present as a calculator. The extension on the same user's desktop is listed by name in the browser's extension page, in the profile directory on disk, and in any enterprise or forensic inventory of installed extensions. The disguise is only as strong as the least disguised component, and this is it. The extension is otherwise carefully built: no host permissions, no web-accessible resources, no remote code.

**Fix.** Give the shipped listing a neutral identity and keep the honest explanation inside the options page:

```jsonc
  "name": "Site Routing Helper",
  "version": "1.0.16",
  "description": "Routes chosen sites through a local desktop proxy. Does nothing unless that desktop application is running.",
```

Keep the existing `optional_host_permissions` reasoning and the leakscan gate unchanged. Add an assertion to `tools/leakscan.py` that no packaged file contains the product name.

**Residual risk.** Store listings must still be findable by users who need them, so discoverability moves to the website's download page rather than to store search (UNVERIFIED-LIVE: whether Chrome Web Store and AMO permit a listing whose name does not match the developer's other properties). This is a policy call for the owner, not a technical one, and the extension is the component where the cost of the disguise is lowest.

---

### F-23 | Domain E | The PWA manifest makes an unqualified no-logs claim that the site's own text contradicts
**File:** `web/manifest.json`
**Evidence:** `"description": "AI-powered, no-logs VPN protection made in America."` against `web/_worker.js`, `publicFallbackAnswer`: `Win's VPN is designed as a verified no-log service for browsing history, DNS query history, traffic contents, and destination activity. The service may keep limited account, device-count, payment, referral, security, and legal-acceptance metadata`

The qualified statement in the Worker is accurate and careful. The manifest strips every qualifier, and the manifest is what a user's device shows when the site is installed as an app. An unqualified "no-logs" claim is the exact form that draws consumer-protection attention for VPN vendors (UNVERIFIED-LIVE: current enforcement posture), and for a 501(c)(3) with an audited privacy story it also undercuts the value of the honest version.

**Fix.**

```json
    "description": "Privacy and anti-censorship VPN. No logs of browsing history, DNS queries, traffic contents, or destinations. Limited account and payment metadata is retained to operate the service.",
```

Add the same string to `app_store/*/metadata/en-US/short_description.txt` review so the claim is identical across every ship channel, and add a check to `tools/verify_live_deployment.py` that the live `manifest.json` description equals the repository's.

**Residual risk.** A longer description may truncate in some install prompts. Truncation of an accurate sentence is preferable to a complete inaccurate one.

---

### F-24 | Domain C | Forty audit receipt files are deleted in the working tree
**File:** `docs/evidence/codex_astra_audit_round{2..20}.md`, `docs/evidence/codex_sol_audit_round{2..20}.md`
**Evidence:** git status shows ` D` on all forty, alongside ` M docs/blueprints/DEBATE_PROTOCOL.md` and ` M docs/evidence/codex_astra_audit.md`

The governing protocol in this tree requires that every round's output persists locally and that certification binds to a receipt manifest. Deleting nineteen rounds of receipts per podium, uncommitted, while the debate protocol document is itself being modified in the same working tree, removes the chain those certifications rest on. Whether the deletion is intentional archival or an accident, the current state cannot be distinguished from either.

**Fix.** Do not commit the deletion. Restore and archive instead:

```bash
git restore --source=HEAD --staged --worktree -- docs/evidence/
git checkout -b evidence/archive-rounds-2-20
mkdir -p docs/evidence/archive
git mv docs/evidence/codex_astra_audit_round*.md docs/evidence/archive/
git mv docs/evidence/codex_sol_audit_round*.md   docs/evidence/archive/
git commit -m "Archive audit rounds 2-20 receipts under docs/evidence/archive (no content removed)"
```

If the intent was genuinely to remove them, the protocol's own removal record applies: write a tombstone naming each artifact, the digest of the removed text, the reason class, and the timestamp, before the deletion is committed.

**Residual risk.** The archive path grows without bound. A retention decision for receipts older than a stated window is a separate, deliberate change with its own tombstones.

---

### F-25 | Domain H | Apple platforms have no camouflage equivalent (inventory round)
**File:** `apple/WinsTunnelCore/WinsPacketTunnelEngine.swift`, `apple/WinsTunnelCore/WinsTunnelConfig.swift`, `apple/EngineWrappers/WinsXrayVlessWsTransport.m` (all modified, bodies not in this packet)
**Evidence:** Domain A ships a full disguise mechanism (`activity-alias .LauncherDecoy`, `DISGUISED_DISPLAY_NAME`, `SecretCodeReceiver`). Nothing in the packet's Apple inventory, and nothing in `app_store/` beyond Android and Windows and Linux metadata, indicates any equivalent.

iOS has no activity-alias analogue and the springboard display name is fixed at submission (UNVERIFIED-LIVE: current App Store policy on alternate app icons and display names, which do permit alternate icons but not alternate names). A user who follows the product's own threat guidance on Android and then installs the iOS build gets a device that names the product on the home screen, in Settings, and in the VPN configuration list.

**Fix for this round, since H is inventory only.** Add an explicit platform-capability statement to `SECURITY_NOTES_FINAL.md` and to the in-app first-run notice, naming the platforms where camouflage exists and the platforms where it does not:

```markdown
## Camouflage availability by platform
- Android, Android TV, Wear OS: launcher label and icon camouflage available (opt-in).
- iOS, macOS, watchOS: no camouflage. The app name is visible on the home screen,
  in Settings, and in the system VPN configuration list.
- Windows, Linux: see the desktop notes; the installed program name is visible.
Users in a jurisdiction where possession of circumvention software is itself a risk
should treat the Apple builds as fully attributable.
```

Then evaluate the alternate-app-icon API as a partial measure in a later round.

**Residual risk.** Documentation does not reduce the exposure, it only stops a user from relying on protection that is not there. That is the whole of what this round can deliver for H.

---

### F-26 | Domain C | Two assignment lines in the deployment scripts are not valid shell as presented
**File:** `server/wins_data_plane_setup_ONETOUCH.sh` (near `ADMIN_TOKEN_DEFAULT=""`)
**Evidence:** `ADMIN_TOKEN: \"[REDACTED]\"` and `NODE_TOKEN: \"[REDACTED]\"s/^NODE_TOKEN="\(.*\)"$/\1/p' "${NODE_ENV_FILE}" | tail -n 1)"`

I flag this as verify-first rather than asserting it, because the second line clearly shows a redaction pass having overwritten the left half of a `sed -n '...p'` command substitution. The same pass turned `MONERO_CLI_VERSION="v[IP_2]"` in the Spain script into an IP alias where a version string belongs, which confirms the redactor rewrites content outside its intended class. If these lines are literal in the repository, `ADMIN_TOKEN:` is parsed as a command name, the command is not found, and `set -Eeuo pipefail` aborts the installer before anything is provisioned.

**Fix.** Confirm first, then repair only if confirmed:

```bash
bash -n server/wins_data_plane_setup_ONETOUCH.sh && echo "parses clean"
grep -n 'ADMIN_TOKEN:\|NODE_TOKEN:' server/wins_data_plane_setup_ONETOUCH.sh
```

If the literals are present, the intended lines are:

```bash
ADMIN_TOKEN="${ADMIN_TOKEN:-$ADMIN_TOKEN_DEFAULT}"
NODE_TOKEN="${NODE_TOKEN:-$NODE_TOKEN_DEFAULT}"
if [[ -z "${NODE_TOKEN}" && -r "${NODE_ENV_FILE}" ]]; then
  NODE_TOKEN="$(sed -n 's/^NODE_TOKEN="\(.*\)"$/\1/p' "${NODE_ENV_FILE}" | tail -n 1)"
fi
```

Separately, fix the redaction tooling: add `bash -n` and `python -m py_compile` over every redacted script before a packet ships, so a packet can never present broken code as evidence.

**Residual risk.** If the lines are redaction artifacts, this finding costs one `bash -n` run. If they are real, it is the difference between a working installer and one that dies at line 300.

---

## P2

### F-27 | Domain E | Rate-bucket eviction lets a limited client reset its own counter
**File:** `web/_worker.js`, `pruneRateBuckets()` and `isolateLocalRateLimited()`
**Evidence:** `while (rateBuckets.size > RATE_BUCKET_CAP) { rateBuckets.delete(rateBuckets.keys().next().value); }` and `if ((rateBuckets.size & 127) === 0) pruneRateBuckets(now);`

Eviction is insertion-ordered, so the oldest key is dropped first, and the oldest key is frequently an actively rate-limited client whose bucket was created early in the window. Filling the map past 10,000 entries therefore clears exactly the entries that are doing work. The prune trigger is also a size congruence test, and since the size both grows and shrinks, it can step over every multiple of 128 and never fire.

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
  ...
}
```

**Residual risk.** Isolate-local limiting stays isolate-local. The zone-level WAF rule already tracked as M-9 is the actual control; this only stops the fallback from being trivially resettable.

---

### F-28 | Domain G | The endpoint module documents a pinned host that the code does not enforce
**File:** `extension/src/core/endpoint.js`
**Evidence:** The header states `the host comes from a constant compiled into this extension` and `a bridge that has been replaced, compromised or simply written wrong cannot make this browser send traffic anywhere except 127.0.0.1`, while `validateEndpoint()` accepts any host passing `isLoopbackHost`, which returns true for all of `127.0.0.0/8` and for `::1`.

The guarantee in the prose is stronger than the guarantee in the code. The gap is not exploitable (anything in 127/8 is still this machine) but the file's own reasoning says an assertion beats a habit, and the assertion here does not match the claim it is documenting.

**Fix.**

```js
if (endpoint.host !== LOOPBACK_HOST) {
  return { ok: false, reason: 'endpoint host is not the pinned loopback constant' };
}
if (!isLoopbackHost(endpoint.host)) {
  return { ok: false, reason: 'endpoint host is not a numeric loopback address' };
}
```

Keep both checks: the second stays as the defense in depth the file already argues for.

**Residual risk.** If the bridge ever needs to bind a non-default loopback address, this becomes a deliberate change with a visible failure rather than a silent acceptance.

---

### F-29 | Domain E | The Pages preview origin is a trusted CORS origin for payment routes
**File:** `web/_worker.js`, `allowedOrigins`
**Evidence:** `"https://winsvpn.pages.dev",` in the set consumed by `corsHeaders()` and `paymentOriginGuard()`

Preview and production share one allowlist, so any deployment served on the project's `pages.dev` host can drive the payment POST routes with credentials echoed back by CORS. The `pages.dev` host is also outside the organization's certificate and DNS control.

**Fix.**

```js
const allowedOrigins = new Set([
  "https://winsvpn.org",
  "https://www.winsvpn.org",
  "https://winsvpn.com",
  "https://www.winsvpn.com",
]);
```

If a preview origin is needed during deployment checks, add it from `env` rather than from source:

```js
for (const extra of String(env.EXTRA_ALLOWED_ORIGINS || "").split(",")) {
  const value = extra.trim();
  if (value.startsWith("https://")) allowedOrigins.add(value);
}
```

**Residual risk.** An operator who sets `EXTRA_ALLOWED_ORIGINS` in the production environment reintroduces the gap. The variable name makes that visible in the Cloudflare dashboard, which the hardcoded entry did not.

---

### F-30 | Domain C | A checksum staged beside the binary it checks provides integrity, not authenticity
**File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy()` and `cmd_verify_hub()`
**Evidence:** `(cd "$STAGE" && sha256sum -c "$BIN_SRC.sha256") || die "gateway binary sha256 mismatch"` where `cmd_stage_help` instructs copying `out/winn3-gateway-linux-amd64 out/winn3-gateway-linux-amd64.sha256` together over the same channel

Anyone able to replace the binary in transit or in the staging directory can replace the `.sha256` file in the same motion. The check detects a truncated copy, which is worth having, and detects nothing adversarial.

**Fix.** Pin the expected digest in the script, where it is reviewed under version control:

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

**Residual risk.** The reviewed digest still has to reach the node, now through the script rather than a sidecar file. That moves the trust to the reviewed, committed artifact, which is the intended place.

---

### F-31 | Domain C | The replay journal has a documented replacement hazard and no guard
**File:** `server/wins_winn3_gateway_install.sh`, `provision_replay_journal` (referenced) and the `WINN3_REPLAY_JOURNAL_DIR` comment block
**Evidence:** `Do not delete or replace the journal while the service is running: on Unix an open file descriptor can keep writing an unlinked inode that a restart cannot reload. Stop the service before journal recovery.`

The hazard is stated precisely and enforced by nothing. The whole point of the durable journal is that a captured initiation stays refused across a restart, and an operator who replaces the file on a running unit loses exactly that property without any error.

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

**Residual risk.** A re-install that now refuses is a small operational cost against silently losing the replay guarantee. An operator who stops the unit, replaces the journal, and starts it again is doing the supported thing.

---

### F-32 | Domain D | SQLite sidecar files are not permission-checked
**File:** `router/security.py`, `replay_journal_ready()` and `DurableReplayGuard`
**Evidence:** `_validate_private_regular_file(path, maximum_bytes, "nonce journal")` is applied to the journal path only, while the connection is opened with WAL-style access (`BEGIN IMMEDIATE`, a `replay_state` table, a busy timeout)

SQLite creates `-wal` and `-shm` beside the database. Their mode derives from the process umask at creation, so a service started with the default 022 umask produces sidecars at 0644 while the main file is carefully held at 0600. The exposed content is nonce hashes and timestamps rather than nonces, so the impact is limited, but the module's stated posture is that every file it owns is 0600.

**Fix.** Set the umask in the unit so the sidecars inherit the same restriction:

```ini
[Service]
UMask=0077
```

and extend the readiness probe to assert it:

```python
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(path) + suffix)
            if sidecar.exists():
                _validate_private_regular_file(
                    sidecar, maximum_bytes, f"nonce journal{suffix}", enforce_size=False
                )
```

**Residual risk.** The sidecars are recreated on each connection, so a unit restarted without `UMask=0077` recreates the exposure. The assertion above is what turns that into a visible failure.

---

### F-33 | Domain E | The live-deployment verifier has two parsing weaknesses that can invert its verdict
**File:** `tools/verify_live_deployment.py`, `repo_header()` and `inline_blocks()`
**Evidence:** `for raw in HEADERS_FILE.read_text(encoding="utf-8").splitlines(): line = raw.strip(); if line.lower().startswith(prefix): return line[len(prefix):].strip()` and `INLINE_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.S | re.I)`

`repo_header` returns the first occurrence of a header name anywhere in `web/_headers`, including inside a path-scoped block such as the `/releases/downloads.json` section. A future path-scoped CSP would be compared against the live global CSP and always fail. The attribute regex `[^>]*` terminates at the first `>` even inside a quoted attribute value, so a `<script>` tag carrying `>` in an attribute is mis-split and its hash is computed over the wrong bytes.

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

**Residual risk.** Regex-based HTML parsing remains approximate. The checker's job is to compare a repository build against a deployed one, both produced by the same generator, so approximate parsing is tolerable as long as it is identical on both sides, which these patterns are.

---

### F-34 | Domain C | Gateway deploy changes the node-wide default queueing discipline
**File:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy()`
**Evidence:** the heredoc writing `/etc/sysctl.d/60-winn3-gateway-pps.conf` containing `net.core.default_qdisc = fq`, applied immediately with `sysctl -p /etc/sysctl.d/60-winn3-gateway-pps.conf`

`net.core.default_qdisc` is global. On a node that also carries the frozen AmneziaWG datapath, changing the default qdisc changes the queueing behavior of interfaces created after the change, including any AWG interface brought up later. The downlink datapath is under a freeze directive, and this sysctl reaches it indirectly. The rollback path deliberately does not revert it (`sysctls ... left in place: one-way by design`), so the change is permanent.

**Fix.** Scope the queueing change to the gateway interface rather than to the node default. Remove `net.core.default_qdisc = fq` from the drop-in and apply `fq` to `winn3gw0` alone, after the interface exists:

```bash
  if ip link show winn3gw0 >/dev/null 2>&1; then
    tc qdisc replace dev winn3gw0 root fq || NOTE "tc qdisc replace on winn3gw0 failed; leaving kernel default"
  fi
```

Keep the backlog and budget knobs, which are receive-path and do not alter the existing interfaces' queueing discipline.

**Residual risk.** Per-interface `tc` state does not survive an interface recreate. Adding the `tc` call to the unit's `ExecStartPost` is the durable form, and is a change to the gateway unit rather than to the datapath.

---

### F-35 | Domain G | Extension version is decoupled from the release identity
**File:** `extension/manifest/base.jsonc`
**Evidence:** `"version": "1.0.0"` against `versionName = "1.0.16"` / `versionCode = 33` in `android/app/build.gradle.kts` and `release_id !== "v1.0.16+33"` in `web/_worker.js`

Three ship channels carry three different opinions about which release this is. Support cannot map a user-reported extension version to a release, and the release evidence pipeline has no way to bind the extension artifact to the rest of the build.

**Fix.** Have the extension build derive its version from the same source as the rest, in the merge step that produces the shipped manifest:

```jsonc
  "version": "__RELEASE_VERSION__",
```

with the build substituting `1.0.16` from `pubspec.yaml`, and the release gate asserting equality across `pubspec.yaml`, `android/app/build.gradle.kts`, `web/_worker.js`, and the generated extension manifests. This is the same generator proposed in F-18.

**Residual risk.** Chrome and Firefox version-string grammars differ from the app's `major.minor.patch+build` form (UNVERIFIED-LIVE for current accepted formats). Use only the `major.minor.patch` prefix for the extension and record the build number in a separate manifest key.

---

### F-36 | Domain E | The AI chat's secret-request filter is a protocol-name oracle
**File:** `web/_worker.js`, `containsSecretRequest()`
**Evidence:** `/\b(secret|token|...|xray|amnezia|awg|wireguard|port\s+\d+|control\s+hub\s+ip|server\s+ip|protocol\s+stack|underlying\s+protocol)\b/i`

The function changes the response when the question contains a protocol name, and the refusal text is distinctive: `I can explain public Win's VPN features and troubleshooting steps, but I cannot reveal private infrastructure details...`. An adversary can binary-search the keyword list from the public endpoint and recover it, which enumerates the exact set of terms the operator considers sensitive. That is a short list of the technologies in use, confirmed from the outside, at no cost.

**Fix.** Return a single response for every out-of-scope question, so no keyword produces a distinguishable answer:

```js
function publicFallbackAnswer(message) {
  const q = String(message || "").toLowerCase();
  if (containsSecretRequest(q)) {
    // Identical to the generic closing answer, so the refusal is not a signal.
    return "I can help with setup, free server access, premium access, privacy, downloads, server selection, referrals, and connection troubleshooting.";
  }
  ...
  return "I can help with setup, free server access, premium access, privacy, downloads, server selection, referrals, and connection troubleshooting.";
}
```

**Residual risk.** Response timing may still differ marginally between the filtered and unfiltered paths. Both are local string operations on the same request, so the difference is far below network noise.

---

## Domains with insufficient evidence this round

**B (Go protocol engine).** The packet contains no file under `winn_protocol_experimental/`. F-12 is the only finding I can support, and it rests on a behavior quoted in a deployment script rather than on the source. The carrier, session, driver, tun, and PMTUD files named in the mandate are entirely unreviewed. I will not manufacture findings about code I have not read.

**D (control hub).** The packet contains the top of `wins_control_plane_setup_ONETOUCH.sh` and a list of forty test filenames, with no hub application source. F-16, F-17, F-26, and F-32 are what the router and installer evidence supports. Account deletion, entitlement grant, and Litestream restore posture are unexamined, despite `test_account_deletion_hub.py`, `test_account_expiry_revocation_hub.py`, and `test_paid_refresh_authorization_hub.py` naming exactly the paths that matter most for the enumeration threat model.

**H (Apple).** Inventory only per the mandate, delivered as F-25 plus the file list.

---

## NEXT-DEEP-DIVE

1. **`winn_protocol_experimental/winn3/`** (full tree, especially `carrier/`, `session/`, `driver/`, `tun/`, and the PMTUD sources): domain B has zero primary evidence this round, and the profile-validation defect in F-12 indicates the accept path and the dial path have drifted apart in at least one place.
2. **`server/db/` plus the hub application source behind `wins-hub.service`** (`[ROOT]/vpn_auth/main.py` as committed in this repository): account deletion, entitlement grant, and device-limit enforcement are the enumeration-critical paths in domain D and none of them are readable from this packet.
3. **`web/_worker.js`** (full text; it was capped mid `handleGeoScene`): the translate proxy, the AI chat handler, and all four payment POST handlers are below the cap, and F-27 through F-36 only cover what was visible above it.
4. **`web/index.html`**: F-1 requires knowing exactly which tracker tags are embedded and recomputing the two inline-script hashes, and `tools/verify_live_deployment.py` treats this file as the source of truth for four behavioral markers.
5. **`android/app/src/main/kotlin/org/winsvpn/app/{VpnTunnelService,WinnV3Keys,SecureFileStore,SecretCodeReceiver}.kt`**: F-9 and F-10 assert behavior about the secret-code and watch paths from the manifest alone, and the key custody plus kill-switch logic is where an Android camouflage failure would become a traffic failure.
6. **`apple/WinsTunnelCore/WinsPacketTunnelEngine.swift` and `apple/WinsTunnelCore/WinsTunnelConfig.swift`**: domain H moves from inventory to audit next round, and these two carry the packet tunnel lifecycle and the on-demand and kill-switch configuration where an Apple-side leak would live.
