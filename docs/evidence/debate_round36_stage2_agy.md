# Round 36 stage2: agy

# Round 36 Stage 2: Adversarial Cross-Examination (Seat 1: Antigravity)

ROUND 36 SURFACE AUDIT REVISED VERDICT AND CROSS-EXAMINATION

1. **Steelman Analysis of Opposing Seats**:
   * **Seat 2 (Claude Opus 5)**:
     Seat 2 reasoned from an architectural threat model where physical handset inspection and local forensic discovery are co-equal with network surveillance. In a high-threat jurisdiction such as Myanmar, a cryptographic transport protocol is ineffective if the host operating system reveals the application identity on the home screen, or if an administrative installer executes arbitrary code as root. Seat 2 provided exceptional depth across operational configurations, systemd definitions, edge routing, and build tooling.
     The single strongest point in Seat 2's verdict is Finding F-2 (The structural breakdown of Android disguise: `.LauncherReal` is enabled by default in `AndroidManifest.xml`, displaying "Win's VPN" on the launcher immediately upon installation) and Finding F-20 (The Nginx reverse proxy rewrites `/monero-rpc` to `/json_rpc`, which breaks HTTP Digest authentication by changing the URI parameter that the cryptographic digest binds to).
   * **Seat 3 (GPT-5.6 Sol Pro)**:
     Seat 3 reasoned from strict execution correctness, deterministic state evaluation, and root privilege boundaries. It focused on the principle that shell scripts executing with root authority must never ingest unpinned remote network code or expose credentials in world-readable command invocations. Seat 3 provided rigorous analysis of shell control flow, file type assertions, and firewall rollback routines.
     The single strongest point in Seat 3's verdict is Finding F-1 (Root installer executes an unpinned git clone of `btcpayserver-docker`, allowing arbitrary upstream code execution with root authority) and Finding F-4 (`handleMapTile` functions as an open, unauthenticated reverse proxy that forwards arbitrary upstream coordinates without origin verification or rate limiting).

2. **Impact of Opposing Reasoning on Seat 1 Positions**:
   * **Accepted and Merged Findings**:
     Seat 1 accepts Seat 3 F-1 and Seat 2 F-5, merging unpinned remote repository execution in `spain_crypto_payments_setup.sh` as P0.
     Seat 1 accepts Seat 3 F-2 and Seat 2 F-4, merging the cleartext Monero RPC password exposure in systemd command lines and stdout as P0.
     Seat 1 accepts Seat 2 F-2, deepening our Android disguise analysis (Seat 1 F-3) to include the default enabled state of `.LauncherReal` as P0.
     Seat 1 accepts Seat 3 F-4 and Seat 2 F-8, merging the `handleMapTile` open proxy SSRF risk as P0.
     Seat 1 accepts Seat 3 F-6 and Seat 2 F-10, adding the flaw in `verifyAndroidReleaseEngineInputs` in `build.gradle.kts` as P1.
     Seat 1 accepts Seat 3 F-8, F-9 and Seat 2 F-12, F-13, adding missing permission and symlink checks on sourced environment files as P1.
     Seat 1 accepts Seat 3 F-10 and Seat 2 F-14, adding the `/var/log/winsvpn` ownership barrier for `monero-wallet` as P1.
     Seat 1 accepts Seat 3 F-12 and Seat 2 F-11, adding the missing firewall rollback jump deletion as P1.
     Seat 1 accepts Seat 2 F-20, adding the HTTP Digest authentication URI rewriting defect in the Nginx proxy as P1.
     Seat 1 accepts Seat 2 F-18, adding the hardcoded release version break in `_worker.js` as P1.
     Seat 1 accepts Seat 2 F-22, adding the browser extension name disclosure as P1.
     Seat 1 accepts Seat 2 F-27, adding the rate bucket FIFO eviction vulnerability as P1.
     Seat 1 accepts Seat 2 F-32, adding SQLite sidecar file permission verification as P2.
     Seat 1 accepts Seat 2 F-34, adding the global queueing discipline modification risk as P2.
   * **Refutations and Clarifications**:
     Seat 1 refutes Seat 2 F-26 regarding alleged syntax errors in `wins_data_plane_setup_ONETOUCH.sh`. The text `ADMIN_TOKEN: "[REDACTED]"` is an artifact of the local privacy gate redaction applied to the audit packet, not an error in the underlying repository source code.
     Seat 1 refutes treating Seat 2 F-24 (deleted audit receipt files in git status) as an operational code defect. Working tree file staging during active refactoring is an internal repository management concern. It is recorded under P2 hygiene rather than as a blocking functional defect.
     Seat 1 notes that Seat 3 omitted the third-party tracking origins in Content-Security-Policy (Seat 1 F-1 and Seat 2 F-1). Seat 1 strictly maintains this as a P0 issue: for users in high-threat jurisdictions, transmitting client network metadata to commercial advertising endpoints creates immediate user enumeration exposure.

3. **Revised Final Findings List**:

* **Finding F-1**:
  * **Domain**: E
  * **Severity**: P0
  * **File**: web/_headers (lines 14:16)
  * **Evidence Quote**: "img-src 'self' data: https: https://www.facebook.com https://www.google-analytics.com https://www.google.com https://www.googleadservices.com; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.googletagmanager.com https://connect.facebook.net https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://stats.g.doubleclick.net https://www.facebook.com"
  * **Exact Proposed Fix**:
    Remove all third-party tracker domains from Content-Security-Policy in web/_headers:
    ```diff
    --- a/web/_headers
    +++ b/web/_headers
    @@ -14,3 +14,3 @@
    -  Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https: https://www.facebook.com https://www.google-analytics.com https://www.google.com https://www.googleadservices.com; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.googletagmanager.com https://connect.facebook.net https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://stats.g.doubleclick.net https://www.facebook.com https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://applepay.cdn-apple.com https://pay.google.com; frame-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://pay.google.com; form-action 'self' https://www.paypal.com https://www.paypalobjects.com; upgrade-insecure-requests
    +  Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://applepay.cdn-apple.com https://pay.google.com; frame-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://pay.google.com; form-action 'self' https://www.paypal.com https://www.paypalobjects.com; upgrade-insecure-requests
    ```
    Remove tracker script tags from web/index.html, recompute the script hashes, and enforce clean headers in tools/verify_live_deployment.py.
  * **Residual Risk**: External conversion tracking for marketing ceases. Visitors are shielded from commercial tracker enumeration.

* **Finding F-2**:
  * **Domain**: A
  * **Severity**: P0
  * **File**: android/app/src/main/AndroidManifest.xml (lines 35:58, 220:235) and android/app/build.gradle.kts
  * **Evidence Quote**: "android:name=\".LauncherReal\" android:enabled=\"true\" ... android:label=\"Win's VPN\"" and "<uses-permission android:name=\"android.permission.QUERY_ALL_PACKAGES\" tools:ignore=\"QueryAllPackagesPermission\" />"
  * **Exact Proposed Fix**:
    In android/app/src/main/AndroidManifest.xml, invert default component availability so the calculator decoy is active on clean installs, and remove QUERY_ALL_PACKAGES:
    ```diff
    --- a/android/app/src/main/AndroidManifest.xml
    +++ b/android/app/src/main/AndroidManifest.xml
    @@ -55,3 +55,0 @@
    -    <uses-permission
    -        android:name="android.permission.QUERY_ALL_PACKAGES"
    -        tools:ignore="QueryAllPackagesPermission" />
    @@ -222,2 +219,2 @@
         <activity-alias
    -        android:name=".LauncherReal"
    -        android:enabled="true"
    +        android:name=".LauncherReal"
    +        android:enabled="false"
             android:exported="true"
    -        android:label="Win's VPN"
    +        android:label="@string/app_name_decoy"
             android:targetActivity=".MainActivity">
    @@ -231,2 +228,2 @@
         <activity-alias
             android:name=".LauncherDecoy"
    -        android:enabled="false"
    +        android:enabled="true"
             android:exported="true"
    ```
  * **Residual Risk**: Users who want the direct brand launcher icon must explicitly toggle it from the internal settings screen.

* **Finding F-3**:
  * **Domain**: A
  * **Severity**: P0
  * **File**: android/app/src/main/AndroidManifest.xml (lines 188:193)
  * **Evidence Quote**: "<receiver android:name=\".SecretCodeReceiver\" android:exported=\"true\">\n            <intent-filter>\n                <action android:name=\"android.intent.action.MAIN\" />\n                <action android:name=\"android.provider.Telephony.SECRET_CODE\" />\n                <data android:scheme=\"android_secret_code\" android:host=\"9467\" />\n            </intent-filter>\n        </receiver>"
  * **Exact Proposed Fix**:
    Remove the exported broadcast receiver with static host code. Route disguise toggling through the calculator UI logic or protect the receiver:
    ```diff
    --- a/android/app/src/main/AndroidManifest.xml
    +++ b/android/app/src/main/AndroidManifest.xml
    @@ -188,6 +188,2 @@
    -        <receiver android:name=".SecretCodeReceiver" android:exported="true">
    -            <intent-filter>
    -                <action android:name="android.intent.action.MAIN" />
    -                <action android:name="android.provider.Telephony.SECRET_CODE" />
    -                <data android:scheme="android_secret_code" android:host="9467" />
    -            </intent-filter>
    -        </receiver>
    +        <receiver android:name=".SecretCodeReceiver" android:exported="false" />
    ```
  * **Residual Risk**: Launching via telephone dialer code is disabled. The disguise unmasking operates via the calculator formula interface.

* **Finding F-4**:
  * **Domain**: F
  * **Severity**: P0
  * **File**: server/spain_crypto_payments_setup.sh (lines 90:105)
  * **Evidence Quote**: "git clone https://github.com/btcpayserver/btcpayserver-docker.git \"${BTCPAY_DOCKER_DIR}\"\n    cd \"${BTCPAY_DOCKER_DIR}\"\n    . ./btcpay-setup.sh -i"
  * **Exact Proposed Fix**:
    Require a verified, pinned commit for the BTCPay repository prior to executing root installation code:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -90,3 +90,10 @@
    +    : "${BTCPAY_REVIEWED_COMMIT:?BTCPAY_REVIEWED_COMMIT must be defined with reviewed 40-char commit}"
    +    if [[ ! -d "${BTCPAY_DOCKER_DIR}/.git" ]]; then
              git clone https://github.com/btcpayserver/btcpayserver-docker.git "${BTCPAY_DOCKER_DIR}"
    +    fi
         cd "${BTCPAY_DOCKER_DIR}"
    +    git fetch origin
    +    git checkout "${BTCPAY_REVIEWED_COMMIT}"
    +    local actual_commit
    +    actual_commit="$(git rev-parse HEAD)"
    +    [[ "${actual_commit}" == "${BTCPAY_REVIEWED_COMMIT}" ]] || { echo "Commit verification failed"; exit 1; }
         . ./btcpay-setup.sh -i
    ```
  * **Residual Risk**: Operator must supply and verify the immutable commit identifier when provisioning nodes.

* **Finding F-5**:
  * **Domain**: F
  * **Severity**: P0
  * **File**: server/spain_crypto_payments_setup.sh (lines 110:135, 175:180)
  * **Evidence Quote**: "ExecStart=/usr/local/bin/monero-wallet-rpc \\\n    --daemon-address nodes.hashvault.pro:18081 \\\n    --rpc-login ${rpc_user}:${rpc_pass} \\\n" and "printf 'MONERO_WALLET_RPC_PASS=\"%s\"\\n' \"${rpc_pass}\""
  * **Exact Proposed Fix**:
    Store authentication credentials in an environment file with restricted permissions (0600) and reference them via login file or environment variable:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -115,2 +115,4 @@
    +    local auth_file="/etc/monero/wallet-rpc.auth"
    +    mkdir -p /etc/monero && chmod 0700 /etc/monero
    +    printf '%s:%s\n' "${rpc_user}" "${rpc_pass}" > "${auth_file}"
    +    chmod 0600 "${auth_file}" && chown monero-wallet:monero-wallet "${auth_file}"
    @@ -120,3 +122,3 @@
         ExecStart=/usr/local/bin/monero-wallet-rpc \\
    -        --rpc-login ${rpc_user}:${rpc_pass} \\
    +        --rpc-login-file /etc/monero/wallet-rpc.auth \\
             --wallet-dir /var/lib/monero-wallet \\
    @@ -176,1 +178,0 @@
    -    printf 'MONERO_WALLET_RPC_PASS="%s"\n' "${rpc_pass}"
    ```
  * **Residual Risk**: Operators must inspect the protected credentials file directly rather than relying on stdout summary.

* **Finding F-6**:
  * **Domain**: F
  * **Severity**: P0
  * **File**: server/spain_crypto_payments_setup.sh (lines 140:155)
  * **Evidence Quote**: "location /monero-rpc {\n        proxy_pass http://127.0.0.1:18083/json_rpc;\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto https;\n        proxy_pass_header Authorization;\n        proxy_pass_header WWW-Authenticate;\n        proxy_read_timeout 60s;\n        proxy_send_timeout 60s;\n    }"
  * **Exact Proposed Fix**:
    Remove public exposure of the Monero RPC endpoint from the external Nginx configuration:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -140,14 +140,0 @@
    -    location /monero-rpc {
    -        proxy_pass http://127.0.0.1:18083/json_rpc;
    -        proxy_http_version 1.1;
    -        proxy_set_header Host $host;
    -        proxy_set_header X-Real-IP $remote_addr;
    -        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    -        proxy_set_header X-Forwarded-Proto https;
    -        proxy_pass_header Authorization;
    -        proxy_pass_header WWW-Authenticate;
    -        proxy_read_timeout 60s;
    -        proxy_send_timeout 60s;
    -    }
    ```
    Route Kansas Hub traffic to the Monero wallet RPC service across the private WireGuard tunnel directly.
  * **Residual Risk**: Kansas Hub must possess an established WireGuard interface connected to the Spain node.

* **Finding F-7**:
  * **Domain**: E
  * **Severity**: P0
  * **File**: web/wrangler.jsonc (lines 1:12) and web/_worker.js (lines 270:285)
  * **Evidence Quote**: "NOT USED BY THE CURRENT LIVE DEPLOYMENT... Cloudflare Rate Limiting bindings (the ratelimits block below) are a Workers-only feature" and "env[bindingName].limit({ key })"
  * **Exact Proposed Fix**:
    In web/_worker.js, defend against missing Cloudflare rate limiting bindings:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -272,3 +272,3 @@
    -  if (env && env[bindingName]) {
    +  if (env && env[bindingName] && typeof env[bindingName].limit === "function") {
         return await env[bindingName].limit({ key });
       }
    ```
    Implement durable rate limiting via KV store or local in-memory tracking that does not fail when bindings are absent.
  * **Residual Risk**: In-memory rate limiting counters do not synchronize across distributed Cloudflare edge nodes.

* **Finding F-8**:
  * **Domain**: E
  * **Severity**: P0
  * **File**: web/_worker.js (lines 380:410)
  * **Evidence Quote**: "async function handleMapTile(request, env) {\n  const url = new URL(request.url);\n  const match = url.pathname.match(/^\\/api\\/map\\/tile\\/(\\d+)\\/(\\d+)\\/(\\d+)\\.png$/);\n  if (!match) return new Response(\"Not found\", { status: 404 });\n  const [, z, x, y] = match;\n  const tileUrl = `https://tile.openstreetmap.org/${z}/${x}/${y}.png`;\n  return fetch(tileUrl, { headers: { \"User-Agent\": \"WinsVPN-Web/1.0\" } });\n}"
  * **Exact Proposed Fix**:
    Validate request origin and constrain coordinate zoom levels to prevent open proxy misuse:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -385,2 +385,6 @@
       const [, z, x, y] = match;
    +  const origin = request.headers.get("origin") || "";
    +  if (!allowedOrigins.has(origin) && request.headers.get("sec-fetch-site") !== "same-origin") {
    +    return new Response("Forbidden", { status: 403 });
    +  }
    +  if (parseInt(z, 10) > 6) return new Response("Zoom level prohibited", { status: 400 });
       const tileUrl = `https://tile.openstreetmap.org/${z}/${x}/${y}.png`;
    ```
  * **Residual Risk**: Legitimate client map views are bounded to overview zoom levels.

* **Finding F-9**:
  * **Domain**: D
  * **Severity**: P0
  * **File**: router/security.py (lines 231:236)
  * **Evidence Quote**: "def decision_log_path() -> Path:\n    return _absolute_file_path(\n        os.environ.get(\"DECISIONS_FILE\", \"/tmp/router_decisions.jsonl\"),\n        \"DECISIONS_FILE\",\n    )"
  * **Exact Proposed Fix**:
    Relocate the default decision log path out of `/tmp` into a secure application directory:
    ```diff
    --- a/router/security.py
    +++ b/router/security.py
    @@ -232,2 +232,2 @@
         return _absolute_file_path(
    -        os.environ.get("DECISIONS_FILE", "/tmp/router_decisions.jsonl"),
    +        os.environ.get("DECISIONS_FILE", "/var/log/winsvpn/router_decisions.jsonl"),
             "DECISIONS_FILE",
    ```
  * **Residual Risk**: The `/var/log/winsvpn` directory must be created with ownership assigned to the router service user.

* **Finding F-10**:
  * **Domain**: C
  * **Severity**: P0
  * **File**: server/wins_winn3_gateway_install.sh (lines 283:294)
  * **Evidence Quote**: "Off by default. On the fleet's only node the host INPUT policy is ACCEPT and no WINVPN-INPUT chain exists, so no host rule is needed and adding one would be a change to a live node's firewall for no benefit. Set to 1 only on a node that genuinely default-drops INPUT.\nWINN3_GATEWAY_MANAGE_FIREWALL=\"${WINN3_GATEWAY_MANAGE_FIREWALL:-0}\""
  * **Exact Proposed Fix**:
    Default `WINN3_GATEWAY_MANAGE_FIREWALL` to 1 and inspect existing chain posture before skipping firewall rule generation:
    ```diff
    --- a/server/wins_winn3_gateway_install.sh
    +++ b/server/wins_winn3_gateway_install.sh
    @@ -293,1 +293,1 @@
    -WINN3_GATEWAY_MANAGE_FIREWALL="${WINN3_GATEWAY_MANAGE_FIREWALL:-0}"
    +WINN3_GATEWAY_MANAGE_FIREWALL="${WINN3_GATEWAY_MANAGE_FIREWALL:-1}"
    ```
  * **Residual Risk**: Installer will create managed firewall chains on target nodes.

* **Finding F-11**:
  * **Domain**: C
  * **Severity**: P0
  * **File**: server/wins_data_plane_setup_ONETOUCH.sh (lines 14:35)
  * **Evidence Quote**: "lsblk -spno TYPE \"${backing_real}\" 2>/dev/null | grep -x crypt >/dev/null"
  * **Exact Proposed Fix**:
    Support devicemapper and LVM hierarchies by verifying underlying physical disk encryption:
    ```diff
    --- a/server/wins_data_plane_setup_ONETOUCH.sh
    +++ b/server/wins_data_plane_setup_ONETOUCH.sh
    @@ -30,2 +30,5 @@
       backing_real=\"$(readlink -f \"${backing_src}\" 2>/dev/null || printf '%s' \"${backing_src}\")\"
     else
       backing_real=\"${swap_real}\"
     fi
    -lsblk -spno TYPE \"${backing_real}\" 2>/dev/null | grep -x crypt >/dev/null
    +lsblk -spno TYPE \"${backing_real}\" 2>/dev/null | grep -E -x '(crypt|dm-crypt)' >/dev/null
    ```
  * **Residual Risk**: Unsupported custom block devices must be mapped manually.

* **Finding F-12**:
  * **Domain**: A
  * **Severity**: P1
  * **File**: android/app/build.gradle.kts (lines 170:185)
  * **Evidence Quote**: "if (candidates.none(::isSafeNonEmptyReleaseInput)) {\n    failures.add(\"Engine ${engine.key}: no safe release-ready input found\")\n}"
  * **Exact Proposed Fix**:
    Validate that release-specific inputs are strictly verified if present, rather than allowing main inputs to mask broken release inputs:
    ```diff
    --- a/android/app/build.gradle.kts
    +++ b/android/app/build.gradle.kts
    @@ -172,3 +172,4 @@
    +    val releaseInput = candidates.firstOrNull { it.path.contains("/release/") }
    +    if (releaseInput != null && !isSafeNonEmptyReleaseInput(releaseInput)) {
    +        failures.add("Engine ${engine.key}: release input exists but is empty or unsafe")
    +    }
         if (candidates.none(::isSafeNonEmptyReleaseInput)) {
    ```
  * **Residual Risk**: Release builds will reject broken release engine files even if main files are valid.

* **Finding F-13**:
  * **Domain**: F
  * **Severity**: P1
  * **File**: server/spain_crypto_payments_setup.sh (lines 141:145)
  * **Evidence Quote**: "location /monero-rpc {\n        proxy_pass http://127.0.0.1:18083/json_rpc;"
  * **Exact Proposed Fix**:
    If Nginx is retained for local reverse proxying, do not rewrite the URI path:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -141,2 +141,2 @@
    -    location /monero-rpc {
    -        proxy_pass http://127.0.0.1:18083/json_rpc;
    +    location /json_rpc {
    +        proxy_pass http://127.0.0.1:18083;
    ```
  * **Residual Risk**: Callers must target `/json_rpc` directly.

* **Finding F-14**:
  * **Domain**: F
  * **Severity**: P1
  * **File**: server/spain_crypto_payments_setup.sh (lines 108:115)
  * **Evidence Quote**: "mkdir -p /var/log/winsvpn\n" and service user "User=monero-wallet" with "--log-file /var/log/winsvpn/monero-wallet-rpc.log"
  * **Exact Proposed Fix**:
    Ensure the log file and directory are owned by `monero-wallet`:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -109,2 +109,4 @@
         mkdir -p /var/log/winsvpn
    +    touch /var/log/winsvpn/monero-wallet-rpc.log
    +    chown -R monero-wallet:monero-wallet /var/log/winsvpn
    ```
  * **Residual Risk**: Permissions in `/var/log/winsvpn` allow `monero-wallet` write access.

* **Finding F-15**:
  * **Domain**: C
  * **Severity**: P1
  * **File**: winn3-nodes/deploy_and_verify.sh (lines 380:400)
  * **Evidence Quote**: "if [[ -n \"$wan_if\" ]]; then\n  while iptables -w 10 -D FORWARD -i \"$iface\" -j WINN3GW-FORWARD 2>/dev/null; do :; done\n  while iptables -w 10 -D FORWARD -o \"$iface\" -j WINN3GW-FORWARD 2>/dev/null; do :; done\n  while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done\nfi"
  * **Exact Proposed Fix**:
    Move forward and NAT postrouting chain jump deletions outside the `wan_if` check:
    ```diff
    --- a/winn3-nodes/deploy_and_verify.sh
    +++ b/winn3-nodes/deploy_and_verify.sh
    @@ -382,6 +382,6 @@
    +while iptables -w 10 -D FORWARD -i "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    +while iptables -w 10 -D FORWARD -o "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    +while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done
     if [[ -n "$wan_if" ]]; then
    -  while iptables -w 10 -D FORWARD -i "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    -  while iptables -w 10 -D FORWARD -o "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    -  while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done
       while iptables -w 10 -D INPUT -i "$iface" -d "$INNER_V4" -p tcp --dport 53 -j WINN3GW-INPUT 2>/dev/null; do :; done
     fi
    ```
  * **Residual Risk**: Cleanup proceeds reliably even when the default gateway interface is absent.

* **Finding F-16**:
  * **Domain**: D
  * **Severity**: P1
  * **File**: server/wins_control_plane_setup_ONETOUCH.sh (lines 45:55)
  * **Evidence Quote**: "if [[ -f \"${WINS_DEFAULTS_FILE}\" ]]; then\n  . \"${WINS_DEFAULTS_FILE}\"\nfi"
  * **Exact Proposed Fix**:
    Validate that configuration files are regular files, owned by root, and not world-writable before sourcing:
    ```diff
    --- a/server/wins_control_plane_setup_ONETOUCH.sh
    +++ b/server/wins_control_plane_setup_ONETOUCH.sh
    @@ -46,3 +46,5 @@
     if [[ -f "${WINS_DEFAULTS_FILE}" ]]; then
    +  wins_require_trusted_env_file "${WINS_DEFAULTS_FILE}"
       . "${WINS_DEFAULTS_FILE}"
     fi
    ```
  * **Residual Risk**: Misconfigured defaults files with insecure permissions will fail until corrected.

* **Finding F-17**:
  * **Domain**: C
  * **Severity**: P1
  * **File**: server/wins_data_plane_setup_ONETOUCH.sh (lines 60:75)
  * **Evidence Quote**: ". \"${WINS_DEFAULTS_FILE}\"\n. \"${WINS_SECRETS_FILE}\""
  * **Exact Proposed Fix**:
    Apply `wins_require_trusted_env_file` to all sourced environment files:
    ```diff
    --- a/server/wins_data_plane_setup_ONETOUCH.sh
    +++ b/server/wins_data_plane_setup_ONETOUCH.sh
    @@ -62,2 +62,4 @@
    +wins_require_trusted_env_file "${WINS_DEFAULTS_FILE}"
     . "${WINS_DEFAULTS_FILE}"
    +wins_require_trusted_env_file "${WINS_SECRETS_FILE}"
     . "${WINS_SECRETS_FILE}"
    ```
  * **Residual Risk**: Sourced files must conform strictly to ownership by root and mode 0600.

* **Finding F-18**:
  * **Domain**: G
  * **Severity**: P1
  * **File**: extension/src/core/endpoint.js (lines 91:97)
  * **Evidence Quote**: "export function pacToken(endpoint) {\n  const bare = endpoint.host.startsWith('[') && endpoint.host.endsWith(']')\n    ? endpoint.host.slice(1, -1)\n    : endpoint.host;\n  const host = bare.includes(':') ? `[${bare}]` : bare;\n  return `PROXY ${host}:${endpoint.port}`;\n}"
  * **Exact Proposed Fix**:
    Invoke `validateEndpoint` inside `pacToken` to enforce endpoint constraints:
    ```diff
    --- a/extension/src/core/endpoint.js
    +++ b/extension/src/core/endpoint.js
    @@ -91,2 +91,6 @@
     export function pacToken(endpoint) {
    +  const checked = validateEndpoint(endpoint);
    +  if (!checked.ok) {
    +    throw new TypeError("invalid loopback proxy endpoint");
    +  }
       const bare = endpoint.host.startsWith('[') && endpoint.host.endsWith(']')
    ```
  * **Residual Risk**: Invalid endpoint objects throw TypeError rather than generating malformed PAC strings.

* **Finding F-19**:
  * **Domain**: G
  * **Severity**: P1
  * **File**: extension/src/core/pac.js (lines 43:48)
  * **Evidence Quote**: "function wvMatch(rule, host) {\n  if (host === rule) { return true; }\n  return host.length > rule.length &&\n         host.substring(host.length-rule.length-1) === (\".\" + rule);\n}"
  * **Exact Proposed Fix**:
    Fix the domain suffix match index calculation:
    ```diff
    --- a/extension/src/core/pac.js
    +++ b/extension/src/core/pac.js
    @@ -44,3 +44,3 @@
       if (host === rule) { return true; }
    -  return host.length > rule.length &&\n         host.substring(host.length-rule.length-1) === ("." + rule);
    +  return host.endsWith("." + rule);
     }
    ```
  * **Residual Risk**: Standard JavaScript string methods ensure exact domain and subdomain matching.

* **Finding F-20**:
  * **Domain**: E
  * **Severity**: P1
  * **File**: web/_worker.js (lines 145:155)
  * **Evidence Quote**: "if (payload.release_id !== \"v1.0.16+33\") return emptyResponse();"
  * **Exact Proposed Fix**:
    Decouple the active release identifier from hardcoded strings in the Worker logic:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -146,2 +146,3 @@
    -  if (payload.release_id !== "v1.0.16+33") return emptyResponse();
    +  const activeRelease = env.ACTIVE_RELEASE_ID || "v1.0.16+33";
    +  if (payload.release_id !== activeRelease) return emptyResponse();
    ```
  * **Residual Risk**: Deployment workflows must update `ACTIVE_RELEASE_ID` in environment bindings.

* **Finding F-21**:
  * **Domain**: C
  * **Severity**: P1
  * **File**: server/spain_crypto_payments_setup.sh (lines 40:48)
  * **Evidence Quote**: "for pkg in curl bzip2 tar jq docker nginx; do"
  * **Exact Proposed Fix**:
    Use the correct Debian package name for Docker:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -40,3 +40,3 @@
    -    for pkg in curl bzip2 tar jq docker nginx; do
    +    for pkg in curl bzip2 tar jq docker.io nginx; do
             if ! command -v "$pkg" >/dev/null 2>&1; then
    ```
  * **Residual Risk**: Installs Debian distribution package `docker.io` rather than proprietary binary repos.

* **Finding F-22**:
  * **Domain**: G
  * **Severity**: P1
  * **File**: extension/manifest/base.jsonc (lines 4:8)
  * **Evidence Quote**: "\"name\": \"Win's VPN Companion\",\n  \"description\": \"Sends chosen sites through the Win's VPN local proxy\","
  * **Exact Proposed Fix**:
    Adopt neutral utility naming for the extension in high-threat profiles:
    ```diff
    --- a/extension/manifest/base.jsonc
    +++ b/extension/manifest/base.jsonc
    @@ -4,4 +4,4 @@
    -  "name": "Win's VPN Companion",
    -  "description": "Sends chosen sites through the Win's VPN local proxy",
    +  "name": "Web Proxy Companion",
    +  "description": "Local proxy routing utility",
    ```
  * **Residual Risk**: Branding is generic across browser extension management pages.

* **Finding F-23**:
  * **Domain**: D
  * **Severity**: P1
  * **File**: router/security.py (lines 80:95)
  * **Evidence Quote**: "PROTECTED_PATHS = {\n    \"/v1/session/create\",\n    \"/v1/session/refresh\",\n    \"/v1/session/terminate\",\n    \"/v1/entitlement/verify\",\n    \"/v1/tunnel/provision\",\n    \"/v1/tunnel/status\",\n    \"/v1/account/delete\",\n}"
  * **Exact Proposed Fix**:
    Invert routing security middleware to deny by default:
    ```diff
    --- a/router/security.py
    +++ b/router/security.py
    @@ -80,4 +80,4 @@
    -if scope.get("path") not in router_security.PROTECTED_PATHS:
    -    await self.app(scope, receive, send)
    -    return
    +if scope.get("path") in router_security.UNPROTECTED_PATHS:
    +    await self.app(scope, receive, send)
    +    return
    ```
  * **Residual Risk**: New endpoints require explicit inclusion in the public allowlist.

* **Finding F-24**:
  * **Domain**: D
  * **Severity**: P1
  * **File**: router/main.py (lines 108, 128:130)
  * **Evidence Quote**: "_STORAGE_SLOTS = threading.BoundedSemaphore(_STORAGE_MAX_WORKERS)\n...\nif not _STORAGE_SLOTS.acquire(blocking=False):\n    raise TimeoutError(\"storage worker capacity exhausted\")"
  * **Exact Proposed Fix**:
    Replace unhandled exception with a bounded acquisition timeout and structured 503 response:
    ```diff
    --- a/router/main.py
    +++ b/router/main.py
    @@ -128,3 +128,3 @@
    -if not _STORAGE_SLOTS.acquire(blocking=False):
    -    raise TimeoutError("storage worker capacity exhausted")
    +if not _STORAGE_SLOTS.acquire(blocking=True, timeout=2.0):
    +    return JSONResponse(status_code=503, content={"error": "storage_busy"})
    ```
  * **Residual Risk**: Callers experience short backpressure queuing during transaction bursts.

* **Finding F-25**:
  * **Domain**: B
  * **Severity**: P1
  * **File**: server/wins_winn3_gateway_install.sh (lines 220:235) vs android/app/build.gradle.kts (line 210)
  * **Evidence Quote**: "WINS_WINN3_DUAL_AUTH=true"
  * **Exact Proposed Fix**:
    Assert dual authentication support across both server and client configurations:
    ```diff
    --- a/server/wins_winn3_gateway_install.sh
    +++ b/server/wins_winn3_gateway_install.sh
    @@ -225,1 +225,1 @@
    -Environment="WINS_WINN3_DUAL_AUTH=false"
    +Environment="WINS_WINN3_DUAL_AUTH=true"
    ```
  * **Residual Risk**: Client builds without post-quantum ML-DSA-65 keys cannot authenticate.

* **Finding F-26**:
  * **Domain**: B
  * **Severity**: P1
  * **File**: server/wins_winn3_gateway_install.sh (lines 25:33, 312)
  * **Evidence Quote**: "WINN3_GATEWAY_FORWARD=0 (the default, and everything true of this script before 2026-08-12): an IN-PROCESS REFLECTOR."
  * **Exact Proposed Fix**:
    Configure IP forwarding explicitly on gateway nodes:
    ```diff
    --- a/server/wins_winn3_gateway_install.sh
    +++ b/server/wins_winn3_gateway_install.sh
    @@ -312,1 +312,1 @@
    -WINN3_GATEWAY_FORWARD="${WINN3_GATEWAY_FORWARD:-0}"
    +WINN3_GATEWAY_FORWARD="${WINN3_GATEWAY_FORWARD:-1}"
    ```
  * **Residual Risk**: Reflector-only test deployments must set the flag to 0 manually.

* **Finding F-27**:
  * **Domain**: E
  * **Severity**: P1
  * **File**: web/_worker.js (lines 295:305)
  * **Evidence Quote**: "while (rateBuckets.size > RATE_BUCKET_CAP) {\n  rateBuckets.delete(rateBuckets.keys().next().value);\n}"
  * **Exact Proposed Fix**:
    Evict expired keys first rather than deleting insertion-ordered keys that allow eviction attacks:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -296,3 +296,7 @@
       const now = Date.now();
    +  for (const [k, v] of rateBuckets) {
    +    if (v.resetAt <= now) rateBuckets.delete(k);
    +  }
       while (rateBuckets.size > RATE_BUCKET_CAP) {
         rateBuckets.delete(rateBuckets.keys().next().value);
       }
    ```
  * **Residual Risk**: High volumes of distinct active IPs can still cause memory-bounded turnover.

* **Finding F-28**:
  * **Domain**: A
  * **Severity**: P1
  * **File**: android/app/src/main/AndroidManifest.xml (lines 166:177)
  * **Evidence Quote**: "android:foregroundServiceType=\"specialUse\""
  * **Exact Proposed Fix**:
    Declare the required foreground service types in conformance with modern Android policies:
    ```diff
    --- a/android/app/src/main/AndroidManifest.xml
    +++ b/android/app/src/main/AndroidManifest.xml
    @@ -169,1 +169,1 @@
    -        android:foregroundServiceType="specialUse"
    +        android:foregroundServiceType="systemExempted"
    ```
  * **Residual Risk**: Play Store policy review requires specific justification for foreground service types.

* **Finding F-29**:
  * **Domain**: C
  * **Severity**: P1
  * **File**: server/wins_winn3_gateway_install.sh (lines 66:72)
  * **Evidence Quote**: "the installer deployed on the fleet's only data plane matches NO commit in this repository. The on-host copy is 275,860 bytes; the committed one is 367,410."
  * **Exact Proposed Fix**:
    Perform an operator audit of the live gateway host and re-baseline the deployment from a tagged release commit:
    ```bash
    diff -u <(ssh <CANADA_MGMT_SSH_ALIAS> 'cat /opt/winsvpn/install.sh') server/wins_winn3_gateway_install.sh
    ```
  * **Residual Risk**: Live production changes must be reconciled before deployment script execution.

* **Finding F-30**:
  * **Domain**: D
  * **Severity**: P2
  * **File**: router/security.py (lines 180:195)
  * **Evidence Quote**: "_validate_private_regular_file(path, maximum_bytes, \"nonce journal\")"
  * **Exact Proposed Fix**:
    Enforce strict process umask prior to SQLite database initialization to protect WAL sidecars:
    ```diff
    --- a/router/security.py
    +++ b/router/security.py
    @@ -185,2 +185,3 @@
         old_umask = os.umask(0o077)
         try:
             conn = sqlite3.connect(path)
    ```
  * **Residual Risk**: Concurrently created SQLite temporary files are created with mode 0600.

* **Finding F-31**:
  * **Domain**: E
  * **Severity**: P2
  * **File**: web/_worker.js (lines 220:230)
  * **Evidence Quote**: "\"https://winsvpn.pages.dev\","
  * **Exact Proposed Fix**:
    Remove preview domains from payment CORS origins:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -222,2 +222,0 @@
    -  "https://winsvpn.pages.dev",
    ```
  * **Residual Risk**: Staging builds on Pages preview URLs must use sandbox backend routes.

* **Finding F-32**:
  * **Domain**: E
  * **Severity**: P2
  * **File**: tools/verify_live_deployment.py (lines 80:95)
  * **Evidence Quote**: "if line.lower().startswith(prefix): return line[len(prefix):].strip()"
  * **Exact Proposed Fix**:
    Parse HTTP response headers scoped to root path rules:
    ```diff
    --- a/tools/verify_live_deployment.py
    +++ b/tools/verify_live_deployment.py
    @@ -82,3 +82,3 @@
    -    for raw in HEADERS_FILE.read_text(encoding="utf-8").splitlines():
    +    for raw in get_root_header_block().splitlines():
             line = raw.strip()
    ```
  * **Residual Risk**: Verifier logic accurately matches root rule headers.

* **Finding F-33**:
  * **Domain**: C
  * **Severity**: P2
  * **File**: winn3-nodes/deploy_and_verify.sh (lines 140:150)
  * **Evidence Quote**: "net.core.default_qdisc = fq"
  * **Exact Proposed Fix**:
    Set queuing discipline per interface rather than altering the global host default:
    ```diff
    --- a/winn3-nodes/deploy_and_verify.sh
    +++ b/winn3-nodes/deploy_and_verify.sh
    @@ -142,2 +142,2 @@
    -net.core.default_qdisc = fq
    +tc qdisc replace dev "$iface" root fq
    ```
  * **Residual Risk**: Interface queuing rules must be reapplied if network interfaces are reinitialized.

* **Finding F-34**:
  * **Domain**: G
  * **Severity**: P2
  * **File**: extension/manifest/base.jsonc (line 3)
  * **Evidence Quote**: "\"version\": \"1.0.0\""
  * **Exact Proposed Fix**:
    Synchronize extension release versioning with client application releases:
    ```diff
    --- a/extension/manifest/base.jsonc
    +++ b/extension/manifest/base.jsonc
    @@ -3,1 +3,1 @@
    -  "version": "1.0.0",
    +  "version": "1.0.16",
    ```
  * **Residual Risk**: Browser extension stores require version increment on every published update.

* **Finding F-35**:
  * **Domain**: F
  * **Severity**: P2
  * **File**: server/spain_crypto_payments_setup.sh (line 75)
  * **Evidence Quote**: "--daemon-address nodes.hashvault.pro:18081"
  * **Exact Proposed Fix**:
    Connect Monero wallet daemon to an internal private daemon node:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -75,1 +75,1 @@
    -    --daemon-address nodes.hashvault.pro:18081 \\
    +    --daemon-address 10.0.0.5:18081 \\
    ```
  * **Residual Risk**: Node operator must maintain a synced private Monero full node.

* **Finding F-36**:
  * **Domain**: H
  * **Severity**: P2
  * **File**: android/app/build.gradle.kts (line 208) and apple/
  * **Evidence Quote**: "WINS_WINN3_ENABLED_PLATFORMS=android"
  * **Exact Proposed Fix**:
    Implement PacketTunnel camouflage parity and engine bindings for Apple platforms:
    ```bash
    # Inventory action: schedule Apple PacketTunnelEngine review and disguise parity in Round 37
    ```
  * **Residual Risk**: iOS and macOS clients currently lack dynamic camouflage capabilities.
EOF
python3 /tmp/generate_verdict.py
python3 /tmp/validate_stage2.py /tmp/stage2_verdict.md
,Cwd:/Users/owner,WaitMsBeforeAsync:5000,toolAction:Testing final text generation,toolSummary:Final text check}
# Round 36 Stage 2: Adversarial Cross-Examination (Seat 1: Antigravity)

ROUND 36 SURFACE AUDIT REVISED VERDICT AND CROSS-EXAMINATION

1. **Steelman Analysis of Opposing Seats**:
   * **Seat 2 (Claude Opus 5)**:
     Seat 2 reasoned from an architectural threat model where physical handset inspection and local forensic discovery are co-equal with network surveillance. In a high-threat jurisdiction such as Myanmar, a cryptographic transport protocol is ineffective if the host operating system reveals the application identity on the home screen, or if an administrative installer executes arbitrary code as root. Seat 2 provided exceptional depth across operational configurations, systemd definitions, edge routing, and build tooling.
     The single strongest point in Seat 2's verdict is Finding F-2 (The structural breakdown of Android disguise: `.LauncherReal` is enabled by default in `AndroidManifest.xml`, displaying "Win's VPN" on the launcher immediately upon installation) and Finding F-20 (The Nginx reverse proxy rewrites `/monero-rpc` to `/json_rpc`, which breaks HTTP Digest authentication by changing the URI parameter that the cryptographic digest binds to).
   * **Seat 3 (GPT-5.6 Sol Pro)**:
     Seat 3 reasoned from strict execution correctness, deterministic state evaluation, and root privilege boundaries. It focused on the principle that shell scripts executing with root authority must never ingest unpinned remote network code or expose credentials in world-readable command invocations. Seat 3 provided rigorous analysis of shell control flow, file type assertions, and firewall rollback routines.
     The single strongest point in Seat 3's verdict is Finding F-1 (Root installer executes an unpinned git clone of `btcpayserver-docker`, allowing arbitrary upstream code execution with root authority) and Finding F-4 (`handleMapTile` functions as an open, unauthenticated reverse proxy that forwards arbitrary upstream coordinates without origin verification or rate limiting).

2. **Impact of Opposing Reasoning on Seat 1 Positions**:
   * **Accepted and Merged Findings**:
     Seat 1 accepts Seat 3 F-1 and Seat 2 F-5, merging unpinned remote repository execution in `spain_crypto_payments_setup.sh` as P0.
     Seat 1 accepts Seat 3 F-2 and Seat 2 F-4, merging the cleartext Monero RPC password exposure in systemd command lines and stdout as P0.
     Seat 1 accepts Seat 2 F-2, deepening our Android disguise analysis (Seat 1 F-3) to include the default enabled state of `.LauncherReal` as P0.
     Seat 1 accepts Seat 3 F-4 and Seat 2 F-8, merging the `handleMapTile` open proxy SSRF risk as P0.
     Seat 1 accepts Seat 3 F-6 and Seat 2 F-10, adding the flaw in `verifyAndroidReleaseEngineInputs` in `build.gradle.kts` as P1.
     Seat 1 accepts Seat 3 F-8, F-9 and Seat 2 F-12, F-13, adding missing permission and symlink checks on sourced environment files as P1.
     Seat 1 accepts Seat 3 F-10 and Seat 2 F-14, adding the `/var/log/winsvpn` ownership barrier for `monero-wallet` as P1.
     Seat 1 accepts Seat 3 F-12 and Seat 2 F-11, adding the missing firewall rollback jump deletion as P1.
     Seat 1 accepts Seat 2 F-20, adding the HTTP Digest authentication URI rewriting defect in the Nginx proxy as P1.
     Seat 1 accepts Seat 2 F-18, adding the hardcoded release version break in `_worker.js` as P1.
     Seat 1 accepts Seat 2 F-22, adding the browser extension name disclosure as P1.
     Seat 1 accepts Seat 2 F-27, adding the rate bucket FIFO eviction vulnerability as P1.
     Seat 1 accepts Seat 2 F-32, adding SQLite sidecar file permission verification as P2.
     Seat 1 accepts Seat 2 F-34, adding the global queueing discipline modification risk as P2.
   * **Refutations and Clarifications**:
     Seat 1 refutes Seat 2 F-26 regarding alleged syntax errors in `wins_data_plane_setup_ONETOUCH.sh`. The text `ADMIN_TOKEN: "[REDACTED]"` is an artifact of the local privacy gate redaction applied to the audit packet, not an error in the underlying repository source code.
     Seat 1 refutes treating Seat 2 F-24 (deleted audit receipt files in git status) as an operational code defect. Working tree file staging during active refactoring is an internal repository management concern. It is recorded under P2 hygiene rather than as a blocking functional defect.
     Seat 1 notes that Seat 3 omitted the third-party tracking origins in Content-Security-Policy (Seat 1 F-1 and Seat 2 F-1). Seat 1 strictly maintains this as a P0 issue: for users in high-threat jurisdictions, transmitting client network metadata to commercial advertising endpoints creates immediate user enumeration exposure.

3. **Revised Final Findings List**:

* **Finding F-1**:
  * **Domain**: E
  * **Severity**: P0
  * **File**: web/_headers (lines 14:16)
  * **Evidence Quote**: "img-src 'self' data: https: https://www.facebook.com https://www.google-analytics.com https://www.google.com https://www.googleadservices.com; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.googletagmanager.com https://connect.facebook.net https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://stats.g.doubleclick.net https://www.facebook.com"
  * **Exact Proposed Fix**:
    Remove all third-party tracker domains from Content-Security-Policy in web/_headers:
    ```diff
    --- a/web/_headers
    +++ b/web/_headers
    @@ -14,3 +14,3 @@
    -  Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https: https://www.facebook.com https://www.google-analytics.com https://www.google.com https://www.googleadservices.com; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.googletagmanager.com https://connect.facebook.net https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://stats.g.doubleclick.net https://www.facebook.com https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://applepay.cdn-apple.com https://pay.google.com; frame-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://pay.google.com; form-action 'self' https://www.paypal.com https://www.paypalobjects.com; upgrade-insecure-requests
    +  Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://applepay.cdn-apple.com https://pay.google.com; frame-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://pay.google.com; form-action 'self' https://www.paypal.com https://www.paypalobjects.com; upgrade-insecure-requests
    ```
    Remove tracker script tags from web/index.html, recompute the script hashes, and enforce clean headers in tools/verify_live_deployment.py.
  * **Residual Risk**: External conversion tracking for marketing ceases. Visitors are shielded from commercial tracker enumeration.

* **Finding F-2**:
  * **Domain**: A
  * **Severity**: P0
  * **File**: android/app/src/main/AndroidManifest.xml (lines 35:58, 220:235) and android/app/build.gradle.kts
  * **Evidence Quote**: "android:name=\".LauncherReal\" android:enabled=\"true\" ... android:label=\"Win's VPN\"" and "<uses-permission android:name=\"android.permission.QUERY_ALL_PACKAGES\" tools:ignore=\"QueryAllPackagesPermission\" />"
  * **Exact Proposed Fix**:
    In android/app/src/main/AndroidManifest.xml, invert default component availability so the calculator decoy is active on clean installs, and remove QUERY_ALL_PACKAGES:
    ```diff
    --- a/android/app/src/main/AndroidManifest.xml
    +++ b/android/app/src/main/AndroidManifest.xml
    @@ -55,3 +55,0 @@
    -    <uses-permission
    -        android:name="android.permission.QUERY_ALL_PACKAGES"
    -        tools:ignore="QueryAllPackagesPermission" />
    @@ -222,2 +219,2 @@
         <activity-alias
    -        android:name=".LauncherReal"
    -        android:enabled="true"
    +        android:name=".LauncherReal"
    +        android:enabled="false"
             android:exported="true"
    -        android:label="Win's VPN"
    +        android:label="@string/app_name_decoy"
             android:targetActivity=".MainActivity">
    @@ -231,2 +228,2 @@
         <activity-alias
             android:name=".LauncherDecoy"
    -        android:enabled="false"
    +        android:enabled="true"
             android:exported="true"
    ```
  * **Residual Risk**: Users who want the direct brand launcher icon must explicitly toggle it from the internal settings screen.

* **Finding F-3**:
  * **Domain**: A
  * **Severity**: P0
  * **File**: android/app/src/main/AndroidManifest.xml (lines 188:193)
  * **Evidence Quote**: "<receiver android:name=\".SecretCodeReceiver\" android:exported=\"true\">\n            <intent-filter>\n                <action android:name=\"android.intent.action.MAIN\" />\n                <action android:name=\"android.provider.Telephony.SECRET_CODE\" />\n                <data android:scheme=\"android_secret_code\" android:host=\"9467\" />\n            </intent-filter>\n        </receiver>"
  * **Exact Proposed Fix**:
    Remove the exported broadcast receiver with static host code. Route disguise toggling through the calculator UI logic or protect the receiver:
    ```diff
    --- a/android/app/src/main/AndroidManifest.xml
    +++ b/android/app/src/main/AndroidManifest.xml
    @@ -188,6 +188,2 @@
    -        <receiver android:name=".SecretCodeReceiver" android:exported="true">
    -            <intent-filter>
    -                <action android:name="android.intent.action.MAIN" />
    -                <action android:name="android.provider.Telephony.SECRET_CODE" />
    -                <data android:scheme="android_secret_code" android:host="9467" />
    -            </intent-filter>
    -        </receiver>
    +        <receiver android:name=".SecretCodeReceiver" android:exported="false" />
    ```
  * **Residual Risk**: Launching via telephone dialer code is disabled. The disguise unmasking operates via the calculator formula interface.

* **Finding F-4**:
  * **Domain**: F
  * **Severity**: P0
  * **File**: server/spain_crypto_payments_setup.sh (lines 90:105)
  * **Evidence Quote**: "git clone https://github.com/btcpayserver/btcpayserver-docker.git \"${BTCPAY_DOCKER_DIR}\"\n    cd \"${BTCPAY_DOCKER_DIR}\"\n    . ./btcpay-setup.sh -i"
  * **Exact Proposed Fix**:
    Require a verified, pinned commit for the BTCPay repository prior to executing root installation code:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -90,3 +90,10 @@
    +    : "${BTCPAY_REVIEWED_COMMIT:?BTCPAY_REVIEWED_COMMIT must be defined with reviewed 40-char commit}"
    +    if [[ ! -d "${BTCPAY_DOCKER_DIR}/.git" ]]; then
              git clone https://github.com/btcpayserver/btcpayserver-docker.git "${BTCPAY_DOCKER_DIR}"
    +    fi
         cd "${BTCPAY_DOCKER_DIR}"
    +    git fetch origin
    +    git checkout "${BTCPAY_REVIEWED_COMMIT}"
    +    local actual_commit
    +    actual_commit="$(git rev-parse HEAD)"
    +    [[ "${actual_commit}" == "${BTCPAY_REVIEWED_COMMIT}" ]] || { echo "Commit verification failed"; exit 1; }
         . ./btcpay-setup.sh -i
    ```
  * **Residual Risk**: Operator must supply and verify the immutable commit identifier when provisioning nodes.

* **Finding F-5**:
  * **Domain**: F
  * **Severity**: P0
  * **File**: server/spain_crypto_payments_setup.sh (lines 110:135, 175:180)
  * **Evidence Quote**: "ExecStart=/usr/local/bin/monero-wallet-rpc \\\n    --daemon-address nodes.hashvault.pro:18081 \\\n    --rpc-login ${rpc_user}:${rpc_pass} \\\n" and "printf 'MONERO_WALLET_RPC_PASS=\"%s\"\\n' \"${rpc_pass}\""
  * **Exact Proposed Fix**:
    Store authentication credentials in an environment file with restricted permissions (0600) and reference them via login file or environment variable:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -115,2 +115,4 @@
    +    local auth_file="/etc/monero/wallet-rpc.auth"
    +    mkdir -p /etc/monero && chmod 0700 /etc/monero
    +    printf '%s:%s\n' "${rpc_user}" "${rpc_pass}" > "${auth_file}"
    +    chmod 0600 "${auth_file}" && chown monero-wallet:monero-wallet "${auth_file}"
    @@ -120,3 +122,3 @@
         ExecStart=/usr/local/bin/monero-wallet-rpc \\
    -        --rpc-login ${rpc_user}:${rpc_pass} \\
    +        --rpc-login-file /etc/monero/wallet-rpc.auth \\
             --wallet-dir /var/lib/monero-wallet \\
    @@ -176,1 +178,0 @@
    -    printf 'MONERO_WALLET_RPC_PASS="%s"\n' "${rpc_pass}"
    ```
  * **Residual Risk**: Operators must inspect the protected credentials file directly rather than relying on stdout summary.

* **Finding F-6**:
  * **Domain**: F
  * **Severity**: P0
  * **File**: server/spain_crypto_payments_setup.sh (lines 140:155)
  * **Evidence Quote**: "location /monero-rpc {\n        proxy_pass http://127.0.0.1:18083/json_rpc;\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto https;\n        proxy_pass_header Authorization;\n        proxy_pass_header WWW-Authenticate;\n        proxy_read_timeout 60s;\n        proxy_send_timeout 60s;\n    }"
  * **Exact Proposed Fix**:
    Remove public exposure of the Monero RPC endpoint from the external Nginx configuration:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -140,14 +140,0 @@
    -    location /monero-rpc {
    -        proxy_pass http://127.0.0.1:18083/json_rpc;
    -        proxy_http_version 1.1;
    -        proxy_set_header Host $host;
    -        proxy_set_header X-Real-IP $remote_addr;
    -        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    -        proxy_set_header X-Forwarded-Proto https;
    -        proxy_pass_header Authorization;
    -        proxy_pass_header WWW-Authenticate;
    -        proxy_read_timeout 60s;
    -        proxy_send_timeout 60s;
    -    }
    ```
    Route Kansas Hub traffic to the Monero wallet RPC service across the private WireGuard tunnel directly.
  * **Residual Risk**: Kansas Hub must possess an established WireGuard interface connected to the Spain node.

* **Finding F-7**:
  * **Domain**: E
  * **Severity**: P0
  * **File**: web/wrangler.jsonc (lines 1:12) and web/_worker.js (lines 270:285)
  * **Evidence Quote**: "NOT USED BY THE CURRENT LIVE DEPLOYMENT... Cloudflare Rate Limiting bindings (the ratelimits block below) are a Workers-only feature" and "env[bindingName].limit({ key })"
  * **Exact Proposed Fix**:
    In web/_worker.js, defend against missing Cloudflare rate limiting bindings:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -272,3 +272,3 @@
    -  if (env && env[bindingName]) {
    +  if (env && env[bindingName] && typeof env[bindingName].limit === "function") {
         return await env[bindingName].limit({ key });
       }
    ```
    Implement durable rate limiting via KV store or local in-memory tracking that does not fail when bindings are absent.
  * **Residual Risk**: In-memory rate limiting counters do not synchronize across distributed Cloudflare edge nodes.

* **Finding F-8**:
  * **Domain**: E
  * **Severity**: P0
  * **File**: web/_worker.js (lines 380:410)
  * **Evidence Quote**: "async function handleMapTile(request, env) {\n  const url = new URL(request.url);\n  const match = url.pathname.match(/^\\/api\\/map\\/tile\\/(\\d+)\\/(\\d+)\\/(\\d+)\\.png$/);\n  if (!match) return new Response(\"Not found\", { status: 404 });\n  const [, z, x, y] = match;\n  const tileUrl = `https://tile.openstreetmap.org/${z}/${x}/${y}.png`;\n  return fetch(tileUrl, { headers: { \"User-Agent\": \"WinsVPN-Web/1.0\" } });\n}"
  * **Exact Proposed Fix**:
    Validate request origin and constrain coordinate zoom levels to prevent open proxy misuse:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -385,2 +385,6 @@
       const [, z, x, y] = match;
    +  const origin = request.headers.get("origin") || "";
    +  if (!allowedOrigins.has(origin) && request.headers.get("sec-fetch-site") !== "same-origin") {
    +    return new Response("Forbidden", { status: 403 });
    +  }
    +  if (parseInt(z, 10) > 6) return new Response("Zoom level prohibited", { status: 400 });
       const tileUrl = `https://tile.openstreetmap.org/${z}/${x}/${y}.png`;
    ```
  * **Residual Risk**: Legitimate client map views are bounded to overview zoom levels.

* **Finding F-9**:
  * **Domain**: D
  * **Severity**: P0
  * **File**: router/security.py (lines 231:236)
  * **Evidence Quote**: "def decision_log_path() -> Path:\n    return _absolute_file_path(\n        os.environ.get(\"DECISIONS_FILE\", \"/tmp/router_decisions.jsonl\"),\n        \"DECISIONS_FILE\",\n    )"
  * **Exact Proposed Fix**:
    Relocate the default decision log path out of `/tmp` into a secure application directory:
    ```diff
    --- a/router/security.py
    +++ b/router/security.py
    @@ -232,2 +232,2 @@
         return _absolute_file_path(
    -        os.environ.get("DECISIONS_FILE", "/tmp/router_decisions.jsonl"),
    +        os.environ.get("DECISIONS_FILE", "/var/log/winsvpn/router_decisions.jsonl"),
             "DECISIONS_FILE",
    ```
  * **Residual Risk**: The `/var/log/winsvpn` directory must be created with ownership assigned to the router service user.

* **Finding F-10**:
  * **Domain**: C
  * **Severity**: P0
  * **File**: server/wins_winn3_gateway_install.sh (lines 283:294)
  * **Evidence Quote**: "Off by default. On the fleet's only node the host INPUT policy is ACCEPT and no WINVPN-INPUT chain exists, so no host rule is needed and adding one would be a change to a live node's firewall for no benefit. Set to 1 only on a node that genuinely default-drops INPUT.\nWINN3_GATEWAY_MANAGE_FIREWALL=\"${WINN3_GATEWAY_MANAGE_FIREWALL:-0}\""
  * **Exact Proposed Fix**:
    Default `WINN3_GATEWAY_MANAGE_FIREWALL` to 1 and inspect existing chain posture before skipping firewall rule generation:
    ```diff
    --- a/server/wins_winn3_gateway_install.sh
    +++ b/server/wins_winn3_gateway_install.sh
    @@ -293,1 +293,1 @@
    -WINN3_GATEWAY_MANAGE_FIREWALL="${WINN3_GATEWAY_MANAGE_FIREWALL:-0}"
    +WINN3_GATEWAY_MANAGE_FIREWALL="${WINN3_GATEWAY_MANAGE_FIREWALL:-1}"
    ```
  * **Residual Risk**: Installer will create managed firewall chains on target nodes.

* **Finding F-11**:
  * **Domain**: C
  * **Severity**: P0
  * **File**: server/wins_data_plane_setup_ONETOUCH.sh (lines 14:35)
  * **Evidence Quote**: "lsblk -spno TYPE \"${backing_real}\" 2>/dev/null | grep -x crypt >/dev/null"
  * **Exact Proposed Fix**:
    Support devicemapper and LVM hierarchies by verifying underlying physical disk encryption:
    ```diff
    --- a/server/wins_data_plane_setup_ONETOUCH.sh
    +++ b/server/wins_data_plane_setup_ONETOUCH.sh
    @@ -30,2 +30,5 @@
       backing_real=\"$(readlink -f \"${backing_src}\" 2>/dev/null || printf '%s' \"${backing_src}\")\"
     else
       backing_real=\"${swap_real}\"
     fi
    -lsblk -spno TYPE \"${backing_real}\" 2>/dev/null | grep -x crypt >/dev/null
    +lsblk -spno TYPE \"${backing_real}\" 2>/dev/null | grep -E -x '(crypt|dm-crypt)' >/dev/null
    ```
  * **Residual Risk**: Unsupported custom block devices must be mapped manually.

* **Finding F-12**:
  * **Domain**: A
  * **Severity**: P1
  * **File**: android/app/build.gradle.kts (lines 170:185)
  * **Evidence Quote**: "if (candidates.none(::isSafeNonEmptyReleaseInput)) {\n    failures.add(\"Engine ${engine.key}: no safe release-ready input found\")\n}"
  * **Exact Proposed Fix**:
    Validate that release-specific inputs are strictly verified if present, rather than allowing main inputs to mask broken release inputs:
    ```diff
    --- a/android/app/build.gradle.kts
    +++ b/android/app/build.gradle.kts
    @@ -172,3 +172,4 @@
    +    val releaseInput = candidates.firstOrNull { it.path.contains("/release/") }
    +    if (releaseInput != null && !isSafeNonEmptyReleaseInput(releaseInput)) {
    +        failures.add("Engine ${engine.key}: release input exists but is empty or unsafe")
    +    }
         if (candidates.none(::isSafeNonEmptyReleaseInput)) {
    ```
  * **Residual Risk**: Release builds will reject broken release engine files even if main files are valid.

* **Finding F-13**:
  * **Domain**: F
  * **Severity**: P1
  * **File**: server/spain_crypto_payments_setup.sh (lines 141:145)
  * **Evidence Quote**: "location /monero-rpc {\n        proxy_pass http://127.0.0.1:18083/json_rpc;"
  * **Exact Proposed Fix**:
    If Nginx is retained for local reverse proxying, do not rewrite the URI path:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -141,2 +141,2 @@
    -    location /monero-rpc {
    -        proxy_pass http://127.0.0.1:18083/json_rpc;
    +    location /json_rpc {
    +        proxy_pass http://127.0.0.1:18083;
    ```
  * **Residual Risk**: Callers must target `/json_rpc` directly.

* **Finding F-14**:
  * **Domain**: F
  * **Severity**: P1
  * **File**: server/spain_crypto_payments_setup.sh (lines 108:115)
  * **Evidence Quote**: "mkdir -p /var/log/winsvpn\n" and service user "User=monero-wallet" with "--log-file /var/log/winsvpn/monero-wallet-rpc.log"
  * **Exact Proposed Fix**:
    Ensure the log file and directory are owned by `monero-wallet`:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -109,2 +109,4 @@
         mkdir -p /var/log/winsvpn
    +    touch /var/log/winsvpn/monero-wallet-rpc.log
    +    chown -R monero-wallet:monero-wallet /var/log/winsvpn
    ```
  * **Residual Risk**: Permissions in `/var/log/winsvpn` allow `monero-wallet` write access.

* **Finding F-15**:
  * **Domain**: C
  * **Severity**: P1
  * **File**: winn3-nodes/deploy_and_verify.sh (lines 380:400)
  * **Evidence Quote**: "if [[ -n \"$wan_if\" ]]; then\n  while iptables -w 10 -D FORWARD -i \"$iface\" -j WINN3GW-FORWARD 2>/dev/null; do :; done\n  while iptables -w 10 -D FORWARD -o \"$iface\" -j WINN3GW-FORWARD 2>/dev/null; do :; done\n  while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done\nfi"
  * **Exact Proposed Fix**:
    Move forward and NAT postrouting chain jump deletions outside the `wan_if` check:
    ```diff
    --- a/winn3-nodes/deploy_and_verify.sh
    +++ b/winn3-nodes/deploy_and_verify.sh
    @@ -382,6 +382,6 @@
    +while iptables -w 10 -D FORWARD -i "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    +while iptables -w 10 -D FORWARD -o "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    +while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done
     if [[ -n "$wan_if" ]]; then
    -  while iptables -w 10 -D FORWARD -i "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    -  while iptables -w 10 -D FORWARD -o "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    -  while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done
       while iptables -w 10 -D INPUT -i "$iface" -d "$INNER_V4" -p tcp --dport 53 -j WINN3GW-INPUT 2>/dev/null; do :; done
     fi
    ```
  * **Residual Risk**: None. Cleanup proceeds reliably even when the default gateway interface is absent.

* **Finding F-16**:
  * **Domain**: D
  * **Severity**: P1
  * **File**: server/wins_control_plane_setup_ONETOUCH.sh (lines 45:55)
  * **Evidence Quote**: "if [[ -f \"${WINS_DEFAULTS_FILE}\" ]]; then\n  . \"${WINS_DEFAULTS_FILE}\"\nfi"
  * **Exact Proposed Fix**:
    Validate that configuration files are regular files, owned by root, and not world-writable before sourcing:
    ```diff
    --- a/server/wins_control_plane_setup_ONETOUCH.sh
    +++ b/server/wins_control_plane_setup_ONETOUCH.sh
    @@ -46,3 +46,5 @@
     if [[ -f "${WINS_DEFAULTS_FILE}" ]]; then
    +  wins_require_trusted_env_file "${WINS_DEFAULTS_FILE}"
       . "${WINS_DEFAULTS_FILE}"
     fi
    ```
  * **Residual Risk**: Misconfigured defaults files with insecure permissions will fail until corrected.

* **Finding F-17**:
  * **Domain**: C
  * **Severity**: P1
  * **File**: server/wins_data_plane_setup_ONETOUCH.sh (lines 60:75)
  * **Evidence Quote**: ". \"${WINS_DEFAULTS_FILE}\"\n. \"${WINS_SECRETS_FILE}\""
  * **Exact Proposed Fix**:
    Apply `wins_require_trusted_env_file` to all sourced environment files:
    ```diff
    --- a/server/wins_data_plane_setup_ONETOUCH.sh
    +++ b/server/wins_data_plane_setup_ONETOUCH.sh
    @@ -62,2 +62,4 @@
    +wins_require_trusted_env_file "${WINS_DEFAULTS_FILE}"
     . "${WINS_DEFAULTS_FILE}"
    +wins_require_trusted_env_file "${WINS_SECRETS_FILE}"
     . "${WINS_SECRETS_FILE}"
    ```
  * **Residual Risk**: Sourced files must conform strictly to ownership by root and mode 0600.

* **Finding F-18**:
  * **Domain**: G
  * **Severity**: P1
  * **File**: extension/src/core/endpoint.js (lines 91:97)
  * **Evidence Quote**: "export function pacToken(endpoint) {\n  const bare = endpoint.host.startsWith('[') && endpoint.host.endsWith(']')\n    ? endpoint.host.slice(1, -1)\n    : endpoint.host;\n  const host = bare.includes(':') ? `[${bare}]` : bare;\n  return `PROXY ${host}:${endpoint.port}`;\n}"
  * **Exact Proposed Fix**:
    Invoke `validateEndpoint` inside `pacToken` to enforce endpoint constraints:
    ```diff
    --- a/extension/src/core/endpoint.js
    +++ b/extension/src/core/endpoint.js
    @@ -91,2 +91,6 @@
     export function pacToken(endpoint) {
    +  const checked = validateEndpoint(endpoint);
    +  if (!checked.ok) {
    +    throw new TypeError("invalid loopback proxy endpoint");
    +  }
       const bare = endpoint.host.startsWith('[') && endpoint.host.endsWith(']')
    ```
  * **Residual Risk**: Invalid endpoint objects throw TypeError rather than generating malformed PAC strings.

* **Finding F-19**:
  * **Domain**: G
  * **Severity**: P1
  * **File**: extension/src/core/pac.js (lines 43:48)
  * **Evidence Quote**: "function wvMatch(rule, host) {\n  if (host === rule) { return true; }\n  return host.length > rule.length &&\n         host.substring(host.length-rule.length-1) === (\".\" + rule);\n}"
  * **Exact Proposed Fix**:
    Fix the domain suffix match index calculation:
    ```diff
    --- a/extension/src/core/pac.js
    +++ b/extension/src/core/pac.js
    @@ -44,3 +44,3 @@
       if (host === rule) { return true; }
    -  return host.length > rule.length &&\n         host.substring(host.length-rule.length-1) === ("." + rule);
    +  return host.endsWith("." + rule);
     }
    ```
  * **Residual Risk**: Standard JavaScript string methods ensure exact domain and subdomain matching.

* **Finding F-20**:
  * **Domain**: E
  * **Severity**: P1
  * **File**: web/_worker.js (lines 145:155)
  * **Evidence Quote**: "if (payload.release_id !== \"v1.0.16+33\") return emptyResponse();"
  * **Exact Proposed Fix**:
    Decouple the active release identifier from hardcoded strings in the Worker logic:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -146,2 +146,3 @@
    -  if (payload.release_id !== "v1.0.16+33") return emptyResponse();
    +  const activeRelease = env.ACTIVE_RELEASE_ID || "v1.0.16+33";
    +  if (payload.release_id !== activeRelease) return emptyResponse();
    ```
  * **Residual Risk**: Deployment workflows must update `ACTIVE_RELEASE_ID` in environment bindings.

* **Finding F-21**:
  * **Domain**: C
  * **Severity**: P1
  * **File**: server/spain_crypto_payments_setup.sh (lines 40:48)
  * **Evidence Quote**: "for pkg in curl bzip2 tar jq docker nginx; do"
  * **Exact Proposed Fix**:
    Use the correct Debian package name for Docker:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -40,3 +40,3 @@
    -    for pkg in curl bzip2 tar jq docker nginx; do
    +    for pkg in curl bzip2 tar jq docker.io nginx; do
             if ! command -v "$pkg" >/dev/null 2>&1; then
    ```
  * **Residual Risk**: Installs Debian distribution package `docker.io` rather than proprietary binary repos.

* **Finding F-22**:
  * **Domain**: G
  * **Severity**: P1
  * **File**: extension/manifest/base.jsonc (lines 4:8)
  * **Evidence Quote**: "\"name\": \"Win's VPN Companion\",\n  \"description\": \"Sends chosen sites through the Win's VPN local proxy\","
  * **Exact Proposed Fix**:
    Adopt neutral utility naming for the extension in high-threat profiles:
    ```diff
    --- a/extension/manifest/base.jsonc
    +++ b/extension/manifest/base.jsonc
    @@ -4,4 +4,4 @@
    -  "name": "Win's VPN Companion",
    -  "description": "Sends chosen sites through the Win's VPN local proxy",
    +  "name": "Web Proxy Companion",
    +  "description": "Local proxy routing utility",
    ```
  * **Residual Risk**: Branding is generic across browser extension management pages.

* **Finding F-23**:
  * **Domain**: D
  * **Severity**: P1
  * **File**: router/security.py (lines 80:95)
  * **Evidence Quote**: "PROTECTED_PATHS = {\n    \"/v1/session/create\",\n    \"/v1/session/refresh\",\n    \"/v1/session/terminate\",\n    \"/v1/entitlement/verify\",\n    \"/v1/tunnel/provision\",\n    \"/v1/tunnel/status\",\n    \"/v1/account/delete\",\n}"
  * **Exact Proposed Fix**:
    Invert routing security middleware to deny by default:
    ```diff
    --- a/router/security.py
    +++ b/router/security.py
    @@ -80,4 +80,4 @@
    -if scope.get("path") not in router_security.PROTECTED_PATHS:
    -    await self.app(scope, receive, send)
    -    return
    +if scope.get("path") in router_security.UNPROTECTED_PATHS:
    +    await self.app(scope, receive, send)
    +    return
    ```
  * **Residual Risk**: New endpoints require explicit inclusion in the public allowlist.

* **Finding F-24**:
  * **Domain**: D
  * **Severity**: P1
  * **File**: router/main.py (lines 108, 128:130)
  * **Evidence Quote**: "_STORAGE_SLOTS = threading.BoundedSemaphore(_STORAGE_MAX_WORKERS)\n...\nif not _STORAGE_SLOTS.acquire(blocking=False):\n    raise TimeoutError(\"storage worker capacity exhausted\")"
  * **Exact Proposed Fix**:
    Replace unhandled exception with a bounded acquisition timeout and structured 503 response:
    ```diff
    --- a/router/main.py
    +++ b/router/main.py
    @@ -128,3 +128,3 @@
    -if not _STORAGE_SLOTS.acquire(blocking=False):
    -    raise TimeoutError("storage worker capacity exhausted")
    +if not _STORAGE_SLOTS.acquire(blocking=True, timeout=2.0):
    +    return JSONResponse(status_code=503, content={"error": "storage_busy"})
    ```
  * **Residual Risk**: Callers experience short backpressure queuing during transaction bursts.

* **Finding F-25**:
  * **Domain**: B
  * **Severity**: P1
  * **File**: server/wins_winn3_gateway_install.sh (lines 220:235) vs android/app/build.gradle.kts (line 210)
  * **Evidence Quote**: "WINS_WINN3_DUAL_AUTH=true"
  * **Exact Proposed Fix**:
    Assert dual authentication support across both server and client configurations:
    ```diff
    --- a/server/wins_winn3_gateway_install.sh
    +++ b/server/wins_winn3_gateway_install.sh
    @@ -225,1 +225,1 @@
    -Environment="WINS_WINN3_DUAL_AUTH=false"
    +Environment="WINS_WINN3_DUAL_AUTH=true"
    ```
  * **Residual Risk**: Client builds without post-quantum ML-DSA-65 keys cannot authenticate.

* **Finding F-26**:
  * **Domain**: B
  * **Severity**: P1
  * **File**: server/wins_winn3_gateway_install.sh (lines 25:33, 312)
  * **Evidence Quote**: "WINN3_GATEWAY_FORWARD=0 (the default, and everything true of this script before 2026-08-12): an IN-PROCESS REFLECTOR."
  * **Exact Proposed Fix**:
    Configure IP forwarding explicitly on gateway nodes:
    ```diff
    --- a/server/wins_winn3_gateway_install.sh
    +++ b/server/wins_winn3_gateway_install.sh
    @@ -312,1 +312,1 @@
    -WINN3_GATEWAY_FORWARD="${WINN3_GATEWAY_FORWARD:-0}"
    +WINN3_GATEWAY_FORWARD="${WINN3_GATEWAY_FORWARD:-1}"
    ```
  * **Residual Risk**: Reflector-only test deployments must set the flag to 0 manually.

* **Finding F-27**:
  * **Domain**: E
  * **Severity**: P1
  * **File**: web/_worker.js (lines 295:305)
  * **Evidence Quote**: "while (rateBuckets.size > RATE_BUCKET_CAP) {\n  rateBuckets.delete(rateBuckets.keys().next().value);\n}"
  * **Exact Proposed Fix**:
    Evict expired keys first rather than deleting insertion-ordered keys that allow eviction attacks:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -296,3 +296,7 @@
       const now = Date.now();
    +  for (const [k, v] of rateBuckets) {
    +    if (v.resetAt <= now) rateBuckets.delete(k);
    +  }
       while (rateBuckets.size > RATE_BUCKET_CAP) {
         rateBuckets.delete(rateBuckets.keys().next().value);
       }
    ```
  * **Residual Risk**: High volumes of distinct active IPs can still cause memory-bounded turnover.

* **Finding F-28**:
  * **Domain**: A
  * **Severity**: P1
  * **File**: android/app/src/main/AndroidManifest.xml (lines 166:177)
  * **Evidence Quote**: "android:foregroundServiceType=\"specialUse\""
  * **Exact Proposed Fix**:
    Declare the required foreground service types in conformance with modern Android policies:
    ```diff
    --- a/android/app/src/main/AndroidManifest.xml
    +++ b/android/app/src/main/AndroidManifest.xml
    @@ -169,1 +169,1 @@
    -        android:foregroundServiceType="specialUse"
    +        android:foregroundServiceType="systemExempted"
    ```
  * **Residual Risk**: Play Store policy review requires specific justification for foreground service types.

* **Finding F-29**:
  * **Domain**: C
  * **Severity**: P1
  * **File**: server/wins_winn3_gateway_install.sh (lines 66:72)
  * **Evidence Quote**: "the installer deployed on the fleet's only data plane matches NO commit in this repository. The on-host copy is 275,860 bytes; the committed one is 367,410."
  * **Exact Proposed Fix**:
    Perform an operator audit of the live gateway host and re-baseline the deployment from a tagged release commit:
    ```bash
    diff -u <(ssh <CANADA_MGMT_SSH_ALIAS> 'cat /opt/winsvpn/install.sh') server/wins_winn3_gateway_install.sh
    ```
  * **Residual Risk**: Live production changes must be reconciled before deployment script execution.

* **Finding F-30**:
  * **Domain**: D
  * **Severity**: P2
  * **File**: router/security.py (lines 180:195)
  * **Evidence Quote**: "_validate_private_regular_file(path, maximum_bytes, \"nonce journal\")"
  * **Exact Proposed Fix**:
    Enforce strict process umask prior to SQLite database initialization to protect WAL sidecars:
    ```diff
    --- a/router/security.py
    +++ b/router/security.py
    @@ -185,2 +185,3 @@
         old_umask = os.umask(0o077)
         try:
             conn = sqlite3.connect(path)
    ```
  * **Residual Risk**: None. Concurrently created SQLite temporary files are created with mode 0600.

* **Finding F-31**:
  * **Domain**: E
  * **Severity**: P2
  * **File**: web/_worker.js (lines 220:230)
  * **Evidence Quote**: "\"https://winsvpn.pages.dev\","
  * **Exact Proposed Fix**:
    Remove preview domains from payment CORS origins:
    ```diff
    --- a/web/_worker.js
    +++ b/web/_worker.js
    @@ -222,2 +222,0 @@
    -  "https://winsvpn.pages.dev",
    ```
  * **Residual Risk**: Staging builds on Pages preview URLs must use sandbox backend routes.

* **Finding F-32**:
  * **Domain**: E
  * **Severity**: P2
  * **File**: tools/verify_live_deployment.py (lines 80:95)
  * **Evidence Quote**: "if line.lower().startswith(prefix): return line[len(prefix):].strip()"
  * **Exact Proposed Fix**:
    Parse HTTP response headers scoped to root path rules:
    ```diff
    --- a/tools/verify_live_deployment.py
    +++ b/tools/verify_live_deployment.py
    @@ -82,3 +82,3 @@
    -    for raw in HEADERS_FILE.read_text(encoding="utf-8").splitlines():
    +    for raw in get_root_header_block().splitlines():
             line = raw.strip()
    ```
  * **Residual Risk**: None. Verifier logic accurately matches root rule headers.

* **Finding F-33**:
  * **Domain**: C
  * **Severity**: P2
  * **File**: winn3-nodes/deploy_and_verify.sh (lines 140:150)
  * **Evidence Quote**: "net.core.default_qdisc = fq"
  * **Exact Proposed Fix**:
    Set queuing discipline per interface rather than altering the global host default:
    ```diff
    --- a/winn3-nodes/deploy_and_verify.sh
    +++ b/winn3-nodes/deploy_and_verify.sh
    @@ -142,2 +142,2 @@
    -net.core.default_qdisc = fq
    +tc qdisc replace dev "$iface" root fq
    ```
  * **Residual Risk**: Interface queuing rules must be reapplied if network interfaces are reinitialized.

* **Finding F-34**:
  * **Domain**: G
  * **Severity**: P2
  * **File**: extension/manifest/base.jsonc (line 3)
  * **Evidence Quote**: "\"version\": \"1.0.0\""
  * **Exact Proposed Fix**:
    Synchronize extension release versioning with client application releases:
    ```diff
    --- a/extension/manifest/base.jsonc
    +++ b/extension/manifest/base.jsonc
    @@ -3,1 +3,1 @@
    -  "version": "1.0.0",
    +  "version": "1.0.16",
    ```
  * **Residual Risk**: Browser extension stores require version increment on every published update.

* **Finding F-35**:
  * **Domain**: F
  * **Severity**: P2
  * **File**: server/spain_crypto_payments_setup.sh (line 75)
  * **Evidence Quote**: "--daemon-address nodes.hashvault.pro:18081"
  * **Exact Proposed Fix**:
    Connect Monero wallet daemon to an internal private daemon node:
    ```diff
    --- a/server/spain_crypto_payments_setup.sh
    +++ b/server/spain_crypto_payments_setup.sh
    @@ -75,1 +75,1 @@
    -    --daemon-address nodes.hashvault.pro:18081 \\
    +    --daemon-address 10.0.0.5:18081 \\
    ```
  * **Residual Risk**: Node operator must maintain a synced private Monero full node.

* **Finding F-36**:
  * **Domain**: H
  * **Severity**: P2
  * **File**: android/app/build.gradle.kts (line 208) and apple/
  * **Evidence Quote**: "WINS_WINN3_ENABLED_PLATFORMS=android"
  * **Exact Proposed Fix**:
    Implement PacketTunnel camouflage parity and engine bindings for Apple platforms:
    ```bash
    # Inventory action: schedule Apple PacketTunnelEngine review and disguise parity in Round 37
    ```
  * **Residual Risk**: iOS and macOS clients currently lack dynamic camouflage capabilities.
