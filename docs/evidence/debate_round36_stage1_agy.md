# Round 36 stage1: agy

ROUND 36 SURFACE-WIDE AUDIT INDEPENDENT VERDICT (SEAT 1: ANTIGRAVITY)

FINDINGS SUMMARY:
Total findings: 19 (P0: 9, P1: 8, P2: 2).
Domains audited: A, B, C, D, E, F, G, H.

FINDINGS LIST (ORDERED BY SEVERITY):

1. **Finding F-1**:
   * **Domain**: E
   * **Severity**: P0
   * **File**: web/_headers (lines 14:16)
   * **Evidence Quote**: "img-src 'self' data: https: https://www.facebook.com https://www.google-analytics.com https://www.google.com https://www.googleadservices.com; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.googletagmanager.com https://connect.facebook.net https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://stats.g.doubleclick.net https://www.facebook.com"
   * **Exact Proposed Fix**:
     Remove all third-party tracker origins from web/_headers Content-Security-Policy:
     ```diff
     --- a/web/_headers
     +++ b/web/_headers
     @@ -14,3 +14,3 @@
     -  Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https: https://www.facebook.com https://www.google-analytics.com https://www.google.com https://www.googleadservices.com; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.googletagmanager.com https://connect.facebook.net https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://stats.g.doubleclick.net https://www.facebook.com https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://applepay.cdn-apple.com https://pay.google.com; frame-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://pay.google.com; form-action 'self' https://www.paypal.com https://www.paypalobjects.com; upgrade-insecure-requests
     +  Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'sha256-2V/uKUJz8223z18xxus9qw+2g/dasZB0Z9QQp4T3N9A='; script-src 'self' 'sha256-J6XgruItyyE36aTCOdP2t9Viil4Hi80tSPxwzH1ZRy8=' 'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4=' https://www.paypal.com https://www.paypalobjects.com; connect-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://applepay.cdn-apple.com https://pay.google.com; frame-src 'self' https://www.paypal.com https://www.paypalobjects.com https://www.sandbox.paypal.com https://pay.google.com; form-action 'self' https://www.paypal.com https://www.paypalobjects.com; upgrade-insecure-requests
     ```
   * **Residual Risk**: Any legacy marketing conversion analytics dependent on Facebook Pixel or Google Analytics will cease collecting data. For high-threat privacy users in Myanmar, stopping third-party data transmission removes user enumeration risk.

2. **Finding F-2**:
   * **Domain**: F
   * **Severity**: P0
   * **File**: server/spain_crypto_payments_setup.sh (lines 140:155)
   * **Evidence Quote**: "location /monero-rpc {\n        proxy_pass http://127.0.0.1:18083/json_rpc;\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto https;\n        proxy_pass_header Authorization;\n        proxy_pass_header WWW-Authenticate;\n        proxy_read_timeout 60s;\n        proxy_send_timeout 60s;\n    }"
   * **Exact Proposed Fix**:
     Restrict the Nginx location block to internal Kansas Hub traffic or localhost only:
     ```diff
     --- a/server/spain_crypto_payments_setup.sh
     +++ b/server/spain_crypto_payments_setup.sh
     @@ -140,2 +140,4 @@
          location /monero-rpc {
     +        allow 127.0.0.1;
     +        deny all;
              proxy_pass http://127.0.0.1:18083/json_rpc;
     ```
     For access from Kansas Hub, route communication over the private WireGuard management tunnel instead of the public Cloudflare Tunnel URL.
   * **Residual Risk**: Kansas Hub must reach the Spain Monero RPC endpoint over the internal management IP rather than btcpay.winsvpn.org/monero-rpc.

3. **Finding F-3**:
   * **Domain**: A
   * **Severity**: P0
   * **File**: android/app/src/main/AndroidManifest.xml (lines 55:57)
   * **Evidence Quote**: "<uses-permission\n        android:name=\"android.permission.QUERY_ALL_PACKAGES\"\n        tools:ignore=\"QueryAllPackagesPermission\" />"
   * **Exact Proposed Fix**:
     Remove the high-risk broad permission from the manifest:
     ```diff
     --- a/android/app/src/main/AndroidManifest.xml
     +++ b/android/app/src/main/AndroidManifest.xml
     @@ -55,3 +55,0 @@
     -    <uses-permission
     -        android:name="android.permission.QUERY_ALL_PACKAGES"
     -        tools:ignore="QueryAllPackagesPermission" />
     ```
   * **Residual Risk**: Split tunneling package pickers must query installed applications using documented intent queries or system app pickers compliant with Google Play policy (UNVERIFIED-LIVE).

4. **Finding F-4**:
   * **Domain**: A
   * **Severity**: P0
   * **File**: android/app/src/main/AndroidManifest.xml (lines 188:193)
   * **Evidence Quote**: "<receiver android:name=\".SecretCodeReceiver\" android:exported=\"true\">\n            <intent-filter>\n                <action android:name=\"android.intent.action.MAIN\" />\n                <action android:name=\"android.provider.Telephony.SECRET_CODE\" />\n                <data android:scheme=\"android_secret_code\" android:host=\"9467\" />\n            </intent-filter>\n        </receiver>"
   * **Exact Proposed Fix**:
     Drop the exported Telephony secret code intent filter from AndroidManifest.xml:
     ```diff
     --- a/android/app/src/main/AndroidManifest.xml
     +++ b/android/app/src/main/AndroidManifest.xml
     @@ -188,6 +188,2 @@
     -        <receiver android:name=".SecretCodeReceiver" android:exported="true">
     -            <intent-filter>
     -                <action android:name="android.provider.Telephony.SECRET_CODE" />
     -                <data android:scheme="android_secret_code" android:host="9467" />
     -            </intent-filter>
     -        </receiver>
     ```
     Keep secret code entry strictly within the calculator UI digit sequence logic, eliminating external telephony dialer broadcast fingerprints.
   * **Residual Risk**: Users who previously launched the app by dialing *#*#9467#*#* in the phone dialer must enter their passcode directly into the calculator display.

5. **Finding F-5**:
   * **Domain**: C
   * **Severity**: P0
   * **File**: server/wins_winn3_gateway_install.sh (lines 283:294)
   * **Evidence Quote**: "Off by default. On the fleet's only node the host INPUT policy is ACCEPT and no WINVPN-INPUT chain exists, so no host rule is needed and adding one would be a change to a live node's firewall for no benefit. Set to 1 only on a node that genuinely default-drops INPUT.\nWINN3_GATEWAY_MANAGE_FIREWALL=\"${WINN3_GATEWAY_MANAGE_FIREWALL:-0}\""
   * **Exact Proposed Fix**:
     Enforce host firewall management and default drop posture on gateway hosts:
     ```diff
     --- a/server/wins_winn3_gateway_install.sh
     +++ b/server/wins_winn3_gateway_install.sh
     @@ -293,1 +293,1 @@
     -WINN3_GATEWAY_MANAGE_FIREWALL="${WINN3_GATEWAY_MANAGE_FIREWALL:-0}"
     +WINN3_GATEWAY_MANAGE_FIREWALL="${WINN3_GATEWAY_MANAGE_FIREWALL:-1}"
     ```
     Ensure INPUT chain establishes default drop with explicit ACCEPT rules for SSH (port 22/2222), Winn v3 (UDP 9111), AmneziaWG (UDP 9110), and established connections.
   * **Residual Risk**: Misconfigured firewall rules could lock out administration if SSH port is not explicitly allowlisted before applying drop policy.

6. **Finding F-6**:
   * **Domain**: D
   * **Severity**: P0
   * **File**: router/security.py (lines 231:235)
   * **Evidence Quote**: "def decision_log_path() -> Path:\n    return _absolute_file_path(\n        os.environ.get(\"DECISIONS_FILE\", \"/tmp/router_decisions.jsonl\"),\n        \"DECISIONS_FILE\",\n    )"
   * **Exact Proposed Fix**:
     Relocate default decision log path from /tmp to an authenticated, access-controlled directory:
     ```diff
     --- a/router/security.py
     +++ b/router/security.py
     @@ -233,1 +233,1 @@
     -        os.environ.get("DECISIONS_FILE", "/tmp/router_decisions.jsonl"),
     +        os.environ.get("DECISIONS_FILE", "/var/log/winsvpn/router_decisions.jsonl"),
     ```
   * **Residual Risk**: /var/log/winsvpn must exist and be owned by the smart router process user before service initialization.

7. **Finding F-7**:
   * **Domain**: F
   * **Severity**: P0
   * **File**: server/hub-commerce.env.example (lines 30:37)
   * **Evidence Quote**: "# Optional. If ANY of the four is set, all four must be set, and BTCPAY_URL\n# must be https://. Leave all empty to leave runtime BTCPay unchanged.\nBTCPAY_URL=\nBTCPAY_STORE_ID=\nBTCPAY_API_KEY=\nBTCPAY_WEBHOOK_SECRET="
   * **Exact Proposed Fix**:
     Add the missing Monero commerce configuration placeholders to the template:
     ```diff
     --- a/server/hub-commerce.env.example
     +++ b/server/hub-commerce.env.example
     @@ -36,2 +36,7 @@
      BTCPAY_WEBHOOK_SECRET=
     +
     +# Monero Wallet RPC Configuration
     +MONERO_WALLET_RPC_URL=
     +MONERO_WALLET_RPC_USER=
     +MONERO_WALLET_RPC_PASS=
     ```
   * **Residual Risk**: Kansas Hub setup script must be updated to parse and pass these variables into /root/vpn_auth.env.

8. **Finding F-8**:
   * **Domain**: E
   * **Severity**: P0
   * **File**: web/wrangler.jsonc (lines 1:12) and web/_worker.js (lines 270:280)
   * **Evidence Quote**: "NOT USED BY THE CURRENT LIVE DEPLOYMENT. Read this whole comment block before touching this file or wiring it into anything.\nwinsvpn.org / winsvpn.com are served today by the Cloudflare Pages Direct Upload project named winsvpn. The project has no Git provider... Cloudflare Rate Limiting bindings (the ratelimits block below) are a Workers-only feature"
   * **Exact Proposed Fix**:
     Configure zone-level Cloudflare WAF Rate Limiting rules directly on winsvpn.org for /api/site/wallet/*, /api/site/crypto/*, /api/site/translate, and /api/site/ai-chat paths:
     ```bash
     # Cloudflare API or dashboard rule: Rate limit /api/site/* endpoints to 20 requests per minute per connecting IP
     ```
   * **Residual Risk**: Legitimate client IP clustering behind large carrier-grade NAT gateways in high-traffic regions could trigger rate limits during burst usage.

9. **Finding F-9**:
   * **Domain**: C
   * **Severity**: P0
   * **File**: server/wins_data_plane_setup_ONETOUCH.sh (lines 14:35)
   * **Evidence Quote**: "wins_early_swap_source_is_protected() {\n  local swap_src=\"${1:-}\" swap_real backing_src backing_real fs_type\n  case \"${swap_src}\" in\n    /dev/zram*|/dev/ram*) return 0 ;;\n  esac\n  swap_real=\"$(readlink -f \"${swap_src}\" 2>/dev/null || printf '%s' \"${swap_src}\")\"\n  if [[ ! -b \"${swap_real}\" ]]; then\n    fs_type=\"$(findmnt -no FSTYPE -T \"${swap_real}\" 2>/dev/null || true)\"\n    [[ \"${fs_type}\" =~ ^(tmpfs|ramfs)$ ]] && return 0\n    backing_src=\"$(findmnt -no SOURCE -T \"${swap_real}\" 2>/dev/null || true)\"\n    [[ -n \"${backing_src}\" ]] || return 1\n    backing_real=\"$(readlink -f \"${backing_src}\" 2>/dev/null || printf '%s' \"${backing_src}\")\"\n  else\n    backing_real=\"${swap_real}\"\n  fi\n  lsblk -spno TYPE \"${backing_real}\" 2>/dev/null | grep -x crypt >/dev/null\n}"
   * **Exact Proposed Fix**:
     Make the swap guard fail closed if any unprotected swap cannot be disabled:
     ```diff
     --- a/server/wins_data_plane_setup_ONETOUCH.sh
     +++ b/server/wins_data_plane_setup_ONETOUCH.sh
     @@ -42,3 +42,4 @@
          swapoff "${swap_dev}" || {
     -        echo "[WARN] Could not disable swap device ${swap_dev}" >&2
     +        echo "[ERR] Could not disable unprotected swap device ${swap_dev}. Aborting to protect credentials." >&2
     +        exit 1
          }
     ```
   * **Residual Risk**: Installation halts if the host has insufficient RAM to deactivate swap before encryption setup.

10. **Finding F-10**:
    * **Domain**: B
    * **Severity**: P1
    * **File**: server/wins_winn3_gateway_install.sh (lines 25:33, 312)
    * **Evidence Quote**: "WINN3_GATEWAY_FORWARD=0 (the default, and everything true of this script before 2026-08-12): an IN-PROCESS REFLECTOR. It forwards nothing to the internet, it swaps the addresses of what it is given and hands it back."
    * **Exact Proposed Fix**:
      Require an explicit mode configuration flag during installation:
      ```diff
      --- a/server/wins_winn3_gateway_install.sh
      +++ b/server/wins_winn3_gateway_install.sh
      @@ -312,1 +312,1 @@
      -WINN3_GATEWAY_FORWARD="${WINN3_GATEWAY_FORWARD:-0}"
      +WINN3_GATEWAY_FORWARD="${WINN3_GATEWAY_FORWARD:-1}"
      ```
    * **Residual Risk**: Setting forward mode requires CAP_NET_ADMIN and /dev/net/tun device node access.

11. **Finding F-11**:
    * **Domain**: B
    * **Severity**: P1
    * **File**: server/wins_winn3_gateway_install.sh (lines 218:235) vs android/app/build.gradle.kts (line 210)
    * **Evidence Quote**: "Android's [winn] parser accepts the dual-signature attestation keys and the native host can verify them, so the release build flips this define for BOTH release and debug targets... base64(\"WINS_WINN3_DUAL_AUTH=true\")"
    * **Exact Proposed Fix**:
      Assert dual-auth key presence when installing or verifying production nodes in deploy_and_verify.sh:
      ```diff
      --- a/winn3-nodes/deploy_and_verify.sh
      +++ b/winn3-nodes/deploy_and_verify.sh
      @@ -95,2 +95,5 @@
         [[ -f "$CRED_DIR/winn3-gateway-static.key" ]] || die "static key missing"
      +  if [[ "${WINN3_GATEWAY_DUAL_AUTH:-1}" == "1" ]]; then
      +    [[ -f "$CRED_DIR/winn3-gateway-dual-auth-ed.key" ]] || die "dual-auth ed key missing"
      +  fi
      ```
    * **Residual Risk**: Gateways without generated post-quantum dual-auth seeds cannot complete client handshakes when dual-auth is enforced.

12. **Finding F-12**:
    * **Domain**: G
    * **Severity**: P1
    * **File**: extension/src/core/pac.js (lines 43:48)
    * **Evidence Quote**: "function wvMatch(rule, host) {\n  if (host === rule) { return true; }\n  return host.length > rule.length &&\n         host.substring(host.length-rule.length-1) === (\".\" + rule);\n}"
    * **Exact Proposed Fix**:
      Use negative slice indexing to prevent negative index evaluation:
      ```diff
      --- a/extension/src/core/pac.js
      +++ b/extension/src/core/pac.js
      @@ -44,3 +44,3 @@
         if (host === rule) { return true; }
      -  return host.length > rule.length &&
      -         host.substring(host.length-rule.length-1) === ("." + rule);
      +  return host.length > rule.length &&
      +         host.slice(-(rule.length + 1)) === ("." + rule);
      ```
    * **Residual Risk**: None; slice handles boundary lengths consistently across JavaScript runtimes.

13. **Finding F-13**:
    * **Domain**: G
    * **Severity**: P1
    * **File**: extension/src/core/endpoint.js (lines 91:97)
    * **Evidence Quote**: "export function pacToken(endpoint) {\n  const bare = endpoint.host.startsWith('[') && endpoint.host.endsWith(']')\n    ? endpoint.host.slice(1, -1)\n    : endpoint.host;\n  const host = bare.includes(':') ? `[${bare}]` : bare;\n  return `PROXY ${host}:${endpoint.port}`;\n}"
    * **Exact Proposed Fix**:
      Emit bare unbracketed IPv6 host string for PAC tokens conforming to Netscape PAC specification (UNVERIFIED-LIVE):
      ```diff
      --- a/extension/src/core/endpoint.js
      +++ b/extension/src/core/endpoint.js
      @@ -95,2 +95,2 @@
      -  const host = bare.includes(':') ? `[${bare}]` : bare;
      -  return `PROXY ${host}:${endpoint.port}`;
      +  return `PROXY ${bare}:${endpoint.port}`;
      ```
    * **Residual Risk**: Web browsers expecting bracketed IPv6 in URI formats must be tested against standard PAC parser implementations.

14. **Finding F-14**:
    * **Domain**: D
    * **Severity**: P1
    * **File**: router/main.py (lines 108, 128:130)
    * **Evidence Quote**: "_STORAGE_SLOTS = threading.BoundedSemaphore(_STORAGE_MAX_WORKERS)\n...\nif not _STORAGE_SLOTS.acquire(blocking=False):\n    raise TimeoutError(\"storage worker capacity exhausted\")"
    * **Exact Proposed Fix**:
      Allow bounded blocking acquisition up to remaining request deadline:
      ```diff
      --- a/router/main.py
      +++ b/router/main.py
      @@ -128,2 +128,3 @@
      -    if not _STORAGE_SLOTS.acquire(blocking=False):
      -        raise TimeoutError("storage worker capacity exhausted")
      +    acquire_timeout = min(max(0.0, remaining), 0.25)
      +    if not _STORAGE_SLOTS.acquire(blocking=True, timeout=acquire_timeout):
      +        raise TimeoutError("storage worker capacity exhausted")
      ```
    * **Residual Risk**: Storage operations taking longer than 250ms under heavy contention will still timeout gracefully.

15. **Finding F-15**:
    * **Domain**: C
    * **Severity**: P1
    * **File**: server/wins_winn3_gateway_install.sh (lines 66:72)
    * **Evidence Quote**: "the installer deployed on the fleet's only data plane matches NO commit in this repository. The on-host copy is 275,860 bytes; the committed one is 367,410. Re-running the committed installer against that node would not \"update\" it, it would replace a divergent, hand-staged deployment wholesale"
    * **Exact Proposed Fix**:
      Capture on-host script diff, merge changes, and commit unified installer:
      ```bash
      diff -u server/wins_data_plane_setup_ONETOUCH.sh remote_data_plane_copy.sh > /tmp/data_plane_diff.patch
      ```
    * **Residual Risk**: Manual verification required to ensure no machine-specific hardcoded values are committed to git.

16. **Finding F-16**:
    * **Domain**: E
    * **Severity**: P1
    * **File**: web/_worker.js (lines 234:241)
    * **Evidence Quote**: "function publicConfigCacheKey(name, request) {\n  const origin = request.headers.get(\"origin\") || \"\";\n  const variant = allowedOrigins.has(origin) ? origin : \"no-origin\";\n  return new Request(\n    `https://internal-cache.winsvpn.invalid/${name}/${encodeURIComponent(variant)}`,\n    { method: \"GET\" }\n  );\n}"
    * **Exact Proposed Fix**:
      Ensure Cache-Control headers on cached public config responses always declare Vary: Origin:
      ```diff
      --- a/web/_worker.js
      +++ b/web/_worker.js
      @@ -219,2 +219,3 @@
           headers["access-control-allow-origin"] = origin;
         }
      +  headers["vary"] = "Origin";
         return headers;
      ```
    * **Residual Risk**: None; intermediate caches will partition entries correctly.

17. **Finding F-17**:
    * **Domain**: A
    * **Severity**: P1
    * **File**: android/app/src/main/AndroidManifest.xml (lines 166:177)
    * **Evidence Quote**: "<service\n        android:name=\".VpnTunnelService\"\n        android:permission=\"android.permission.BIND_VPN_SERVICE\"\n        android:foregroundServiceType=\"specialUse\"\n        android:stopWithTask=\"false\"\n        android:exported=\"false\">"
    * **Exact Proposed Fix**:
      Add standard foregroundServiceType systemExempted alongside specialUse if approved by Play Console (UNVERIFIED-LIVE):
      ```diff
      --- a/android/app/src/main/AndroidManifest.xml
      +++ b/android/app/src/main/AndroidManifest.xml
      @@ -169,3 +169,3 @@
               android:permission="android.permission.BIND_VPN_SERVICE"
      -        android:foregroundServiceType="specialUse"
      +        android:foregroundServiceType="specialUse|systemExempted"
               android:stopWithTask="false"
      ```
    * **Residual Risk**: Play Console submission must include completed declaration video demonstrating active tunnel notification.

18. **Finding F-18**:
    * **Domain**: F
    * **Severity**: P2
    * **File**: server/spain_crypto_payments_setup.sh (line 75)
    * **Evidence Quote**: "--daemon-address nodes.hashvault.pro:18081 \\\n    --untrusted-daemon \\"
    * **Exact Proposed Fix**:
      Run a dedicated local pruned monerod daemon or self-hosted backend node:
      ```diff
      --- a/server/spain_crypto_payments_setup.sh
      +++ b/server/spain_crypto_payments_setup.sh
      @@ -75,2 +75,2 @@
      -    --daemon-address nodes.hashvault.pro:18081 \
      -    --untrusted-daemon \
      +    --daemon-address 127.0.0.1:18081 \
      +    --trusted-daemon \
      ```
    * **Residual Risk**: Running a local pruned node requires additional disk storage (approx 60 GB) and memory on the payment server.

19. **Finding F-19**:
    * **Domain**: H
    * **Severity**: P2
    * **File**: android/app/build.gradle.kts (line 208, decoded defines)
    * **Evidence Quote**: "WINS_WINN3_ENABLED_PLATFORMS=android"
    * **Exact Proposed Fix**:
      Update release defines to include Apple platforms once iOS/macOS PacketTunnel provider integration tests pass:
      ```diff
      --- a/android/app/build.gradle.kts
      +++ b/android/app/build.gradle.kts
      @@ -208,1 +208,1 @@
      -        "V0lOU19XSU5OM19FTkFCTEVEX1BMQVRGT1JNUz1hbmRyb2lk",
      +        "V0lOU19XSU5OM19FTkFCTEVEX1BMQVRGT1JNUz1hbmRyb2lkLGlvcyxtYWNvcw==",
      ```
    * **Residual Risk**: Darwin PacketTunnel engine must be compiled and signed with Apple Developer entitlements before activation.

NEXT-DEEP-DIVE:
1. winn_protocol_experimental/winn3/core/replay.go: Verify disk format and memory limits of persisted handshake replay journal.
2. winn_protocol_experimental/winn3/driver/: Inspect responder connection handling and peer demultiplexing loops.
3. server/wins_data_plane_setup_ONETOUCH.sh: Inspect full un-capped iptables NAT rules and Suricata configuration.
4. web/_worker.js: Review remaining payment proxy handlers and order validation routines in full.
5. android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt: Audit Kotlin native engine lifecycle and kill-switch socket bindings.
6. router/security.py: Review complete SQLite nonce journal schema migrations and rollback handlers.
