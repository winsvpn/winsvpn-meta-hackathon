# Round 36 stage2: solpro

Release verdict

BLOCK release and production deployment. The revised list contains 28 findings: 4 P0, 22 P1, and 2 P2. Arithmetic: 4 + 22 + 2 = 28.

Packet integrity note

The reproduced Turn 1 verdict says it contains 15 findings, but the supplied text exposes headings F-1 through F-12 only and cuts F-12 off after `iptables -S FORWARD 2`. Therefore, 15 - 12 = 3 original findings are unavailable. I cannot audit or reproduce those three without inventing evidence.

Steelman of Seat 1

Seat 1 consistently prioritized observable user exposure over internal correctness. Its reasoning is strongest where a quoted deployment fact directly defeats a claimed protection, such as a public `/monero-rpc` proxy, unprotected swap that may remain enabled, or a production installer that matches no repository commit.

Its single strongest point is the production installer divergence:

`the installer deployed on the fleet's only data plane matches NO commit in this repository. The on-host copy is 275,860 bytes; the committed one is 367,410.`

The exact size difference is 367,410 - 275,860 = 91,550 bytes. That evidence changes my Turn 1 list because it proves the reviewed repository cannot identify the code that provisioned the only live data plane.

Steelman of Seat 2

Seat 2 usually separated primary evidence from live-policy assumptions and marked unsupported external details as `UNVERIFIED-LIVE`. Its strongest findings connect two quoted code paths and show a verdict inversion, release-gate bypass, or custody failure.

Its single strongest point is the production-signed QA bypass:

`signingConfig = ... signingConfigs.getByName("release")`

combined with a task gate that recognizes only release task names. A production key applied to a build type outside the production checks defeats the checks by construction. I therefore add that finding.

Disposition of Seat 1 findings

1. S1 F-1: ACCEPT at P1, not P0. The CSP quote proves authorization of Google, Meta, and arbitrary HTTPS images. It does not alone prove every visitor transmits data.
2. S1 F-2: ACCEPT and revise. The public proxy is evidenced. The localhost-only fix would break Kansas access, so the revised fix uses a private management-tunnel listener.
3. S1 F-3: NO CHANGE. This was my F-7. I retain P1 because the packet proves excessive permission scope but supplies no current Play-policy evidence.
4. S1 F-4: PARTIAL ACCEPT. The exported secret-code declaration and product-derived `9467` fingerprint are evidenced. Receiver behavior is absent, so I do not claim that an external intent changes tunnel state.
5. S1 F-5: REFUTE. `INPUT` policy `ACCEPT` is quoted, but no packet evidence shows an unintended listening service. Changing the default to firewall management also risks lockout, which Seat 1 acknowledges.
6. S1 F-6: ACCEPT. `/tmp` conflicts with the quoted required parent mode `0700`.
7. S1 F-7: REFUTE. Empty template variables do not prove runtime Monero configuration is missing, and the proposed template-only edit does not wire the variables into runtime configuration.
8. S1 F-8: NO CHANGE. My F-3 and F-4 already fail paid upstream routes closed when Pages lacks distributed bindings.
9. S1 F-9: ACCEPT. The quoted `swapoff` failure emits only a warning, so unprotected swap can remain active.
10. S1 F-10: REFUTE. The quoted comment expressly defines reflector mode as the default. An intentional documented mode is not made defective by existing.
11. S1 F-11: REFUTE. The packet does not prove the proposed dual-auth filename or that every deployed gateway must possess that key.
12. S1 F-12: REFUTE. With the existing `host.length > rule.length` guard, `substring(host.length-rule.length-1)` and `slice(-(rule.length+1))` select the same suffix.
13. S1 F-13: REFUTE. The proposed unbracketed IPv6 PAC syntax is marked `UNVERIFIED-LIVE` and conflicts with the existing unambiguous bracketed host representation.
14. S1 F-14: REFUTE. The nonblocking semaphore is directly evidenced, but no requirement says requests must wait 250 ms rather than fail when capacity is exhausted.
15. S1 F-15: ACCEPT. The 91,550-byte production divergence is direct evidence.
16. S1 F-16: ACCEPT. An origin-dependent response without `Vary: Origin` can be reused by an intermediary that does not know the Worker's internal cache key.
17. S1 F-17: REFUTE. `systemExempted` eligibility is marked `UNVERIFIED-LIVE`, so adding it is not justified by packet evidence.
18. S1 F-18: REFUTE. The service already declares `--untrusted-daemon`, which is explicit treatment of the remote daemon as untrusted. The packet proves no resulting confidentiality or integrity failure.
19. S1 F-19: REFUTE. The define says only Android is enabled. Enabling untested Apple platforms would convert a disabled surface into an unsupported one.

Disposition of Seat 2 findings

1. S2 F-1: ACCEPT at P1. The authorized tracker origins are direct evidence; universal transmission is not.
2. S2 F-2: PARTIAL ACCEPT. The manifest exposes `org.winsvpn.app`, `Win's VPN`, and a real launcher enabled by default. The claim that `QUERY_ALL_PACKAGES` proves another app can enumerate this app does not follow from that permission.
3. S2 F-3: NO CHANGE. This was my F-2.
4. S2 F-4: PARTIAL ACCEPT. The public proxy is evidenced. The interpretation of Monero's presence-style flags is marked `UNVERIFIED-LIVE`, so I do not use it as proof.
5. S2 F-5: NO CHANGE. This was my F-1.
6. S2 F-6: ACCEPT. The rule list is emitted without the lowercase and trailing-dot normalization applied to the host.
7. S2 F-7: ACCEPT. The exact divergence is 91,550 bytes.
8. S2 F-8: ACCEPT and merge into my Android engine-gate finding. Non-empty files and modified blobs do not provide provenance.
9. S2 F-9: PARTIAL ACCEPT and merge with the camouflage finding. The exported declaration and `9467` string are proven; receiver side effects are not.
10. S2 F-10: REFUTE. The manifest proves an exported service but the absent Kotlin body prevents proof that a forged start changes tunnel state.
11. S2 F-11: ACCEPT. The QA build uses the release signing configuration while the quoted gate recognizes release task names.
12. S2 F-12: ACCEPT as a provisioning finding. The control-plane script states that validation accepts TLS while the dialer refuses it.
13. S2 F-13: NO CHANGE. This was part of my F-5.
14. S2 F-14: NO CHANGE. This was part of my F-5.
15. S2 F-15: ACCEPT. Installed copies are made, but the staged secret files have no quoted deletion path.
16. S2 F-16: ACCEPT. `/tmp` mode 1777 conflicts with the module's quoted `0700` requirement.
17. S2 F-17: REFUTE. The packet identifies seven protected paths but does not prove that any current sensitive route lies outside the set. The future-route argument is prospective.
18. S2 F-18: REFUTE. A release pin intentionally refusing an unapproved manifest is a publication control. The packet does not prove a release process that omits synchronized updates.
19. S2 F-19: ACCEPT and merge with the public Monero proxy finding.
20. S2 F-20: REFUTE. Strict digest-URI behavior for the pinned Monero build is marked `UNVERIFIED-LIVE`.
21. S2 F-21: REFUTE. The archive mapping for `docker` is marked `UNVERIFIED-LIVE`, and the packet does not identify the target distribution release.
22. S2 F-22: REFUTE. Android camouflage is evidenced as opt-in. No packet requirement says the separately installed browser extension must conceal its product identity.
23. S2 F-23: ACCEPT. The manifest says `no-logs`, while the Worker explicitly lists retained account, payment, device, referral, security, and legal metadata.
24. S2 F-24: ACCEPT with corrected arithmetic. Rounds 2 through 20 inclusive total 20 - 2 + 1 = 19 per series. Two series therefore contain 19 x 2 = 38 deleted receipt files, not 40.
25. S2 F-25: REFUTE. Seat 2 states that the Apple source bodies are absent. Absence from an inventory packet does not prove absence from the product.
26. S2 F-26: REFUTE as a product finding. Seat 2 identifies the lines as probable redaction corruption and labels the issue verify-first.
27. S2 F-27: ACCEPT at P2. Insertion-order eviction can delete a still-active bucket.
28. S2 F-28: REFUTE. Every accepted address remains within numeric loopback, so the packet proves a documentation mismatch but no traffic escape.
29. S2 F-29: REFUTE. The packet says Pages Direct Upload is the current deployment. It does not prove that the project's `pages.dev` origin is hostile or uncontrolled.
30. S2 F-30: ACCEPT. A binary and its checksum copied together share one custody path.
31. S2 F-31: ACCEPT. The installer documents the live inode-replacement hazard but enforces no stop requirement.
32. S2 F-32: REFUTE. `BEGIN IMMEDIATE` and a busy timeout do not prove SQLite WAL mode is enabled, so creation of `-wal` and `-shm` files is not established.
33. S2 F-33: ACCEPT at P2. Both parser weaknesses follow directly from the quoted loops and regular expressions.
34. S2 F-34: ACCEPT. `net.core.default_qdisc` is node-wide, while the deployment intends to affect only the new gateway.
35. S2 F-35: REFUTE. Independent extension and application version numbers do not prove an operational failure.
36. S2 F-36: REFUTE. The response reveals that a queried term is filtered, but the packet does not establish that membership in this literal keyword list is confidential infrastructure information.

Changes to my visible Turn 1 findings

1. Original F-1: retained unchanged in substance.
2. Original F-2: retained unchanged in substance.
3. Original F-3 and F-4: merged because both require the same distributed fail-closed control.
4. Original F-5: retained unchanged in substance.
5. Original F-6: expanded to require digests for the selected native objects.
6. Original F-7: retained at P1.
7. Original F-8 and F-9: merged because both source privileged shell environment files.
8. Original F-10: retained unchanged in substance.
9. Original F-11: retained unchanged in substance.
10. Original F-12: retained and its truncated fix is completed below.
11. Original F-13 through F-15: unavailable in the reproduced packet, since 15 declared findings minus 12 visible findings equals 3 omitted findings.

Revised final findings

F-1

**Domain:** F

**Severity:** P0

**Exact file:** `server/spain_crypto_payments_setup.sh`, `setup_btcpay_server`

**Evidence quote:** `git clone https://github.com/btcpayserver/btcpayserver-docker.git` followed by `. ./btcpay-setup.sh -i`

**Exact fix:** Remove cloning and fetching from the privileged installer. Require a clean pre-staged checkout at a reviewed 40-character commit:

```bash
: "${BTCPAY_REVIEWED_COMMIT:?set reviewed BTCPay commit}"
[[ "${BTCPAY_REVIEWED_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || exit 1
[[ -d "${BTCPAY_DOCKER_DIR}/.git" ]] || exit 1

actual_commit="$(git -C "${BTCPAY_DOCKER_DIR}" rev-parse HEAD)"
[[ "${actual_commit}" == "${BTCPAY_REVIEWED_COMMIT}" ]] || exit 1
git -C "${BTCPAY_DOCKER_DIR}" diff --quiet || exit 1
git -C "${BTCPAY_DOCKER_DIR}" diff --cached --quiet || exit 1
```

The operator must stage the reviewed tree before running the installer:

```bash
git clone --no-checkout https://github.com/btcpayserver/btcpayserver-docker.git /opt/btcpayserver-docker
git -C /opt/btcpayserver-docker checkout --detach "$REVIEWED_COMMIT"
```

**Residual risk:** A fixed commit can still contain malicious code. The change supplies immutable identity, not a safety proof.

F-2

**Domain:** F

**Severity:** P0

**Exact file:** `server/spain_crypto_payments_setup.sh`, `setup_monero_service` and `print_summary`

**Evidence quote:** `--rpc-login ${rpc_user}:${rpc_pass}` and `printf 'MONERO_WALLET_RPC_PASS="%s"\n' "${rpc_pass}"`

**Exact fix:** Write the unit through a temporary file and install it at mode 0600:

```bash
unit_tmp="$(mktemp)"
trap 'rm -f "${unit_tmp}"' RETURN

cat > "${unit_tmp}" <<EOF
[Service]
User=monero-wallet
Group=monero-wallet
ExecStart=/usr/local/bin/monero-wallet-rpc \
  --wallet-dir /var/lib/monero/wallet \
  --rpc-bind-ip 127.0.0.1 \
  --rpc-bind-port 18083 \
  --restricted-rpc \
  --rpc-login ${rpc_user}:${rpc_pass}
EOF

install -o root -g root -m 0600 \
  "${unit_tmp}" /etc/systemd/system/monero-wallet-rpc.service
```

Replace the summary output with:

```bash
printf 'MONERO_WALLET_RPC_PASS="<stored in %s; not printed>"\n' "${creds_file}"
```

Rotate the current credential after deleting it from the existing unit, terminal capture, and `/var/log/winsvpn/spain_crypto_setup.log`.

**Residual risk:** The password remains in the process argument vector. The packet supplies no verified Monero descriptor-based credential option.

F-3

**Domain:** E

**Severity:** P0

**Exact file:** `web/_worker.js`, `requireQuota`, translation, AI chat, and map-tile handlers

**Evidence quote:** The packet states that Pages rejects Rate Limiting bindings, `env[bindingName]` is undefined in production, and `handleMapTile` performs upstream fetches without calling a quota function.

**Exact fix:** Add a required-binding mode to `requireQuota`:

```javascript
async function requireQuota(
  request, env, bindingName, keyPrefix,
  limit = 20, windowMs = 60_000, bindingRequired = false
) {
  const ip = connectingClientIp(request);
  if (!ip) return json({ error: "ip_unavailable" }, 503);

  const limiter = env[bindingName];
  if (!limiter || typeof limiter.limit !== "function") {
    if (bindingRequired) return json({ error: "quota_unavailable" }, 503);
    return isolateLocalRateLimited(keyPrefix, ip, limit, windowMs)
      ? json({ error: "rate_limited" }, 429)
      : null;
  }

  try {
    const outcome = await limiter.limit({ key: `${keyPrefix}:${ip}` });
    return outcome.success ? null : json({ error: "rate_limited" }, 429);
  } catch (_) {
    return bindingRequired
      ? json({ error: "quota_unavailable" }, 503)
      : json({ error: "rate_limited" }, 429);
  }
}
```

Pass `true` from translation, AI chat, and map-tile handlers before any cache lookup or upstream request.

**Residual risk:** These routes return 503 on the current Pages deployment. That is an explicit availability failure instead of unbounded paid upstream work.

F-4

**Domain:** C

**Severity:** P0

**Exact file:** `server/wins_winn3_gateway_install.sh`, production-divergence comment and deployment process

**Evidence quote:** `the installer deployed on the fleet's only data plane matches NO commit in this repository. The on-host copy is 275,860 bytes; the committed one is 367,410.`

**Exact fix:** Capture the installed artifact without executing it, record both digests, and reconcile all 91,550 differing bytes before another deployment:

```bash
scp root@DATA_PLANE:/root/wins_data_plane_setup_ONETOUCH.sh \
  server/deployed/wins_data_plane_setup_ONETOUCH.onhost.sh

sha256sum \
  server/deployed/wins_data_plane_setup_ONETOUCH.onhost.sh \
  server/wins_data_plane_setup_ONETOUCH.sh \
  > docs/evidence/data-plane-installer.sha256

diff -u \
  server/deployed/wins_data_plane_setup_ONETOUCH.onhost.sh \
  server/wins_data_plane_setup_ONETOUCH.sh \
  > docs/evidence/data-plane-installer.diff
```

Review each diff hunk, commit the reconciled source, and make deployment verify the committed installer digest before execution.

**Residual risk:** The captured on-host file may already contain unauthorized changes. Capturing it preserves evidence but does not approve it.

F-5

**Domain:** F

**Severity:** P1

**Exact file:** `server/spain_crypto_payments_setup.sh`, `setup_nginx_proxy` and generated hub configuration

**Evidence quote:** `location /monero-rpc { proxy_pass http://127.0.0.1:18083/json_rpc; ... }` and `MONERO_WALLET_RPC_URL="https://btcpay.winsvpn.org/monero-rpc"`

**Exact fix:** Delete `/monero-rpc` from the public virtual host. Add a private listener bound only to the Spain management-tunnel address:

```nginx
server {
    listen SPAIN_TUNNEL_IP:18084;
    allow HUB_TUNNEL_IP;
    deny all;

    location = /json_rpc {
        proxy_pass http://127.0.0.1:18083/json_rpc;
        proxy_pass_header Authorization;
        proxy_pass_header WWW-Authenticate;
    }
}
```

Set the hub URL to:

```bash
MONERO_WALLET_RPC_URL="http://SPAIN_TUNNEL_IP:18084/json_rpc"
```

The operator must provide `SPAIN_TUNNEL_IP` and `HUB_TUNNEL_IP` from the existing management-tunnel allocation.

**Residual risk:** The management tunnel endpoints can still observe request timing. Monero RPC authentication remains required inside the tunnel.

F-6

**Domain:** C

**Severity:** P1

**Exact file:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy` and `cmd_verify_hub`

**Evidence quote:** `local_jump_receipts` increments `FAILURES`, but `cmd_deploy` never calls `verdict`; the Python verifier computes `result` without reading `fails`.

**Exact fix:** End `cmd_deploy` with:

```bash
verdict
```

Replace the Python result with:

```python
result = "PASS" if fails == 0 else "FAIL"
print(
    f"RESULT {role}: {result} "
    f"(failures={fails} handshake={int(carrying)} "
    f"icmp-inner={int(ok_inner)} icmp-nat={int(ok_nat)})"
)
sys.exit(0 if fails == 0 else 1)
```

**Residual risk:** A passing point-in-time ICMP and TCP probe does not measure sustained packet loss or behavior after restart.

F-7

**Domain:** A

**Severity:** P1

**Exact file:** `android/app/build.gradle.kts`, `verifyAndroidReleaseEngineInputs`

**Evidence quote:** The gate accepts when any release or main candidate is a non-empty regular file, while nine native objects are listed as modified.

**Exact fix:** First select the source-set winner:

```kotlin
val selected =
    if (Files.exists(releaseCandidate.toPath(), LinkOption.NOFOLLOW_LINKS)) {
        releaseCandidate
    } else {
        mainCandidate
    }

if (!isSafeNonEmptyReleaseInput(selected)) {
    missing += "$abi/$engine from ${selected.relativeTo(projectDir)}"
}
```

Then compare its SHA-256 digest against a committed manifest:

```kotlin
val actual = MessageDigest.getInstance("SHA-256")
    .digest(selected.readBytes())
    .joinToString("") { "%02x".format(it) }

val wanted = expectedDigests["$abi/$engine"]
if (wanted != actual) {
    throw GradleException("Unreviewed engine digest for $abi/$engine: $actual")
}
```

Add a fixture where an unsafe release file shadows a valid main file.

**Residual risk:** A compromised workstation can modify both a blob and its digest manifest. Reproducible build comparison remains necessary.

F-8

**Domain:** A

**Severity:** P1

**Exact file:** `android/app/build.gradle.kts`, `buildTypes.create("qa")` and task-graph release checks

**Evidence quote:** QA uses `signingConfigs.getByName("release")`, while the gate matches release task names such as `assembleRelease` and `signRelease`.

**Exact fix:** Generate and use a separate QA key:

```bash
keytool -genkeypair \
  -keystore "$HOME/.android/winsvpn-qa.jks" \
  -alias winsvpn-qa \
  -keyalg RSA -keysize 3072 -validity 3650
```

Configure QA with `signingConfigs.getByName("qa")` and `applicationIdSuffix = ".qa"`. Independently, invoke the engine, identity, API, shrinking, and obfuscation checks for every variant whose signing configuration is `release`, rather than recognizing task names.

**Residual risk:** QA artifacts no longer update production installs. Production-signed internal testing must pass all production gates.

F-9

**Domain:** A

**Severity:** P1

**Exact file:** `android/app/src/main/AndroidManifest.xml`

**Evidence quote:** `<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" tools:ignore="QueryAllPackagesPermission" />`

**Exact fix:** Delete that permission. Add only exact `<package>` or `<intent>` declarations under `<queries>` when a concrete query is evidenced.

**Residual risk:** Code outside the packet may depend on broad enumeration. Search and device tests are required before publication.

F-10

**Domain:** A

**Severity:** P1

**Exact file:** `android/app/src/main/AndroidManifest.xml`, launcher aliases and `SecretCodeReceiver`

**Evidence quote:** `.LauncherReal` is `enabled="true"` with label `Win's VPN`; `.LauncherDecoy` is disabled; the manifest also exports `android_secret_code` host `9467`.

**Exact fix:** Use a neutral launcher label in the manifest, enable the decoy by default where camouflage is promised, and remove the external telephony trigger:

```xml
<activity-alias
    android:name=".LauncherReal"
    android:enabled="false"
    android:label="@string/neutral_launcher_label"
    ... />

<activity-alias
    android:name=".LauncherDecoy"
    android:enabled="true"
    android:label="@string/calculator_label"
    ... />
```

Delete the `SecretCodeReceiver` declaration and keep reveal behavior behind the calculator UI passcode flow.

**Residual risk:** The existing application ID `org.winsvpn.app` remains visible to local package inspection and cannot be changed while preserving the same update identity.

F-11

**Domain:** D and C

**Severity:** P1

**Exact file:** `server/wins_control_plane_setup_ONETOUCH.sh` and `server/wins_data_plane_setup_ONETOUCH.sh`, environment-file loading

**Evidence quote:** The control-plane script executes `. "${WINS_DEFAULTS_FILE}"` without trusted-file checks; the data-plane defaults and secrets loads lack equivalent regular-file and symlink checks.

**Exact fix:** Before sourcing any defaults, secrets, or node environment file, call:

```bash
wins_require_trusted_env_file() {
  local path="$1" label="$2"

  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "[ERR] ${label} must be a real regular file: ${path}" >&2
    exit 1
  }

  [[ "$(stat -c '%u' "${path}")" == "0" ]] || {
    echo "[ERR] ${label} must be root-owned: ${path}" >&2
    exit 1
  }

  [[ -z "$(find "${path}" -prune -perm /077 -print -quit)" ]] || {
    echo "[ERR] ${label} must have mode 600 or stricter: ${path}" >&2
    exit 1
  }
}
```

Apply it to `NODE_ENV_FILE`, `WINS_DEFAULTS_FILE`, and `WINS_SECRETS_FILE`.

**Residual risk:** A root-owned file still contains executable shell syntax. Root can intentionally place commands in it.

F-12

**Domain:** C

**Severity:** P1

**Exact file:** `server/wins_data_plane_setup_ONETOUCH.sh`, early swap handling

**Evidence quote:** `swapoff "${swap_dev}" || { echo "[WARN] Could not disable swap device ${swap_dev}" >&2; }`

**Exact fix:** Abort when an unprotected swap target cannot be disabled:

```bash
swapoff "${swap_dev}" || {
    echo "[ERR] Could not disable unprotected swap ${swap_dev}" >&2
    exit 1
}
```

After the loop, verify that every remaining `swapon --noheadings --raw --output NAME` entry passes `wins_early_swap_source_is_protected`.

**Residual risk:** Installation can halt on a memory-constrained host. The operator must add encrypted swap or sufficient RAM before retrying.

F-13

**Domain:** F

**Severity:** P1

**Exact file:** `server/spain_crypto_payments_setup.sh`, `setup_monero_service`

**Evidence quote:** The service runs as `monero-wallet` but writes `/var/log/winsvpn/monero-wallet-rpc.log` in a directory created by root.

**Exact fix:**

```bash
monero_log="/var/log/winsvpn/monero-wallet-rpc.log"
install -o monero-wallet -g monero-wallet -m 0600 \
  /dev/null "${monero_log}"

runuser -u monero-wallet -- test -w "${monero_log}" || exit 1
systemctl restart monero-wallet-rpc.service
systemctl is-active --quiet monero-wallet-rpc.service || exit 1
```

**Residual risk:** Log rotation must recreate the file with owner `monero-wallet` and mode 0600.

F-14

**Domain:** G

**Severity:** P1

**Exact file:** `extension/src/core/endpoint.js`, `pacToken`; `extension/src/core/pac.js`, `buildPac`

**Evidence quote:** `pacToken` directly reads `endpoint.host` and `endpoint.port`, although the file describes `validateEndpoint` as the final assertion before endpoint use.

**Exact fix:**

```javascript
export function pacToken(endpoint) {
  const checked = validateEndpoint(endpoint);
  if (!checked.ok) {
    throw new TypeError("invalid loopback proxy endpoint");
  }

  const bare = checked.endpoint.host.startsWith("[")
    ? checked.endpoint.host.slice(1, -1)
    : checked.endpoint.host;

  const host = bare.includes(":") ? `[${bare}]` : bare;
  return `PROXY ${host}:${checked.endpoint.port}`;
}
```

Add rejection tests for a routable host, ports 0 and 65536, non-integer ports, and non-HTTP endpoint kinds.

**Residual risk:** The caller must treat the exception as connection failure and must not automatically install an all-direct PAC.

F-15

**Domain:** G

**Severity:** P1

**Exact file:** `extension/src/core/pac.js`, `buildPac`

**Evidence quote:** Hosts are lowercased and stripped of a final dot, while `(settings.listed || []).map(lit)` emits rules without equivalent normalization.

**Exact fix:** Normalize every listed and excluded rule before PAC generation:

```javascript
function normRule(value) {
  let rule = String(value || "").trim().toLowerCase();
  while (rule.endsWith(".")) rule = rule.slice(0, -1);
  if (!rule) return "";

  try {
    const parsed = new URL(`https://${rule}`);
    if (parsed.username || parsed.password || parsed.port) return "";
    return parsed.hostname.replace(/\.$/, "");
  } catch (_) {
    return "";
  }
}
```

Reject empty normalization results in the save UI and display the normalized hostname before storage.

**Residual risk:** A syntactically valid typo or homograph can still route an unintended hostname.

F-16

**Domain:** C

**Severity:** P1

**Exact file:** `winn3-nodes/deploy_and_verify.sh`, `cmd_rollback`

**Evidence quote:** Deletion of both `FORWARD` jumps and the NAT `POSTROUTING` jump is inside `if [[ -n "$wan_if" ]]`, although those deletion commands do not use `$wan_if`.

**Exact fix:** Move those deletions outside the conditional:

```bash
while iptables -w 10 -D FORWARD -i "$iface" \
    -j WINN3GW-FORWARD 2>/dev/null; do :; done
while iptables -w 10 -D FORWARD -o "$iface" \
    -j WINN3GW-FORWARD 2>/dev/null; do :; done
while iptables -w 10 -t nat -D POSTROUTING \
    -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done
```

After chain deletion:

```bash
if iptables-save | grep -q -- '-j WINN3GW-'; then
  FAIL "rollback left WINN3GW jump references"
fi
verdict
```

**Residual risk:** Rules inserted outside the named chains require separate identification and removal.

F-17

**Domain:** E

**Severity:** P1

**Exact file:** `web/_headers`, global Content-Security-Policy

**Evidence quote:** `script-src` authorizes `googletagmanager.com` and `connect.facebook.net`; `connect-src` authorizes Google Analytics, DoubleClick, and Facebook; `img-src` includes unrestricted `https:`.

**Exact fix:** Remove tracker tags and pixels from `web/index.html`. Restrict the CSP to self-hosted assets and required payment providers:

```text
img-src 'self' data:;
script-src 'self' 'sha256-...' 'sha256-...'
  https://www.paypal.com https://www.paypalobjects.com;
connect-src 'self'
  https://www.paypal.com https://www.paypalobjects.com
  https://www.sandbox.paypal.com
  https://applepay.cdn-apple.com https://pay.google.com;
```

Add a release check rejecting `googletagmanager.com`, `connect.facebook.net`, `google-analytics.com`, `doubleclick.net`, and `googleadservices.com` in repository and live CSP values.

**Residual risk:** Hosted payment providers still receive checkout requests. The change removes tracker authorization, not payment-provider visibility.

F-18

**Domain:** D

**Severity:** P1

**Exact file:** `router/security.py`, `decision_log_path`

**Evidence quote:** Default `DECISIONS_FILE` is `/tmp/router_decisions.jsonl`, while `_validate_private_ancestors` requires the parent directory to have mode `0700`.

**Exact fix:**

```python
def decision_log_path() -> Path:
    return _absolute_file_path(
        os.environ.get(
            "DECISIONS_FILE",
            "/var/lib/winsvpn-router/router_decisions.jsonl",
        ),
        "DECISIONS_FILE",
    )
```

Provision it through systemd:

```ini
StateDirectory=winsvpn-router
StateDirectoryMode=0700
UMask=0077
Environment=DECISIONS_FILE=/var/lib/winsvpn-router/router_decisions.jsonl
```

Open and close the decision log during startup so a mode error fails before requests arrive.

**Residual risk:** Explicit existing `/tmp` overrides remain broken until operators remove or replace them.

F-19

**Domain:** C

**Severity:** P1

**Exact file:** `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy` and `cmd_rollback`

**Evidence quote:** Secrets are staged under `[ROOT]/winn3-stage/` and copied into `/etc/winn/credentials`, but no subsequent deletion of staged originals is quoted.

**Exact fix:** After installed copies pass owner, mode, and digest checks, remove staged secret material in both deploy and rollback:

```bash
for secret in \
  winn3-gateway-static.key \
  winn3-gateway-admission.key \
  cover/winn-leaf-key.pem \
  cover/cover-key.pem \
  cover/ech-server-keys.json
do
  [[ -f "$STAGE/$secret" ]] || continue
  shred -u "$STAGE/$secret" 2>/dev/null || rm -f "$STAGE/$secret"
done
```

**Residual risk:** `shred` cannot guarantee physical overwrite on copy-on-write or flash storage. Full-disk encryption remains necessary.

F-20

**Domain:** E

**Severity:** P1

**Exact file:** `web/_worker.js`, public configuration response headers

**Evidence quote:** `publicConfigCacheKey` partitions by request origin, while the response header logic does not quote `Vary: Origin`.

**Exact fix:**

```javascript
function publicConfigHeaders(request) {
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "public, max-age=300",
    "vary": "Origin",
  };

  const origin = request.headers.get("origin") || "";
  if (allowedOrigins.has(origin)) {
    headers["access-control-allow-origin"] = origin;
  }
  return headers;
}
```

**Residual risk:** Any intermediary that ignores `Vary` can still miscache responses, but conforming caches receive the required partition signal.

F-21

**Domain:** E

**Severity:** P1

**Exact file:** `web/manifest.json`

**Evidence quote:** The manifest says `AI-powered, no-logs VPN protection`, while the Worker says the service may retain `account, device-count, payment, referral, security, and legal-acceptance metadata`.

**Exact fix:** Replace the unqualified statement with:

```json
"description": "Privacy and anti-censorship VPN. No logs of browsing history, DNS queries, traffic contents, or destinations. Limited account, device, payment, referral, security, and legal-acceptance metadata is retained to operate the service."
```

Use the same qualified text in store metadata and publication checks.

**Residual risk:** Some install surfaces may truncate the sentence. The stored source text remains factually aligned with the Worker's disclosure.

F-22

**Domain:** C

**Severity:** P1

**Exact file:** `docs/evidence/codex_astra_audit_round{2..20}.md` and `docs/evidence/codex_sol_audit_round{2..20}.md`

**Evidence quote:** Git status lists both round ranges as deleted.

**Exact fix:** Restore all 38 files:

```bash
git restore --source=HEAD --staged --worktree -- docs/evidence/
```

If relocation is intended, move rather than delete:

```bash
mkdir -p docs/evidence/archive
git mv docs/evidence/codex_astra_audit_round*.md docs/evidence/archive/
git mv docs/evidence/codex_sol_audit_round*.md docs/evidence/archive/
```

**Residual risk:** Restoring files does not prove their contents were authentic when first generated. Their committed history remains the custody record.

F-23

**Domain:** C

**Severity:** P1

**Exact file:** `winn3-nodes/deploy_and_verify.sh`, staged gateway binary verification

**Evidence quote:** `(cd "$STAGE" && sha256sum -c "$BIN_SRC.sha256")`, while staging instructions copy the binary and checksum together.

**Exact fix:** Store the reviewed digest in the committed deployment script or a separately signed release manifest:

```bash
declare -A REVIEWED_GATEWAY_SHA256=(
  [demo-gw-a]="REPLACE_WITH_64_HEX_REVIEWED_DIGEST"
)

actual="$(sha256sum "$BIN_SRC" | awk '{print $1}')"
wanted="${REVIEWED_GATEWAY_SHA256[$ROLE]:-}"
[[ "$wanted" =~ ^[0-9a-f]{64}$ ]] || die "no reviewed digest"
[[ "$actual" == "$wanted" ]] || die "gateway digest mismatch"
```

The operator must update the digest in a reviewed commit whenever the binary intentionally changes.

**Residual risk:** An attacker who controls both the binary and the reviewed repository can replace both values. The fix separates staging custody from review custody.

F-24

**Domain:** C

**Severity:** P1

**Exact file:** `server/wins_winn3_gateway_install.sh`, replay-journal provisioning

**Evidence quote:** `Do not delete or replace the journal while the service is running: on Unix an open file descriptor can keep writing an unlinked inode that a restart cannot reload.`

**Exact fix:** Before replacing or recreating the journal:

```bash
if systemctl is-active --quiet winn3-gateway.service &&
   [[ -e "${WINN3_REPLAY_JOURNAL_PATH}" ]]; then
  err "Stop winn3-gateway.service before replay-journal replacement"
  exit 1
fi
```

The operator command is:

```bash
systemctl stop winn3-gateway.service
```

After maintenance, validate the journal and run:

```bash
systemctl start winn3-gateway.service
```

**Residual risk:** An operator can still intentionally discard the journal while the service is stopped, which also discards stored replay history.

F-25

**Domain:** C

**Severity:** P1

**Exact file:** `winn3-nodes/deploy_and_verify.sh`, gateway sysctl deployment

**Evidence quote:** The deployed drop-in sets `net.core.default_qdisc = fq`, and rollback leaves the sysctl in place.

**Exact fix:** Remove `net.core.default_qdisc` from the node-wide sysctl file. Apply `fq` only to the Winn v3 interface after creation:

```bash
tc qdisc replace dev winn3gw0 root fq
```

Place the same command in the gateway unit's `ExecStartPost` so interface recreation reapplies it.

**Residual risk:** A changed interface name causes the scoped command to fail. The unit must fail visibly or obtain the interface name from its validated configuration.

F-26

**Domain:** B and D

**Severity:** P1

**Exact file:** `server/wins_control_plane_setup_ONETOUCH.sh`, `WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT` and descriptor validation

**Evidence quote:** `the client's winn3DialCarrier hard-refuses carrier.ClassTLS ... but winn3Profile validate() ACCEPTS class=tls at load`

**Exact fix:** Until TLS is dialable, remove it from the control-plane defaults and reject it before publishing descriptors:

```bash
WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT="udp"

case "${WINN3_CARRIER_CLASS}" in
  udp) ;;
  tls)
    echo "[ERR] carrier class tls is not dialable by this client build" >&2
    exit 1
    ;;
  *)
    echo "[ERR] unsupported carrier class: ${WINN3_CARRIER_CLASS}" >&2
    exit 1
    ;;
esac
```

Add a test asserting that every provisioned carrier class belongs to the client dialer's accepted set.

**Residual risk:** Existing stored descriptors containing `class=tls` must be found and replaced before rollout.

F-27

**Domain:** E

**Severity:** P2

**Exact file:** `web/_worker.js`, `pruneRateBuckets` and `isolateLocalRateLimited`

**Evidence quote:** `while (rateBuckets.size > RATE_BUCKET_CAP) { rateBuckets.delete(rateBuckets.keys().next().value); }`

**Exact fix:** Never evict an active existing bucket merely to admit a new key. Prune expired entries, then fail closed for unseen keys when capacity remains full:

```javascript
function ensureBucketCapacity(now, key) {
  if (rateBuckets.has(key)) return true;

  for (const [candidate, bucket] of rateBuckets) {
    if (bucket.reset <= now) rateBuckets.delete(candidate);
  }

  return rateBuckets.size < RATE_BUCKET_CAP;
}

function isolateLocalRateLimited(keyPrefix, ip, limit, windowMs) {
  const now = Date.now();
  const key = `${keyPrefix}:${ip}`;

  if (!ensureBucketCapacity(now, key)) return true;

  // Existing bucket accounting follows.
}
```

**Residual risk:** When the isolate reaches capacity, new clients receive 429 until entries expire. Distributed limiting remains the required control for paid routes.

F-28

**Domain:** E

**Severity:** P2

**Exact file:** `tools/verify_live_deployment.py`, `repo_header` and inline script/style regular expressions

**Evidence quote:** `repo_header` returns the first matching header anywhere in the file; `INLINE_SCRIPT_RE` uses `<script\b([^>]*)>`, which stops at `>` inside a quoted attribute.

**Exact fix:** Restrict header lookup to the global `/*` block:

```python
def repo_header(name: str) -> str:
    prefix = f"{name.lower()}:"
    in_global = False

    for raw in HEADERS_FILE.read_text(encoding="utf-8").splitlines():
        if raw and not raw[0].isspace():
            in_global = raw.strip() == "/*"
            continue
        if in_global and raw.strip().lower().startswith(prefix):
            line = raw.strip()
            return line[len(prefix):].strip()

    raise SystemExit(f"missing global header {name}")
```

Use quote-aware tag matching:

```python
INLINE_SCRIPT_RE = re.compile(
    r"""<script\b((?:[^>"']|"[^"]*"|'[^']*')*)>(.*?)</script\s*>""",
    re.S | re.I,
)
INLINE_STYLE_RE = re.compile(
    r"""<style\b((?:[^>"']|"[^"]*"|'[^']*')*)>(.*?)</style\s*>""",
    re.S | re.I,
)
```

**Residual risk:** Regular expressions remain an approximate HTML parser. Repository and deployed content must pass the same parser and byte comparison.
