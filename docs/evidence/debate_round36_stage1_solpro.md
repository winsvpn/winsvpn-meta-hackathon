# Round 36 stage1: solpro

**Verdict**

BLOCK release and production deployment. The packet supports 15 findings: 4 P0, 8 P1, and 3 P2. No proposed fix modifies the frozen downlink datapath. Fleet commands below are proposals only. All protocol material and generated evidence must remain private.

**F-1**

- Domain: F
- Severity: P0
- File and location: `server/spain_crypto_payments_setup.sh`, `setup_btcpay_server`
- Evidence: The root-only script runs `git clone https://github.com/btcpayserver/btcpayserver-docker.git` without a commit pin, then executes `. ./btcpay-setup.sh -i`. The downloaded repository therefore supplies root-executed shell code without an immutable identity check.
- Exact fix: Remove network cloning from the privileged installer. Require a clean, pre-staged checkout at an operator-reviewed commit:

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
    git -C "${BTCPAY_DOCKER_DIR}" diff --quiet
    git -C "${BTCPAY_DOCKER_DIR}" diff --cached --quiet

    # Existing environment generation and reviewed setup invocation follow.
}
```

Also remove the existing `git clone` branch entirely.
- Residual risk: The operator must establish the reviewed commit through a separate trusted custody process. A pinned commit does not itself prove the code is safe.

**F-2**

- Domain: F
- Severity: P0
- File and location: `server/spain_crypto_payments_setup.sh`, `setup_monero_service` and `print_summary`
- Evidence: The generated systemd unit embeds `--rpc-login ${rpc_user}:${rpc_pass}`. The script does not enforce a confidential mode on `/etc/systemd/system/monero-wallet-rpc.service`. It then directly prints the password with `printf 'MONERO_WALLET_RPC_PASS="%s"\n' "${rpc_pass}"`.
- Exact fix:

```bash
local unit_tmp
unit_tmp="$(mktemp)"
trap 'rm -f "${unit_tmp}"' RETURN

cat > "${unit_tmp}" <<EOF
[Unit]
Description=Win's VPN Monero View-Only Wallet RPC
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=monero-wallet
Group=monero-wallet
ExecStart=/usr/local/bin/monero-wallet-rpc \\
    --wallet-dir /var/lib/monero/wallet \\
    --rpc-bind-ip 127.0.0.1 \\
    --rpc-bind-port 18083 \\
    --restricted-rpc \\
    --rpc-login ${rpc_user}:${rpc_pass} \\
    --daemon-address nodes.hashvault.pro:18081 \\
    --untrusted-daemon \\
    --log-file /var/log/winsvpn/monero-wallet-rpc.log \\
    --max-log-file-size 10485760 \\
    --disable-rpc-login=0 \\
    --confirm-external-bind=0
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/monero /var/log/winsvpn
MemoryHigh=512M
MemoryMax=768M

[Install]
WantedBy=multi-user.target
EOF

install -o root -g root -m 0600 \
    "${unit_tmp}" /etc/systemd/system/monero-wallet-rpc.service
```

Replace the password output with:

```bash
printf 'MONERO_WALLET_RPC_PASS="<stored in %s; not printed>"\n' "${creds_file}"
```

Never copy the password into generated evidence or handoff text.
- Residual risk: The credential still appears in the running process argument vector. The packet gives no verified Monero option for reading RPC credentials from a protected descriptor, so that remaining exposure needs a separate design review.

**F-3**

- Domain: E
- Severity: P0
- File and location: `web/_worker.js`, `requireQuota` and the translation and AI chat handlers
- Evidence: The packet states that Pages rejects Rate Limiting bindings and that `env[bindingName]` is undefined in production. `requireQuota` therefore falls back to the isolate-local `Map`. The source comment already records a “conditional distributed-cost/quota-exhaustion gap” for translation and AI chat.
- Exact fix: Make paid upstream routes unavailable when their distributed limiter is absent:

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
      if (bindingRequired) {
        return json({ error: "quota_unavailable" }, 503, corsHeaders(request));
      }
    }
  } else if (bindingRequired) {
    return json({ error: "quota_unavailable" }, 503, corsHeaders(request));
  }

  return isolateLocalRateLimited(keyPrefix, ip, limit, windowMs)
    ? json({ error: "rate_limited" }, 429, corsHeaders(request))
    : null;
}
```

Pass `true` as the last argument from the translation and AI chat handlers. Keep that fail-closed setting until either a real Worker binding is deployed or a zone-level rule is independently evidenced.
- Residual risk: Translation and AI chat return 503 on the current Pages deployment. That availability loss is explicit and bounded, while the cost proxy is disabled.

**F-4**

- Domain: E
- Severity: P0
- File and location: `web/_worker.js`, `handleMapTile`
- Evidence: `handleMapTile` accepts every valid coordinate and performs an upstream `fetch`, but invokes no quota function. For zoom levels 0 through 19, the accepted coordinate count is:

```text
1 + 4 + 4^2 + ... + 4^19
= (4^20 - 1) / 3
= 366,503,875,925 distinct tile paths
```

The cache cannot prevent first-fetch work across that path set.
- Exact fix: Use the strict binding behavior from F-3 before checking the cache:

```javascript
async function handleMapTile(request, env, context) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-methods": "GET, OPTIONS",
        "access-control-allow-origin": "*",
      },
    });
  }
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405);
  }

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

  // Existing coordinate validation, cache lookup, and upstream fetch follow.
}
```

Do not add a fake namespace identifier to `web/wrangler.jsonc`. Keep the route unavailable until a real `RATE_LIMITER_MAP_TILE` binding is evidenced.
- Residual risk: Maps remain unavailable on Pages because the packet proves Pages has no such binding. A future distributed limit still permits traffic up to its configured allowance.

**F-5**

- Domain: C
- Severity: P1
- File and location: `winn3-nodes/deploy_and_verify.sh`, `cmd_deploy` and `cmd_verify_hub`
- Evidence:
  - `local_jump_receipts` increments the shell `FAILURES` counter, but `cmd_deploy` never calls `verdict`. It can print `FAIL` for missing forwarding or NAT rules and still exit zero.
  - The Python verifier increments `fails` for `tcp-9111-connect`, `seam-port`, and `client-rx-packets>0`, but computes `result` only from `carrying`, `ok_inner`, and `ok_nat`. Thus `fails=2` can still produce `RESULT ... PASS`.
- Exact fix:

```bash
# At the end of cmd_deploy, after local_jump_receipts:
verdict
```

Replace the Python result calculation with:

```python
result = "PASS" if fails == 0 else "FAIL"
print(
    f"RESULT {role}: {result} "
    f"(failures={fails} handshake={int(carrying)} "
    f"icmp-inner={int(ok_inner)} icmp-nat={int(ok_nat)}; "
    f"log verify-{role}.status.log)"
)
sys.exit(0 if fails == 0 else 1)
```

Ensure every early `seam-port` failure prints receipts before exiting, matching the no-handshake branch.
- Residual risk: ICMP success proves only the tested target and instant. It does not prove long-session stability, packet loss, or behavior after gateway restart.

**F-6**

- Domain: A
- Severity: P1
- File and location: `android/app/build.gradle.kts`, `verifyAndroidReleaseEngineInputs`
- Evidence: For each engine, the gate constructs release and main candidates and accepts when `candidates.none(::isSafeNonEmptyReleaseInput)` is false. A safe `src/main` file can therefore satisfy the gate even when an existing `src/release` file is empty, a symlink, or otherwise unsafe.
- Exact fix: Validate the source-set winner instead of accepting any candidate:

```kotlin
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
        }
    }
}
```

Add a unit fixture where an unsafe release file shadows a valid main file and assert that the gate rejects it.
- Residual risk: Non-empty regular files can still contain stale or incorrect machine code. The existing freshness and packaged-artifact checks must remain independently enforced.

**F-7**

- Domain: A
- Severity: P1
- File and location: `android/app/src/main/AndroidManifest.xml`
- Evidence: The manifest declares:

```xml
<uses-permission
    android:name="android.permission.QUERY_ALL_PACKAGES"
    tools:ignore="QueryAllPackagesPermission" />
```

The supplied manifest gives detailed explanations for other permissions but supplies no operational use for package-wide enumeration. Its `<queries>` section already limits browser intents to `http` and `https`.
- Exact fix: Delete the `QUERY_ALL_PACKAGES` declaration. If a concrete package query is later proven necessary, add only its exact `<package>` or `<intent>` entry under `<queries>`.
- Residual risk: Hidden Kotlin or Dart code not included in the packet may currently depend on broad enumeration. Search and device tests are required before publication. Google Play treatment is UNVERIFIED-LIVE because current store policy was not supplied.

**F-8**

- Domain: D
- Severity: P1
- File and location: `server/wins_control_plane_setup_ONETOUCH.sh`, initial `WINS_DEFAULTS_FILE` load
- Evidence: The script immediately executes `. "${WINS_DEFAULTS_FILE}"` under `set -a` without the ownership, mode, regular-file, or symlink checks used by `server/wins_core_server_setup_ONETOUCH.sh`.
- Exact fix: Add and call this before every sourced defaults or secrets file:

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

Then change the load to:

```bash
if [[ -f "${WINS_DEFAULTS_FILE}" ]]; then
  wins_require_trusted_env_file "${WINS_DEFAULTS_FILE}" "WINS_DEFAULTS_FILE"
  set -a
  . "${WINS_DEFAULTS_FILE}"
  set +a
fi
```

Apply the same helper inside `overlay_wins_secrets_file`.
- Residual risk: Root-owned configuration remains executable shell syntax. A mistaken or malicious root edit still executes with installer privileges.

**F-9**

- Domain: C
- Severity: P1
- File and location: `server/wins_data_plane_setup_ONETOUCH.sh`, `WINS_DEFAULTS_FILE` and `WINS_SECRETS_FILE` loading
- Evidence: `load_existing_node_env` checks ownership and mode, but the later defaults load executes `. "${WINS_DEFAULTS_FILE}"` with no equivalent validation. The secrets path checks owner and mode but has no explicit real-file and non-symlink assertion.
- Exact fix: Copy the `wins_require_trusted_env_file` function from F-8 into this installer and invoke it before sourcing `NODE_ENV_FILE`, `WINS_DEFAULTS_FILE`, and `WINS_SECRETS_FILE`. Retain the existing mode checks as duplicate defense or replace them with that single helper.
- Residual risk: Root can still intentionally source arbitrary shell code. The fix removes untrusted file type and permission states, not root authority.

**F-10**

- Domain: F
- Severity: P1
- File and location: `server/spain_crypto_payments_setup.sh`, `setup_monero_service`
- Evidence: `/var/log/winsvpn` is created by root, while the service runs as `User=monero-wallet` and requests `--log-file /var/log/winsvpn/monero-wallet-rpc.log`. `ReadWritePaths` changes the systemd filesystem sandbox but does not create an owner-writable log file in the script.
- Exact fix: Before starting the service, provision the exact file:

```bash
local monero_log="/var/log/winsvpn/monero-wallet-rpc.log"
if [[ ! -e "${monero_log}" ]]; then
    install -o monero-wallet -g monero-wallet -m 0600 /dev/null "${monero_log}"
fi
chown monero-wallet:monero-wallet "${monero_log}"
chmod 0600 "${monero_log}"
```

Then verify both writability and service state:

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

- Residual risk: The service can fill the configured 10 MiB active log and any external rotations. Rotation ownership must preserve `monero-wallet` writability.

**F-11**

- Domain: G
- Severity: P1
- File and location: `extension/src/core/endpoint.js`, `pacToken`; `extension/src/core/pac.js`, `buildPac`
- Evidence: The comment says `validateEndpoint` is the “Final assertion before an endpoint is used for anything,” but `buildPac` calls `pacToken(endpoint)` and `pacToken` directly reads `endpoint.host` and `endpoint.port` without invoking that assertion.
- Exact fix:

```javascript
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

Add tests asserting that `buildPac` throws for a routable host, port 0, port 65536, non-integer ports, and non-HTTP kinds.
- Residual risk: The background caller must treat this exception as a failed connection and must not install `PAC_ALL_DIRECT` as an automatic fallback. That caller was not included in the packet.

**F-12**

- Domain: C
- Severity: P1
- File and location: `winn3-nodes/deploy_and_verify.sh`, `cmd_rollback`
- Evidence: Removal of both `FORWARD` jumps and the NAT `POSTROUTING` jump is inside `if [[ -n "$wan_if" ]]`, although those three deletion commands do not reference `$wan_if`. If default-route discovery fails, the jumps remain, chain deletion errors are suppressed, and the script still prints a rollback receipt.
- Exact fix: Move the jump deletion loops outside the `wan_if` condition and verify absence:

```bash
while iptables -w 10 -D FORWARD -i "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
while iptables -w 10 -D FORWARD -o "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done

if [[ -n "$wan_if" ]]; then
  while iptables -w 10 -D INPUT -i "$iface" -d "$INNER_V4" \
      -p tcp --dport 53 -j WINN3GW-INPUT 2>/dev/null; do :; done
fi
```

After chain deletion, add:

```bash
iptables -S FORWARD 2
