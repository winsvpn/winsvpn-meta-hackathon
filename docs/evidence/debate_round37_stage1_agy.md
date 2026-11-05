# Round 37 stage1: agy

### Verification Findings

* **FIX 1**: VERIFIED. Moving Monero daemon credentials to `/var/lib/monero/monero-wallet-rpc.conf` under mode 0600 and `monero-wallet:monero-wallet` ownership isolates the secret from non-root accounts. The parent directory is mode 0700, so unprivileged users cannot traverse it or read directory entries. Restricting the service unit to mode 0640 without inline secrets, eliminating stdout credential dumps, and removing the `--disable-rpc-login=0` flag close local credential exposure. Deleting the public `/monero-rpc` location block from Nginx prevents loopback confusion behind the Cloudflare tunnel. Extraction within a mode 0700 temporary directory, enforcing exactly one regular binary and rejecting symlinks, prevents local binary preplanting. Monero v0.18.5.1 checksum (22a7dda7b0cb699fdd6b7674c3b4a4465b337cc98a54983523b759e1e7cc9958) is (unverified-live).

* **FIX 2**: VERIFIED. Rejecting requests with 503 quota_unavailable when bindings fail protects paid AI and translation routes from unmetered execution. Synchronizing secret request responses to be byte-identical with the standard fallback stops keyword list enumeration via timing or response length differences. The `isolateLocalRateLimited` modification correctly prevents attackers from wiping rate-limit windows by flooding dummy entries. Refusing new entries when the bucket table hits `RATE_BUCKET_CAP` without expired slots introduces a localized denial-of-service risk, where an attacker rotating unexpired client identifiers can temporarily block legitimate new arrivals on that specific isolate.

* **FIX 3**: VERIFIED. Removing advertising endpoints, tracking endpoints, and the bare `https:` image wildcard reduces exfiltration channels. Hash-pinning the specific inline script and style blocks satisfies strict content security policy enforcement while allowing checkout operations for approved payment vendors.

* **FIX 4**: VERIFIED. Enabling `LauncherDecoy` by default and disabling `LauncherReal` guarantees the disguised entry point is active immediately upon installation. Deleting the exported `SecretCodeReceiver` from the manifest, code, proguard config, and unit tests removes an unauthenticated telephony intent attack vector. Retaining `QUERY_ALL_PACKAGES` is technically required for split-tunnel package selection, though it remains subject to Google Play declaration scrutiny (unverified-live).

* **FIX 5**: VERIFIED. Moving `decision_log_path` to `/var/lib/winsvpn-router/decisions.jsonl` within the service StateDirectory eliminates insecure `/tmp` file creation. The deny-by-default middleware blocks arbitrary URL paths before handler dispatch. FastAPI documentation endpoints (`/docs`, `/openapi.json`) return 404, which is correct for an internal production data plane. Bounded slot acquisition using a 0.25-second ceiling prevents request queuing from exhausting server worker threads.

* **FIX 6**: VERIFIED. Prioritizing `src/release` over `src/main` using `Files.exists(..., NOFOLLOW_LINKS)` enforces unambiguous source-set precedence. A malformed or unsafe file staged in `src/release` halts the build immediately rather than permitting an insecure fallback to `src/main`.

* **FIX 7**: VERIFIED. Restricting `fq` configuration to `dev winn3gw0` via a bounded interface polling loop avoids modifying unrelated interfaces on the host. Shredding staged keys and verifying erasure receipts after verification terminates persistent secret exposure on the deployment filesystem.

* **FIX 8**: VERIFIED. Injecting `app_version()` directly into the extension manifest keeps package versions aligned with `pubspec.yaml`. The current logic parses standard numeric versions with build metadata like `1.0.16+33`. A version formatted with a prerelease tag, such as `1.0.16-beta.1`, would pass the hyphenated suffix into the manifest and fail web store schema validation.

* **FIX 9**: VERIFIED. Executing `validateEndpoint` inside `pacToken` rejects out-of-bounds ports, non-routable targets, and malformed hosts before PAC proxy rule generation.

* **FIX 10**: VERIFIED. Requiring default environment configuration files to be regular files owned by root with mode 0600 prevents unprivileged users from manipulating environment state via symlinks or world-writable files.

* **FIX 11**: VERIFIED. Adjusting the test oracle to 1536 KiB per session brings regression test assertions into strict mathematical alignment with current installer resource configuration.

### Pre-Warm Collapse Analysis

* **Ranking of Mechanisms**:
1. Pacing/token bucket: An upstream carrier or ISP traffic policer with a token burst bucket of ~100 MB empties in roughly one second at 720 Mbps. Once exhausted, the policer clamps traffic to its committed information rate of 250 to 300 Mbps until token replenishment occurs.
2. Carrier pipe inbox depth backpressure: Injecting 90 MB into large socket buffers creates severe bufferbloat. Queuing latency inflates RTT, which drives the transport congestion window down and slows delivery.
3. Gateway per-peer queue: Accumulation at the gateway input queue triggers head-of-line delays and tail drops, forcing transport backoff.
4. Client socket buffer: Deep 128 MiB buffers absorb the transmission burst instantly, delaying socket-level backpressure until kernel space fills.
5. Cloudflare endpoint throttle: Direct UDP data planes bypass Cloudflare HTTP edge tunnels, excluding edge HTTP rate-limiting from the data path.

* **Discriminating Measurement**:
Capture packet sequence numbers, transmit timestamps, and arrival timestamps on both endpoints during the burst and subsequent plateau. If one-way latency jumps by hundreds of milliseconds while packet loss stays near zero, bufferbloat in client or gateway queues is the root cause. If one-way latency remains flat while packet loss rises to roughly sixty percent (matching the delta between 720 Mbps and 300 Mbps), an external carrier-level token bucket policer is dropping traffic.

### Next Action

* **NEXT**: Run `python3 /Users/owner/xprize/winsvpnv3/server/test_crypto_payments_spain.py` and `python3 /Users/owner/xprize/winsvpnv3/router/tests/test_route_inventory.py` locally to verify that payment assertions and route inventory checks remain fully passing.
