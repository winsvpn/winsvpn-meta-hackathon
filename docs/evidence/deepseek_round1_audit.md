# DeepSeek V4.1 Flash Security & Architecture Audit (Round 1)

## Reasoning Trace Summary

Reasoning length: 27889 characters

## Audit Findings & Recommended Implementations

# WinsVPN — Adversarial Security Audit Report

**Auditor:** Principal Security Engineer / Core Systems
**Scope:** Flutter client, Cloudflare Pages Worker, control plane (Kansas), data plane fleet (8 regions)
**Date:** 2025
**Classification:** Internal — Executive + Engineering

---

## Executive Summary

The system is architecturally sound at a high level (multi-engine data plane, one-time setup keys, hash-pinned CSP, exact-match download allowlist). However the audit surfaces **4 Critical**, **7 High**, and several Medium findings clustered around:

| Severity | Count | Top issue |
|---|---|---|
| **Critical** | 4 | Fail-open dispatch on malformed config; cross-engine iptables teardown collisions; TUN/route race during v1↔v3 switch; naive hashing of activation secrets |
| **High** | 7 | TOCTOU on `_winn3OrdinaryConnectivityAuthorized`; non-atomic `vpn_settings.txt`; worker path-normalization bypass; non-idempotent lifetime migration; unsigned `SHA256SUMS.txt`; IPv6 leak; undefined fwmarks |
| **Medium** | 9 | DNS bind collision, `//` bypass, email-only setup key, missing cache invalidation, etc. |

The single most important fix is **C-1 (fail-closed protocol dispatch)**: today, any parse anomaly in the config silently degrades to an unauthenticated Winn v3 path.

---

## Section 1 — Triple-Protocol Client Contract & Fallback

### F-1.1 (Critical) — Fail-open dispatch on malformed `directConfig`

The dispatch relies on `strictWinnProtocolVersion(directConfig)` without an explicit failure mode. If the descriptor is truncated, cached from an older install, or authored by a downgrade attacker, the function may default to Winn v3 — the *newer* path — even though the user selected v1 with v1-only SPA keys.

**Vulnerability.** An on-disk config from a stale install (or one written by an older buggy client) with `protocol_version = 'v2'` or empty will fall through to whatever the default branch returns. If that default is `kWinnProtocolV3`, the client activates v3 with a v1 SPA key → the v3 handshake to Kansas may succeed under reduced authentication (`_winnSpaKeyProvisioned` may be false), and user traffic egresses without the expected v1 hub authorization.

**Recommended fix — fail closed with an explicit sentinel:**

```dart
const kWinnProtocolUnknown = 'unknown';

String strictWinnProtocolVersion(DirectConfig? cfg) {
  final v = cfg?.protocolVersion?.trim().toLowerCase() ?? '';
  switch (v) {
    case kWinnProtocolV1:
      return kWinnProtocolV1;
    case kWinnProtocolV3:
      return kWinnProtocolV3;
    default:
      return kWinnProtocolUnknown; // caller MUST refuse to auto-connect
  }
}

// in connect():
final plan = _snapshotConnectPlan(directConfig);
if (plan.protocolVersion == kWinnProtocolUnknown) {
  await _teardownAllInterfaces();
  _enterHardBlockedState(reason: 'malformed_protocol_descriptor');
  return;                      // do NOT dial anything
}
if (plan.protocolVersion == kWinnProtocolV1 && !plan.winn3Authorized) {
  await armWinn1PrimaryHubDispatchAuthorization();
}
```

### F-1.2 (High) — TOCTOU on `_winn3OrdinaryConnectivityAuthorized`

`_winnCapabilityFlags` is a getter that re-reads `_userSelectedProtocolVersion` and `_winn3OrdinaryConnectivityAuthorized` on each call. The connect path reads these values **again** separately. Between the two reads there is an `await` boundary (anything in `directConfig` parse, capability probe, UI signal). A concurrent UI toggle or background state update produces a plan whose `capabilities` say v1 but whose dispatch dials v3, or vice versa — a classic time-of-check/time-of-use desynchronization.

**Vulnerability.** This can produce a tunnel that has *not* been armed with `armWinn1PrimaryHubDispatchAuthorization` yet still routes through the v1 primary hub, or vice versa: a v3-dialed socket under a v1-only SPA key.

**Fix — snapshot the entire decision into an immutable record once:**

```dart
class _ConnectPlan {
  final String protocolVersion;
  final bool winn3Authorized;
  final Map<String, bool> capabilities; // unmodifiable
  const _ConnectPlan({
    required this.protocolVersion,
    required this.winn3Authorized,
    required this.capabilities,
  });
}

_ConnectPlan _snapshotConnectPlan(DirectConfig? cfg) {
  final version   = strictWinnProtocolVersion(cfg);
  final authorized = _winn3OrdinaryConnectivityAuthorized;
  final flags = Map<String, bool>.from(winnClientCapabilities(
    operatingSystem: Platform.operatingSystem,
    spaKeyProvisioned: _winnSpaKeyProvisioned,
  ));
  if (version == kWinnProtocolV1) {
    flags['supports_winn3'] = false;
    flags['supports_winn3_descriptor'] = false;
  }
  return _ConnectPlan(
    protocolVersion: version,
    winn3Authorized: authorized,
    capabilities: Map.unmodifiable(flags),
  );
}

// Replace `_winnCapabilityFlags` getter everywhere with a single snapshot
// captured at the start of connect() and threaded down.
```

Then make `_winnCapabilityFlags` a deprecation shim that calls `_snapshotConnectPlan(directConfig).capabilities` so callers cannot accidentally read stale state.

### F-1.3 (Critical) — Route/interface race during v1 ↔ v3 protocol switch (traffic leak)

The dispatch sequence for v1 is:
1. bring up `awg0` (Winn v1 primary), OR
2. fall back to XRay on 443.

For v3:
1. bring up `winn3gw0`.

If a user switches v3→v1 (or an automatic fallback fires), there is a window in which the new interface is being brought up **before** the old one is torn down. Concretely:

- The default route is still on `winn3gw0`.
- The client installs `awg0` and its routes.
- If the route insert is atomic, fine. If not, the kernel briefly uses **clearnet** for default.
- Worse: the old TUN remains up, so lingering TCP sockets (DNS-over-others, telemetry) still exit via v3 while the user believes they're on v1.

This is the classic *dual-tunnel leak*. On Android/iOS the `VpnService`/`NEPacketTunnelProvider` layer must be configured to install a **kill-switch route** (`0.0.0.0/1` + `128.0.0.0/1` via the new TUN) *before* any teardown of the old interface, and old sockets must be failed (`fwmark`-based `SO_MARK` fencing, or route table swap).

**Fix — atomic interface swap with a blocking sentinel route:**

```dart
Future<void> _switchTunnelAtomically({
  required String newIface,
  required String newGateway,
  required String? oldIface,
}) async {
  // 1. Install a black-hole route to stop clearnet egress immediately.
  await _vpnPlatform.addRoute(destination: '0.0.0.0/1', gateway: 'blackhole');
  await _vpnPlatform.addRoute(destination: '128.0.0.0/1', gateway: 'blackhole');

  // 2. Bring up the new tunnel fully (handshake, MTU, DNS).
  await _bringUpInterface(newIface, newGateway);
  await _waitForHandshake(newIface, timeout: const Duration(seconds: 5));

  // 3. Atomically replace the black-hole routes with the new default.
  await _vpnPlatform.addRoute(destination: '0.0.0.0/1', gateway: newGateway, iface: newIface);
  await _vpnPlatform.addRoute(destination: '128.0.0.0/1', gateway: newGateway, iface: newIface);

  // 4. Only NOW tear down the old interface.
  if (oldIface != null && oldIface != newIface) {
    await _tearDownInterface(oldIface);
  }
}
```

On Android, `VpnService.Builder.addRoute("0.0.0.0", 1)` + `addRoute("128.0.0.0", 1)` is the canonical leak-proof half-default pattern; do the same via `NEPacketTunnelProvider.setTunnelNetworkSettings`.

### F-1.4 (High) — Non-atomic write of `vpn_settings.txt`

`selected_protocol_version` is persisted into `vpn_settings.txt`. If the file is written in place and the process crashes (or the SD card sees a power cut mid-`writeString`), the file is torn — the next boot parses garbage and per F-1.1 falls into an undefined branch.

**Fix — write-to-temp-then-rename (atomic on all POSIX filesystems):**

```dart
Future<void> _writeSettingsAtomically(String path, String contents) async {
  final tmp = File('$path.tmp.${DateTime.now().microsecondsSinceEpoch}');
  await tmp.writeAsString(contents, flush: true);
  await tmp.rename(path);           // atomic rename(2)
}

Future<String?> _readSettings(String path) async {
  try {
    return await File(path).readAsString();
  } on FileSystemException {
    return null;
  }
}
```

Additionally, add a version header and HMAC on the file (with a per-install secret in the secure keystore) so tampering by an unprivileged in-app attacker or a hostile backup is detectable:

```
v1\nselected_protocol_version=winn3\nhmac=base64(...)
```

### F-1.5 (High) — Fallback retry storm / unbounded ping-pong (availability & fingerprinting)

The v1 path is "AWG primary / XRay backup". Nowhere is a retry cap or backoff defined. On a network that blocks AWG UDP egress (common on captive portals), the client can oscillate AWG→XRay→AWG indefinitely, generating repeated authentication attempts that (a) burn sessions, (b) trigger rate limits, and (c) let a passive censor fingerprint the client's fallback pattern.

**Fix — bounded, jittered, terminal:**

```dart
class _FallbackPolicy {
  static const _maxAttempts = 4;
  static const _baseBackoff = Duration(seconds: 2);
  static const _maxBackoff  = Duration(seconds: 30);

  Duration backoffFor(int attempt) {
    final jitterMs = Random.secure().nextInt(750);
    final scaled = (_baseBackoff.inMilliseconds * (1 << attempt))
        .clamp(0, _maxBackoff.inMilliseconds);
    return Duration(milliseconds: scaled + jitterMs);
  }
}

Future<void> _connectWithFallback(...) async {
  final policy = _FallbackPolicy();
  final order  = [_Transport.awg, _Transport.xray];
  int attempt = 0;
  while (attempt < 4) {
    final t = order[attempt % order.length];
    try {
      await _dial(t);
      return; // success
    } catch (e) {
      attempt++;
      if (attempt >= 4) {
        _enterHardBlockedState(reason: 'all_transports_exhausted');
        return;
      }
      await Future.delayed(policy.backoffFor(attempt));
    }
  }
}
```

### F-1.6 (Medium) — Active protocol label may reflect "preference" while dispatch reflects "cached config"

The label shows "connected config version **or** default user preference". If the user selects v1 but the cached config is v3, the label shows v3 (correct), but any subsequent reconnect uses the cached v3 config until the user explicitly toggles the setting. The user's mental model ("I'm on v1") diverges from wire behaviour. **Never derive labels from two sources.**

**Fix:** label = `_connectPlan.protocolVersion` at all times; if the user's preference differs, render a secondary line: `preference: v1 · negotiated: v3`.

---

## Section 2 — Web Delivery & Download Routing

### F-2.1 (Critical) — Path-normalization bypass via `//` or encoded traversal

```javascript
if (!pathname.startsWith('/downloads/') && pathname !== '/downloads') { ... return { action: 'ignore' }; }
const filename = pathname.slice('/downloads/'.length);
if (!authorizedPaths.includes(filename)) { return reject; }
```

`pathname.startsWith('/downloads/')` is **false** for `//downloads/foo.exe`. That branch returns `{action:'ignore'}` and falls through to the Pages static handler, which — after Cloudflare's normalizer collapses `//` — serves the same asset **without** the allowlist check. Similarly `/downloads/%2e%2e%2fsecret` (if the CDN decodes post-check) resolves outside the intent.

**Fix — normalize first, refuse encoded/ambiguous input, use a frozen `Set`:**

```javascript
// Module load — build once.
const AUTHORIZED = Object.freeze(new Set(authorizedPaths));

// Reject any path that contains a path-separator, dot-segment, backslash,
// encoded separators, or NUL. Doing this on the raw path blocks double-decode.
const PATH_SAFETY = /(\.\.|\\|\x00|%2e|%2f|%5c|%00)/i;

export function downloadAssetDecision(rawPathname, redirects, authorizedPaths) {
  if (typeof rawPathname !== 'string' || PATH_SAFETY.test(rawPathname)) {
    return { action: 'reject', status: 404 };
  }

  let pathname;
  try {
    pathname = decodeURIComponent(rawPathname);       // single canonical decode
  } catch {
    return { action: 'reject', status: 404 };
  }
  if (PATH_SAFETY.test(pathname) || pathname.includes('//')) {
    return { action: 'reject', status: 404 };
  }

  // Bare /downloads must NEVER serve a directory listing.
  if (pathname === '/downloads' || pathname === '/downloads/') {
    return { action: 'reject', status: 404 };
  }

  if (!pathname.startsWith('/downloads/')) {
    if (pathname === '/pkg' || pathname.startsWith('/pkg/')) {
      return { action: 'reject', status: 404 };
    }
    return { action: 'ignore' };
  }

  const filename = pathname.slice('/downloads/'.length);
  if (filename.includes('/') || filename.includes('\\') || filename.includes('%')) {
    return { action: 'reject', status: 404 };
  }
  if (!AUTHORIZED.has(filename)) {                     // Set.has — O(1), no proto pollution
    return { action: 'reject', status: 404 };
  }
  return { action: 'serve', assetPath: pathname };
}
```

### F-2.2 (Medium) — `redirects` parameter is unused and suspicious

`downloadAssetDecision(pathname, redirects, authorizedPaths)` accepts `redirects` but never references it. Either the parameter is dead code (remove it) or it was intended to gate redirect-based bypass (e.g., `?redirect=` query). **Either is a defect**. If a future maintainer populates `redirects`, they can add SSRF-like redirect behaviour. Remove the parameter or add a test that asserts it is never consulted.

### F-2.3 (High) — Direct `sync.winsvpn.org/downloads/` links bypass the Worker entirely

The email and website link directly to `https://sync.winsvpn.org/downloads/<asset>`. That hostname bypasses the Cloudflare Pages Worker — meaning the `authorizedPaths` allowlist is **not enforced** on the real delivery path. The only protection is obscurity of the filename. `SHA256SUMS.txt` is public, so the filenames are effectively public too.

**Impact.** If any asset is ever intended to be restricted (e.g., a build with a defensive fix not yet rolled out, or a per-channel build), *the allowlist does not protect it*. More immediately, this fails any control-framework assertion that "download authorization is enforced".

**Fix — one of:**

**(A) Serve downloads exclusively through the Worker** (recommended):

```
# Cloudflare DNS: sync.winsvpn.org → same Pages project, route /downloads/* through Worker
# Worker also sets, for every 'serve':
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="<basename>"
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; sandbox
Cache-Control: public, max-age=300, immutable
```

**(B) Enforce signed URLs** on the GCS mirror and any object-store origin:

```python
# control plane issues short-lived signed URLs only after auth
url = blob.generate_signed_url(
    version="v4",
    expiration=timedelta(minutes=5),
    method="GET",
)
```

Pick (A) if the deliverable is unauthenticated; pick (B) if restricted.

### F-2.4 (High) — `SHA256SUMS.txt` is not signed → useless against MITM

The email offers checksums for "cryptographic verification". But `SHA256SUMS.txt` is served over the same TLS channel as the binaries. A MITM who can forge the binary can also forge the checksum. The verification step therefore provides **zero** assurance against a network attacker.

**Fix — sign the manifest with minisign and publish the public key out-of-band:**

```bash
# build job
sha256sum winsvpn-*.exe winsvpn-*.apk winsvpn-*.tar.gz > SHA256SUMS.txt
minisign -Sm SHA256SUMS.txt -s /secure/minisign.key -c "WinsVPN Release $(date -u +%Y-%m-%d)"
# publish SHA256SUMS.txt and SHA256SUMS.txt.minisig
```

Ship the minisign public key (`RWxxxx…`) in the app install docs and in the email *as a base64 string* (not a link). Document the verification step in the portal:

```bash
minisign -Vm SHA256SUMS.txt -P RWxxxx…
sha256sum -c SHA256SUMS.txt
```

### F-2.5 (Medium) — CSP strength for HTML vs. downloads

Hash-pinning inline script/style is good. Verify:

- `base-uri 'none'` (prevents `<base href>` hijacks)
- `form-action 'none'` (prevents form-POST exfiltration)
- `frame-ancestors 'none'` (clickjacking)
- `object-src 'none'`
- `require-trusted-types-for 'script'` if feasible
- A `Content-Security-Policy-Report-Only` reporting endpoint during rollout

**Recommended policy for `index.html`:**

```
Content-Security-Policy:
  default-src 'none';
  script-src 'sha256-<…>';
  style-src 'sha256-<…>' 'unsafe-hashes';   # only if inline styles require
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self' https://sync.winsvpn.org;
  base-uri 'none';
  form-action 'none';
  frame-ancestors 'none';
  object-src 'none';
  upgrade-insecure-requests
```

For download assets:

```
Content-Security-Policy: default-src 'none'; sandbox
X-Content-Type-Options: nosniff
Content-Disposition: attachment
```

---

## Section 3 — Control Plane: Expiration & Setup Key Flow

### F-3.1 (Critical) — Naive `utcnow() + relativedelta(years=10)` loses timezone

```python
expiry = (utcnow() + relativedelta(years=10)).isoformat()
```

If `utcnow()` is `datetime.utcnow()` (naive) the resulting ISO string has **no offset**, e.g., `2035-05-01T14:00:00`. Downstream `parse_iso_datetime` in Kansas may treat that as local time (US Central, UTC−5/6) — shifting every lifetime account's expiry by 5–6 hours. More seriously, a naive comparison against `datetime.now(timezone.utc)` raises `TypeError: can't compare offset-naive and offset-aware datetimes` → **exception → account evaluation falls through**, which is often written as "allow" in defensive code paths. That's a **fail-open**.

**Fix — always store timezone-aware, ISO 8601 with offset, and never compare across naive/aware:**

```python
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta

def _lifetime_expiry(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    expiry = now + relativedelta(years=10)
    return expiry.astimezone(timezone.utc).isoformat(timespec='seconds')
    # → '2035-05-01T19:00:00+00:00'
```

And a defensive parser that refuses naive input rather than coercing:

```python
def parse_iso_datetime(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Do NOT silently localise; refuse.
        raise ValueError(f"naive datetime rejected: {s!r}")
    return dt.astimezone(timezone.utc)
```

### F-3.2 (High) — Lifetime migration is not scoped and not idempotent

The snippet:

```python
UPDATE users SET status = 'active', expiration_date = ? WHERE account_number = ?
```

has no `WHERE` that restricts to the *literal legacy values*. If that loop iterates over all users, every account is reset. Running the migration twice re-adds 10 years from *now*, granting effectively unbounded lifetime.

**Fix — scoped, idempotent, anchored, backed up:**

```python
def migrate_legacy_lifetime(conn, anchor_default: datetime | None = None) -> int:
    anchor_default = anchor_default or datetime.now(timezone.utc)
    legacy = ('LIFETIME ACCESS', 'LIFETIME', 'PERPETUAL', '')

    # 0. Backup (belt-and-braces; also run a consistent snapshot pre-migration).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users_pre_lifetime_migration_2025
        AS SELECT * FROM users
    """)

    conn.execute("BEGIN IMMEDIATE")
    try:
        rows = conn.execute("""
            SELECT account_number, COALESCE(created_at, ?) AS anchor
            FROM users
            WHERE expiration_date IS NULL
               OR expiration_date = ''
               OR UPPER(TRIM(expiration_date)) IN (?, ?, ?)
        """, (anchor_default.isoformat(timespec='seconds'),
              'LIFETIME ACCESS', 'LIFETIME', 'PERPETUAL')).fetchall()

        migrated = 0
        for account_number, anchor in rows:
            anchor_dt = parse_iso_datetime(anchor) or anchor_default
            expiry = (anchor_dt + relativedelta(years=10)).isoformat(timespec='seconds')
            conn.execute(
                "UPDATE users SET status='active', expiration_date=? "
                "WHERE account_number=?",
                (expiry, account_number),
            )
            migrated += 1
        conn.execute("COMMIT")
        return migrated
    except Exception:
        conn.execute("ROLLBACK")
        raise
```

Because the anchor is `created_at` (immutable), re-running produces the **same** expiry for the same account — idempotent by construction.

### F-3.3 (Critical) — Activation secret hashed with (likely) unsalted/fast hash

`activation_secret_hash = <value>` — the algorithm is not shown. If it is SHA-256 (common naive choice) or bcrypt-with-low-cost, a DB leak permits offline attacks on the 256-bit secret? No — 256 bits is not brute-forceable. **But** if the secret is *not* uniformly random (e.g. derived from `account_number + timestamp`), or if the hash is plain SHA-256 and the same secret can be *reused* after a token rotates, offline recovery is feasible when a secret leaks elsewhere. Also, using a fast hash makes enumeration across many leaked hashes cheap when any single secret leaks.

**Fix — Argon2id with per-row salt, single-use, time-bounded:**

```python
import secrets
import argon2
from argon2 import PasswordHasher
from datetime import datetime, timezone, timedelta

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

def issue_activation_secret(conn, account_number: str, ttl: timedelta = timedelta(minutes=30)) -> str:
    secret = secrets.token_urlsafe(32)             # 256 bits, URL-safe
    secret_hash = _ph.hash(secret)                 # argon2id, unique salt
    expires_at  = (datetime.now(timezone.utc) + ttl).isoformat(timespec='seconds')
    conn.execute("""
        UPDATE users
           SET activation_secret_hash       = ?,
               activation_secret_expires_at = ?,
               activation_secret_used_at    = NULL
         WHERE account_number = ?
    """, (secret_hash, expires_at, account_number))
    return secret                                  # deliver once, never log

def verify_and_consume_activation_secret(conn, account_number: str, presented: str) -> bool:
    row = conn.execute("""
        SELECT activation_secret_hash, activation_secret_expires_at, activation_secret_used_at
          FROM users WHERE account_number = ?
    """, (account_number,)).fetchone()

    # Constant-time dummy verify to equalise timing for unknown accounts
    if not row or not row[0]:
        try: _ph.verify(_DUMMY_HASH, presented)
        except Exception: pass
        return False
    if row[2] is not None:                         # already used
        return False
    try:
        exp = parse_iso_datetime(row[1])
        if exp is None or exp <= datetime.now(timezone.utc):
            return False
    except ValueError:
        return False
    try:
        _ph.verify(row[0], presented)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.InvalidHash):
        return False

    # Single-use: only succeed if not already consumed (atomic CAS)
    cur = conn.execute("""
        UPDATE users
           SET activation_secret_used_at = ?
         WHERE account_number = ?
           AND activation_secret_used_at IS NULL
    """, (datetime.now(timezone.utc).isoformat(timespec='seconds'), account_number))
    return cur.rowcount == 1
```

Also add a **rate limiter** keyed by `(account_number, source_ip)` — 5 attempts / 15 min — and a per-account lockout that escalates.

### F-3.4 (High) — Setup key delivered over SMTP only (no second factor)

TLS SMTP protects hop-to-hop only. The user's mailbox is the security boundary. If email is compromised (webmail breach, forwarding rule), the attacker gets a valid setup key and can enrol their own device as the user.

**Fix — require a second enrolment proof:**

- Enrolment URL requires the setup key **plus** an out-of-band code the user must enter from the client device (e.g. a 6-digit numeric shown on the device, validated server-side against a session the client opened via TLS to Kansas).
- Bind the key to the first device fingerprint (public-key-based) — subsequent enrolments invalidate and require re-issuance.
- Send a **notification email** to the account owner on successful enrolment (so a compromised mailbox attacker is at least noticed by the legitimate owner).

The setup key alone must never be sufficient to establish a data-plane peer.

### F-3.5 (Medium) — Anti-spam link hygiene is good, but email template must be XSS-safe

The email now links to `https://winsvpn.org/#download`, the GCS mirror, and `SHA256SUMS.txt` — solid anti-spam posture. Any user-controlled substitution (e.g. display name, account number) into the HTML body must be HTML-escaped:

```python
from markupsafe import escape

html_body = TEMPLATE.format(
    first_name=escape(user.first_name),
    account_number=escape(user.account_number),
)
```

Also set on outbound mail:
- `DKIM`, `SPF -all`, `DMARC p=reject`
- `List-Unsubscribe: <mailto:…>, <https://…>` header (as a header, not a body link)
- `MIME-Version: 1.0` with explicit `Content-Type: text/html; charset=utf-8`

### F-3.6 (Medium) — User enumeration via enrolment endpoint

If the endpoint responds differently (200 vs 404, different body, different timing) for existent vs nonexistent accounts, attackers enumerate account numbers. **Fix:** always return HTTP 200 with a generic body ("If your account is active, you will receive an email shortly"), apply the same rate limit for all inputs, and use `_constant_time_delay()` on the not-found branch.

---

## Section 4 — Data Plane Multi-Engine Isolation & Concurrency

The data plane co-locates three forwarding engines on one host: `awg0` (AmneziaWG, port 9110), `winn3gw0` (Winn v3, port 9111, TUN 10.10.0.1/24), and XRay (VLESS-WS, 80/443). This is a defensible design **only** if their kernel state is strictly partitioned. As currently structured, several implicit collisions exist.

### F-4.1 (Critical) — iptables teardown collisions between engines

If each engine's setup script issues:

```bash
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i <iface> -j ACCEPT
```

and each teardown script issues `iptables -F` or `-D` on a rule index, tearing down **one** engine removes the **other's** rules too. Worse: rule insertion order is not deterministic across engine restarts, and `-A` duplicates accumulate on every restart.

**Fix — one owner chain, one per-engine sub-chain, idempotent, never `-F`:**

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- idempotent add: only add if not already present ---
ip4_ensure() { iptables -C "$@" 2>/dev/null || iptables -A "$@"; }
ip4t_ensure() { iptables -t nat -C "$@" 2>/dev/null || iptables -t nat -A "$@"; }

# --- shared jump chain, inserted once ---
iptables -N WINSV_FORWARD 2>/dev/null || true
iptables -N WINSV_NAT     2>/dev/null || true
ip4_ensure  FORWARD -j WINSV_FORWARD
ip4t_ensure POSTROUTING -j WINSV_NAT

# --- per-engine sub-chains ---
iptables -N WINSV_AWG   2>/dev/null || true
iptables -N WINSV_WINN3 2>/dev/null || true
iptables -N WINSV_XRAY  2>/dev/null || true

# --- dispatch by in-interface ---
ip4_ensure WINSV_FORWARD -i awg0     -j WINSV_AWG
ip4_ensure WINSV_FORWARD -i winn3gw0 -j WINSV_WINN3
# XRay is userspace L4/L7 — no AF_PACKET forwarding needed; do not add FORWARD rules for it.

# --- per-engine forward rules ---
ip4_ensure WINSV_AWG   -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip4_ensure WINSV_AWG   -m conntrack --ctstate NEW -j ACCEPT
ip4_ensure WINSV_WINN3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip4_ensure WINSV_WINN3 -m conntrack --ctstate NEW -j ACCEPT

# --- per-engine NAT ---
ip4t_ensure WINSV_NAT -o eth0 -i awg0     -j MASQUERADE
ip4t_ensure WINSV_NAT -o eth0 -i winn3gw0 -j MASQUERADE

# --- default policy: deny ---
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT   # host-originated egress still needed
```

**Teardown of one engine** must only flush **its** sub-chain:

```bash
iptables -F WINSV_WINN3
iptables -t nat -F WINSV_NAT  # NO — this clears the other engine's NAT too.
```

Correction: NAT must also be per-engine:

```bash
# Per-engine NAT sub-chains
iptables -t nat -N WINSV_NAT_AWG   2>/dev/null || true
iptables -t nat -N WINSV_NAT_WINN3 2>/dev/null || true
ip4t_ensure WINSV_NAT -i awg0     -j WINSV_NAT_AWG
ip4t_ensure WINSV_NAT -i winn3gw0 -j WINSV_NAT_WINN3
ip4t_ensure WINSV_NAT_AWG   -o eth0 -j MASQUERADE
ip4t_ensure WINSV_NAT_WINN3 -o eth0 -j MASQUERADE
```

Then teardown of winn3 is simply `iptables -t nat -F WINSV_NAT_WINN3` — no collateral damage.

### F-4.2 (Critical) — Route table conflicts between `awg0` and `winn3gw0`

Both engines need a default egress. If each does `ip route add default dev <iface>`, the second silently overwrites the first in the main table — the first tunnel becomes a black hole. If they instead use the same non-main table, the isolation is still wrong.

**Fix — policy routing with one table per engine and per-peer source rules:**

```bash
# Register table names once
grep -q '^100 winn3$' /etc/iproute2/rt_tables || echo '100 winn3' >> /etc/iproute2/rt_tables
grep -q '^101 awg$'   /etc/iproute2/rt_tables || echo '101 awg'   >> /etc/iproute2/rt_tables

# Per-engine table has its own default. Never touch main.
ip route replace default dev winn3gw0 table winn3
ip route replace default dev awg0     table awg

# Per-peer source rule installed by the peer provisioning code (not globally!)
ip rule add from 10.10.0.0/24 table winn3 priority 1000
ip rule add from 10.66.66.0/24 table awg   priority 1010
```

**Key principle:** a peer's traffic must select **exactly one** egress engine, chosen by the control plane and reflected in the source address. Do not attempt to load-balance the same peer across engines via table selection — that causes reordering and defeats handshake-based state consistency.

Kansas must return, for each peer, a single `egress_engine ∈ {awg, winn3}`; the data plane refuses to install rules for the other.

### F-4.3 (High) — Undefined firewall marks

`fwmark` is used by both AWG (TUN-related rule exemptions) and winn3-gateway (self-traffic exclusion). If both choose the same mark (e.g. `0x200`), rules can cross-match, producing loops.

**Fix — treat marks as a reserved, centrally documented section:**

```bash
# /etc/winsvpn/marks.env — sourced by all engine unit files
export WINN3_FWMARK=0x200
export AWG_FWMARK=0x100
export XRAY_FWMARK=0x300
# Range reserved for future engines: 0x400-0x7ff
# 0x1-0xff reserved for kernel/tc
```

and in each engine unit:

```ini
EnvironmentFile=/etc/winsvpn/marks.env
ExecStart=/usr/local/bin/winn3-gateway --fwmark ${WINN3_FWMARK} ...
```

Add a startup assertion that refuses to launch if two engines claim the same mark.

### F-4.4 (High) — IPv6 leak

If the DC has native IPv6 and the peers have v6 addresses, and neither tunnel transports v6, peer v6 traffic will exit via the host's v6 default route — a **silent clearnet leak** that bypasses all tunnel accounting.

**Fix — either disable v6 on the host or route it through the tunnels:**

```bash
# If v6 not transported — refuse it entirely.
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1

# Persist
cat >/etc/sysctl.d/90-winsvpn-v6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF

# If v6 IS transported, mirror the v4 policy-routing per engine:
# ip -6 route replace default dev winn3gw0 table winn3v6
# ip -6 rule add from 2001:db8:winn3::/64 table winn3v6 priority 1000
```

Also make the peer provisioning system reject v6 peer addresses unless the engine is v6-capable.

### F-4.5 (Medium) — DNS resolver bind collision

If winn3-gateway and amneziawg-go each run an internal DNS forwarder, both will attempt to bind `127.0.0.53:53` (or `0.0.0.0:53`) on the same host → second listener fails or silently steals the port.

**Fix — distinct loopback and per-engine config:**

```
# winn3-gateway listens on 127.0.0.53:53
# awg (via Unbound instance) listens on 127.0.0.54:53
# XRay's dns_outbound resolves via 127.0.0.55:53
# The host's own systemd-resolved stays on 127.0.0.53 — offset engines to .54/.55.
```

Or, stronger: run each engine in its own network namespace:

```bash
ip netns add winn3
ip link set winn3gw0 netns winn3
ip -n winn3 addr add 10.10.0.1/24 dev winn3gw0

# veth pair into the namespace for host-side policy routing
ip link add veth-winn3 type veth peer name veth-winn3-h
ip link set veth-winn3 netns winn3
ip -n winn3 addr add 169.254.10.2/30 dev veth-winn3
ip -n winn3 route add default via 169.254.10.1
ip addr add 169.254.10.1/30 dev veth-winn3-h

# Firewall/NAT rule keyed on veth-winn3-h (host side)
```

Namespace isolation fully eliminates routing/mark/NAT collisions with other engines on the same host — the strongest fix if the operational team can tolerate it.

### F-4.6 (Medium) — `rp_filter` drops asymmetric flows

With policy routing across multiple interfaces, strict reverse-path filtering (`rp_filter=1`) will drop legitimately asymmetric packets (particularly during handshakes when a return path uses the other TUN).

**Fix — loose mode:**

```bash
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.default.rp_filter=2
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 > "$i"; done

cat >/etc/sysctl.d/90-winsvpn-rpfilter.conf <<'EOF'
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
```

Also ensure `net.ipv4.ip_forward=1`.

### F-4.7 (Medium) — Conntrack table exhaustion under fleet load

Three engines × thousands of peers × multiple flows per peer can overflow default conntrack (often 65536). When full, **new** connections drop silently; existing UDP sessions (AWG handshakes, winn3 keepalives) drop too.

**Fix:**

```bash
sysctl -w net.netfilter.nf_conntrack_max=1048576
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=86400
sysctl -w net.netfilter.nf_conntrack_udp_timeout=120
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=300
sysctl -w net.netfilter.nf_conntrack_buckets=262144
```

Add a Prometheus/Telegraf exporter on `/proc/sys/net/netfilter/nf_conntrack_count` and alert at 60 %.

### F-4.8 (High) — Kansas → data-plane probe channel is not authenticated

If Kansas probes nodes over clearnet HTTP or unauthenticated gRPC over the public IP, an attacker on path (or a hijacked DNS record) can:
- Inject false peer state (create ghost peers, blackhole routes).
- Read node state (peer counts, key fingerprints, geolocation).

**Fix — mTLS with pinned CA on the management plane:**

```bash
# control plane
curl --cert /etc/winsvpn/control-plane.pem \
     --key  /etc/winsvpn/control-plane.key \
     --cacert /etc/winsvpn/node-ca.pem \
     https://<node-fqdn>:9443/admin/health

# node side (server)
openssl s_server -cert node.pem -key node.key -CAfile cp-ca.pem -Verify 1 -accept 9443
```

Restrict the management port (`9443`) to the Kansas control plane's source IP via nftables and require TLS 1.3 only. Never expose the admin endpoint on the same interface as data-plane traffic.

### F-4.9 (High) — systemd unit ordering not enforced → partial bring-up

If `winn3-gateway.service` starts before `network-online.target` or before `winsvpn-firewall.service`, the engine starts and (for a brief period) forwards **without** the firewall being in place. Free clearnet window.

**Fix — explicit ordering and hardening:**

```ini
# /etc/systemd/system/winn3-gateway.service
[Unit]
Description=WinsVPN Winn Protocol v3 Gateway
Wants=network-online.target
After=network-online.target winsvpn-firewall.service
Requires=winsvpn-firewall.service
Before=winsvpn-monitor.service

[Service]
Type=notify
EnvironmentFile=/etc/winsvpn/marks.env
ExecStartPre=/usr/local/sbin/winsvpn-marks-assert.sh
ExecStart=/usr/local/bin/winn3-gateway \
    --config /etc/winsvpn/winn3.yaml \
    --tun winn3gw0 \
    --fwmark ${WINN3_FWMARK} \
    --table winn3
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ReadWritePaths=/var/lib/winsvpn /run/winsvpn

[Install]
WantedBy=multi-user.target
```

And `winsvpn-firewall.service` is `Type=oneshot` + `RemainAfterExit=yes` so `Requires=` behaves correctly.

### F-4.10 (Low/Medium) — TUN MTU not unified

If `winn3gw0` uses MTU 1420 and `awg0` uses MTU 1280, a peer that migrates between engines can see PMTU blackholes. **Enforce a single fleet MTU policy** (I recommend 1280 for both TUNs to tolerate all transport overheads), and enable `net.ipv4.tcp_mtu_probing=1` for safety.

---

## Consolidated Remediation Plan (priority order)

| # | Finding | Severity | Owner | Effort |
|---|---|---|---|---|
| 1 | F-1.1 fail-closed on malformed config | **Critical** | Client | S |
| 2 | F-1.3 atomic interface swap / kill-switch | **Critical** | Client | M |
| 3 | F-2.1 worker path normalization | **Critical** | Web | S |
| 4 | F-3.1 timezone-aware lifetime expiry | **Critical** | Control Plane | S |
| 5 | F-3.3 Argon2id + single-use + TTL secret | **Critical** | Control Plane | M |
| 6 | F-4.1 per-engine iptables chains | **Critical** | Data Plane | M |
| 7 | F-4.2 policy routing per engine | **Critical** | Data Plane | M |
| 8 | F-1.2 TOCTOU snapshot | **High** | Client | S |
| 9 | F-1.4 atomic settings write | **High** | Client | S |
| 10 | F-1.5 bounded fallback | **High** | Client | S |
| 11 | F-2.3 enforce worker on delivery path | **High** | Web/Infra | M |
| 12 | F-2.4 sign SHA256SUMS.txt | **High** | Release Eng | S |
| 13 | F-3.2 idempotent anchored migration | **High** | Control Plane | M |
| 14 | F-3.4 second-factor enrolment | **High** | Control Plane | L |
| 15 | F-4.3, F-4.4, F-4.8, F-4.9 | **High** | Data Plane | M each |
| 16 | F-1.6, F-2.2, F-2.5, F-3.5, F-3.6, F-4.5–7, F-4.10 | Medium | various | S each |

---

## Architectural Recommendations (beyond point fixes)

1. **Introduce a "connection plan" object** as the sole authoritative snapshot of protocol/auth/capability state on the client. Every UI and dispatch path consumes it — no getters that re-read mutable globals.
2. **Move data-plane engines into per-engine network namespaces.** The current co-located design relies on disciplined iptables/marks forever; namespaces make collisions structurally impossible.
3. **Publish a signed release manifest and pin the verification key in the client.** Without this, "checksums" are theatre.
4. **Adopt a formal single-use enrolment token lifecycle** (issue → TTL → single-use → notification), and treat the setup key as a bearer credential that must be paired with device-bound proof-of-possession.
5. **Add invariant tests** to CI: (a) `downloadAssetDecision('//downloads/foo')` rejects; (b) `parse_iso_datetime('2035-01-01T00:00:00')` raises; (c) a second call to `migrate_legacy_lifetime` produces identical expiry; (d) starting winn3 does not flush awg's iptables chains (asserted via `iptables-save` diff).

Implementing items **1–7** in the table above closes every Critical finding. Items **8–15** should be in the same release or the next, with a compensating control (e.g., network ACL restricting the management interface) if any High finding ships out-of-cycle.
