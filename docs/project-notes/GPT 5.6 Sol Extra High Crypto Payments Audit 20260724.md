# GPT 5.6 Sol Extra High — Post-Implementation Security Audit

**Audit date:** 2026-07-24  
**Primary implementation reviewed:** crypto payments, PayPal wallet additions, force-update controls, and the Winn Protocol version seam  
**Claude report reviewed:** `docs/CRYPTO_PAYMENTS_DUAL_MODEL_AUDIT_20260724.md`  
**Audit mode:** source review, focused dynamic reproductions, dependency/CVE review, and existing-test execution  
**Product code modified by this audit:** none

## Executive result

The new payment code does not contain a verified pre-authentication payment-forgery path, hardcoded provider credential, SQL injection, shell injection, or direct private-key disclosure. PayPal webhook verification, BTCPay HMAC verification, parameterized SQL, Decimal/piconero arithmetic, and the existing client configuration validation are generally sound.

The implementation is not ready for production payments yet.

| Severity | Count | Result |
|---|---:|---|
| Critical | 0 | None verified |
| High | 2 | BTCPay invoice provenance/price binding; Monero wallet-RPC least privilege |
| Medium | 10 | Entitlement integrity, public resource amplification, blocking I/O/DB locking, oracle trust, force-update enforcement, and a conditional source-IP trust problem |
| Low | 10 | Robustness, forward-scaling, cleanup, cache variation, and defense-in-depth |
| Functional release blocker | 1 | The Apple Pay/Google Pay browser implementation does not follow the provider APIs |

The highest-priority implementation order is:

1. Add a hub-owned payment-order/entitlement ledger and bind every provider event to it.
2. Enforce authenticated, restricted, loopback-or-TLS Monero wallet RPC.
3. Stop unauthenticated email-only purchases from mutating an existing account.
4. Move provider and wallet network calls out of the single Uvicorn event loop and out of SQLite transactions.
5. Enforce the minimum app version on the server and at the final native-tunnel start boundary.
6. Replace the provisional Apple Pay/Google Pay UI with the documented PayPal wallet flows and perform real sandbox transactions.

## Scope and architecture checked

Only the requested project areas were considered: `android/`, `ios/`, `macos/`, `apple/`, `windows/`, `linux/`, `lib/`, `server/`, `tools/`, `installer/`, `.github/workflows/`, `wins-backend/`, and `web/`. Unrelated repository-root content was ignored.

The implementation currently spans:

- Dart and Flutter for shared client behavior and UI.
- Kotlin/Gradle for Android integration.
- Swift, Objective-C, Xcode, and Network Extension components for iOS/macOS.
- C/C++ and CMake for Windows/Linux native tunnel integration.
- Bash, PowerShell, Python, systemd, Nginx, Docker/Compose, and Inno Setup for deployment and packaging.
- Embedded Python FastAPI, Uvicorn, Pydantic, and SQLite for the control plane and payment functions.
- JavaScript ES modules, Cloudflare Pages Functions/Workers APIs, HTML, and CSS for the public web/payment plane.
- YAML and JSON/JSONC for CI and deployment configuration.

The audit traced each payment from public browser input through the Worker relay, hub API, provider verification, database mutation, account entitlement, and client update/tunnel behavior. It also checked the native applications for newly introduced payment or credential handling.

## High findings

### H-1 — BTCPay grants are not bound to invoices created by this hub

**Vulnerability type and severity:** High — CWE-345 (Insufficient Verification of Data Authenticity), CWE-639-style object/provenance authorization failure, and business-logic authorization failure.

**Location:**

- `server/wins_control_plane_setup_ONETOUCH.sh:7045-7066`
- `server/wins_control_plane_setup_ONETOUCH.sh:8494-8558`
- `server/wins_control_plane_setup_ONETOUCH.sh:10952-11020`

**Impact and exploit scenario:**

The invoice-creation route generates a `hub_order_id`, but neither that ID nor the returned BTCPay invoice ID is recorded in a local order table. The webhook consequently accepts any settled invoice from the configured BTCPay store if its mutable metadata contains a recognized `plan_key`.

For monthly and yearly plans, `crypto_settled_invoice_amount_ok()` accepts any positive USD invoice amount. It also checks the requested invoice amount rather than binding the grant to a locally recorded expected amount and verifying the provider's paid amount.

An operator of another application with legitimate invoice-creation permission on the same BTCPay store—or anyone holding a reused store API credential—could create and settle a low-value invoice whose metadata names a valuable Win's VPN plan. That is valid-authentication abuse with significant entitlement impact, so it is High under the requested rubric. No unauthenticated forged-HMAC route was found.

**Exact code fix:**

Create a durable order before calling BTCPay, update it with the returned provider ID, and allow the webhook to claim only that row:

```python
def create_payment_orders_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payment_orders (
            hub_order_id TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            provider_order_id TEXT UNIQUE,
            plan_key TEXT NOT NULL,
            expected_amount TEXT NOT NULL,
            expected_currency TEXT NOT NULL,
            buyer_email TEXT NOT NULL,
            referral_code TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'creating',
            created_at TEXT NOT NULL,
            settled_at TEXT,
            CHECK (provider IN ('btcpay', 'paypal_wallet', 'monero')),
            CHECK (status IN (
                'creating', 'pending', 'processing', 'settled',
                'expired', 'failed', 'manual_review'
            ))
        )
    """)
```

Before the outbound creation call:

```python
expected = validate_crypto_amount(crypto_price_usd(conn, plan_key))
hub_order_id = secrets.token_urlsafe(24)
conn.execute(
    """
    INSERT INTO payment_orders (
        hub_order_id, provider, plan_key, expected_amount,
        expected_currency, buyer_email, referral_code, status, created_at
    ) VALUES (?, 'btcpay', ?, ?, 'USD', ?, ?, 'creating', ?)
    """,
    (
        hub_order_id,
        plan_key,
        expected,
        normalized_email,
        normalize_referral_code(request.referral),
        utcnow().isoformat(),
    ),
)
```

After BTCPay returns, require a valid invoice ID and atomically bind it:

```python
invoice_id = str(invoice.get("id") or "").strip()
if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", invoice_id):
    raise RuntimeError("BTCPay did not return a valid invoice id")

with get_db() as conn:
    changed = conn.execute(
        """
        UPDATE payment_orders
        SET provider_order_id=?, status='pending'
        WHERE hub_order_id=? AND provider='btcpay' AND status='creating'
        """,
        (invoice_id, hub_order_id),
    ).rowcount
    if changed != 1:
        raise RuntimeError("could not bind the BTCPay invoice")
```

In the webhook, fetch and claim the locally created order before granting:

```python
with get_db() as conn:
    conn.execute("BEGIN IMMEDIATE")
    order = conn.execute(
        """
        SELECT hub_order_id, plan_key, expected_amount, expected_currency,
               buyer_email, referral_code, status
        FROM payment_orders
        WHERE provider='btcpay' AND provider_order_id=?
        """,
        (invoice_id,),
    ).fetchone()
    if not order:
        raise HTTPException(status_code=202, detail="unknown_invoice")
    if order["status"] == "settled":
        return {"status": "duplicate"}
    changed = conn.execute(
        """
        UPDATE payment_orders SET status='processing'
        WHERE provider_order_id=? AND status IN ('pending', 'failed')
        """,
        (invoice_id,),
    ).rowcount
    if changed != 1:
        return {"status": "duplicate"}

metadata = invoice.get("metadata") if isinstance(invoice.get("metadata"), dict) else {}
requested = Decimal(str(invoice.get("amount") or ""))
paid = Decimal(str(invoice.get("paidAmount") or ""))
expected = Decimal(order["expected_amount"])

if (
    str(invoice.get("status") or "").lower() != "settled"
    or metadata.get("hub_order_id") != order["hub_order_id"]
    or metadata.get("plan_key") != order["plan_key"]
    or str(invoice.get("currency") or "").upper() != order["expected_currency"]
    or requested != expected
    or paid < expected
):
    with get_db() as conn:
        conn.execute(
            "UPDATE payment_orders SET status='manual_review' "
            "WHERE provider_order_id=?",
            (invoice_id,),
        )
    raise RuntimeError("BTCPay settlement contract mismatch")
```

Only the email/referral stored in `payment_orders` should be used for provisioning. Do not prefer provider-returned mutable metadata. Restrict `BTCPAY_SETTLED_INVOICE_STATUSES` at line 6911 to `{"settled"}` for standard Greenfield invoices.

### H-2 — Monero wallet RPC can be enabled without authentication or restricted transport

**Vulnerability type and severity:** High when Monero direct checkout is enabled insecurely — CWE-306 (Missing Authentication), CWE-319 (Cleartext Transmission), CWE-284 (Improper Access Control), and least-privilege failure.

**Location:**

- `server/wins_control_plane_setup_ONETOUCH.sh:850-868`
- `server/wins_control_plane_setup_ONETOUCH.sh:7105-7133`
- `server/wins_control_plane_setup_ONETOUCH.sh:7148-7156`

**Impact and exploit scenario:**

The installer treats the URL alone as sufficient to enable Monero. RPC username/password are optional, and `monero_rpc_enabled()` accepts HTTP for any host even though the comment says HTTP is intended only for loopback.

If an attacker gains local access to an unrestricted wallet RPC—or network access to a remotely exposed/plaintext RPC—the attacker may invoke wallet-management/spending operations, steal funds, or replace `create_address` results so customers pay an attacker-controlled address. Local access with significant financial impact is High under the supplied rubric.

**Exact code fix:**

Fail deployment unless the RPC is authenticated, and permit plaintext only on a literal loopback host:

```python
def validate_monero_rpc_configuration() -> None:
    if not MONERO_WALLET_RPC_URL:
        return

    parsed = urllib.parse.urlsplit(MONERO_WALLET_RPC_URL)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
    ):
        raise RuntimeError("invalid Monero wallet-RPC URL")
    if not (MONERO_WALLET_RPC_USER and MONERO_WALLET_RPC_PASS):
        raise RuntimeError("authenticated Monero wallet RPC is required")

    host = parsed.hostname.lower()
    loopback = host == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass

    if parsed.scheme == "http" and not loopback:
        raise RuntimeError("plaintext Monero RPC is permitted only on loopback")
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError("unsupported Monero wallet-RPC scheme")
    if parsed.scheme == "https" and parsed.port not in (None, 443):
        raise RuntimeError("nonstandard remote Monero RPC port is not approved")
```

Call it during process startup and make `monero_rpc_enabled()` depend on successful validation.

Provision a receive-only wallet RPC with explicit authentication and restriction:

```bash
exec monero-wallet-rpc \
  --wallet-file "${MONERO_VIEW_ONLY_WALLET}" \
  --rpc-bind-ip 127.0.0.1 \
  --rpc-bind-port 18083 \
  --rpc-login "${MONERO_WALLET_RPC_USER}:${MONERO_WALLET_RPC_PASS}" \
  --restricted-rpc
```

Keep spend keys outside this online process. If remote RPC is operationally unavoidable, require verified HTTPS or mTLS, disable redirects, firewall the service to the hub, and still use a restricted/view-only wallet.

## Medium findings

### M-1 — An unauthenticated purchase can reduce another customer's entitlement

**Vulnerability type and severity:** Medium — CWE-639 (Authorization Bypass Through User-Controlled Key) and business-logic integrity failure.

**Location:**

- Buyer-controlled email: `server/wins_control_plane_setup_ONETOUCH.sh:8484-8510`
- Buyer-controlled email: `server/wins_control_plane_setup_ONETOUCH.sh:8564-8588`
- BTCPay email extraction: `server/wins_control_plane_setup_ONETOUCH.sh:7031-7043`
- Email-only user selection/expiry replacement: `server/wins_control_plane_setup_ONETOUCH.sh:7639-7684`

**Impact and exploit scenario:**

A buyer can submit any email address. After settlement, the hub selects an existing user solely by that email and replaces the expiration with `now + purchased duration`. Someone who knows a lifetime customer's email can pay for a one-month plan and shorten that customer's entitlement to approximately one month. The attacker does not receive the victim's activation secret, but can corrupt the victim's service entitlement.

**Exact code fix:**

The safe model is to create an unclaimed entitlement for an unauthenticated purchase and require an emailed, single-use claim or an authenticated in-app account binding:

```python
conn.execute("""
    CREATE TABLE IF NOT EXISTS payment_entitlements (
        entitlement_id TEXT PRIMARY KEY,
        account_number TEXT,
        buyer_email TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_reference TEXT NOT NULL,
        plan_key TEXT NOT NULL,
        starts_at TEXT NOT NULL,
        expires_at TEXT,
        status TEXT NOT NULL,
        claim_token_hash TEXT,
        UNIQUE(provider, provider_reference)
    )
""")
```

Until that migration is complete, apply the immediate no-downgrade guard:

```python
existing_expiry = parse_iso_datetime(row["expiration_date"])
purchase_start = max(existing_expiry or now, now)
base_expiry_dt = purchase_start + duration

if existing_expiry and base_expiry_dt < existing_expiry:
    raise RuntimeError("purchase must never reduce an existing entitlement")
```

Do not automatically bind an unauthenticated payment to an existing account by email. A normalized email is a delivery address, not proof of account ownership.

### M-2 — The single-row user model conflates independent purchases, refunds, and providers

**Vulnerability type and severity:** Medium — CWE-840 (Business Logic Errors) and improper state modeling.

**Location:**

- Mutable payment fields on `users`: `server/wins_control_plane_setup_ONETOUCH.sh:4212-4235`
- Payment upsert/overwrite: `server/wins_control_plane_setup_ONETOUCH.sh:7639-7709`
- PayPal stop-event revocation: `server/wins_control_plane_setup_ONETOUCH.sh:10786-10813`
- Reconciliation excludes inactive users: `server/wins_control_plane_setup_ONETOUCH.sh:7786-7804`

**Impact and exploit scenario:**

PayPal subscription, wallet, BTCPay, and Monero purchases overwrite the same plan/reference/expiration fields. A cancellation or refund for one purchase can revoke access that is still supported by another valid purchase. Delayed or out-of-order PayPal stop events are applied without first re-fetching current provider state, and periodic reconciliation scans only locally active users, preventing some false revocations from self-healing.

**Exact code fix:**

Store each provider purchase as an independent entitlement and derive the account status:

```python
def recompute_account_entitlement(conn: sqlite3.Connection, account_number: str) -> None:
    now = utcnow().isoformat()
    row = conn.execute(
        """
        SELECT MAX(expires_at) AS effective_expiry
        FROM payment_entitlements
        WHERE account_number=?
          AND status='active'
          AND (expires_at IS NULL OR expires_at > ?)
        """,
        (account_number, now),
    ).fetchone()

    effective = row["effective_expiry"] if row else None
    status = "active" if effective else "expired"
    conn.execute(
        "UPDATE users SET status=?, expiration_date=? WHERE account_number=?",
        (status, effective, account_number),
    )
```

Cancellation/refund processing must update only the matching `(provider, provider_reference)` row and then call `recompute_account_entitlement()`. Before applying a PayPal stop event, re-fetch the subscription and require a definitive non-active state. Reconciliation should include all rows with a provider subscription ID, not only accounts currently marked active.

### M-3 — Public payment endpoints permit browser-driven and distributed provider-cost amplification

**Vulnerability type and severity:** Medium — CWE-352 (Cross-Site Request Forgery pattern without account authority), CWE-400 (Uncontrolled Resource Consumption), and unsafe HTTP semantics.

**Location:**

- Worker POST handlers: `web/_worker.js:432-459`, `489-520`, `706-729`, `735-757`, `848-880`, `887-925`
- Stateful hub GET: `server/wins_control_plane_setup_ONETOUCH.sh:8332-8362`
- Synchronous PayPal requests: `server/wins_control_plane_setup_ONETOUCH.sh:6500-6558`
- Single Uvicorn worker: `server/wins_control_plane_setup_ONETOUCH.sh:12143-12149`

**Impact and exploit scenario:**

The Worker accepts valid JSON sent as `text/plain` without checking `Origin`. Such a browser request is a CORS "simple request": the hostile page cannot read the response, but the server-side order/invoice/subaddress creation still occurs. This was dynamically reproduced against the handler.

The hub also uses `GET /pay/{option_key}` to obtain a PayPal OAuth token and create a subscription. An attacker can cause GET requests through navigations or embedded resources. Provider calls use blocking `urllib` and retry sleeps inside the sole Uvicorn event loop, so provider slowness can block the control plane.

The hub's persistent per-IP and global limits reduce the impact, so this is not unbounded and Claude's order-creation email-spam subclaim is false. Monero order creation sends no email.

**Exact code fix:**

Require first-party JSON before consuming quota in every Worker POST handler:

```javascript
function requireFirstPartyJson(request) {
  const requestUrl = new URL(request.url);
  const origin = request.headers.get("origin") || "";
  const mediaType = (request.headers.get("content-type") || "")
    .split(";", 1)[0].trim().toLowerCase();
  const fetchSite = request.headers.get("sec-fetch-site") || "";

  if (
    !allowedOrigins.has(requestUrl.origin) ||
    origin !== requestUrl.origin ||
    (fetchSite && fetchSite !== "same-origin")
  ) {
    return json({ error: "forbidden_origin" }, 403, corsHeaders(request));
  }
  if (mediaType !== "application/json") {
    return json(
      { error: "unsupported_media_type" },
      415,
      corsHeaders(request)
    );
  }
  return null;
}
```

Replace the state-changing GET with a POST:

```python
class PayPalCheckoutRequest(BaseModel):
    option_key: str
    referral: str = ""
    turnstile_token: str

@app.post("/pay/paypal/create-checkout")
async def create_paypal_checkout(body: PayPalCheckoutRequest, request: Request):
    require_allowed_browser_origin(request)
    await verify_turnstile(body.turnstile_token, request_origin_ip(request))
    with get_db() as conn:
        enforce_payment_click_limits(conn, request, body.option_key)
    approval_url = await asyncio.to_thread(
        create_paypal_subscription_approval_url,
        plan_id_for(body.option_key),
        normalize_referral_code(body.referral),
        "web",
    )
    return {"approval_url": validated_paypal_approval_url(approval_url)}
```

Cache PayPal OAuth tokens until shortly before `expires_in`, add much smaller provider-specific global limits, and retain hub-side limits because Origin/CORS is not authentication for non-browser clients.

### M-4 — Monero polling performs remote calls while holding database/process capacity

**Vulnerability type and severity:** Medium — CWE-400 and CWE-667 (Improper Locking).

**Location:**

- Database initialization/transactions: `server/wins_control_plane_setup_ONETOUCH.sh:4170-4198`, `4677-4684`
- Settlement sweep: `server/wins_control_plane_setup_ONETOUCH.sh:7333-7445`
- Admin poll route: `server/wins_control_plane_setup_ONETOUCH.sh:11034-11049`

**Impact and exploit scenario:**

`settle_confirmed_monero_orders()` performs up to 200 sequential wallet-RPC calls inside one database context. Schema DML can acquire SQLite's writer lock before those network calls. The same synchronous work runs inside the only Uvicorn event loop. Public callers can create many unpaid orders, making each three-minute sweep longer and delaying account/payment writes and unrelated API requests.

**Exact code fix:**

Claim a bounded batch in a short transaction, close the database, perform RPC concurrently with a small semaphore outside the event loop, then settle each result in a short transaction:

```python
def claim_monero_poll_batch(conn: sqlite3.Connection, limit: int) -> list[dict]:
    lease_until = (utcnow() + timedelta(minutes=5)).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    rows = conn.execute(
        """
        SELECT hub_order_id, subaddress_index, plan_key, amount_atomic,
               buyer_email, referral_code, expires_at
        FROM monero_orders
        WHERE status='pending'
          AND (lease_until IS NULL OR lease_until < ?)
        ORDER BY created_at
        LIMIT ?
        """,
        (utcnow().isoformat(), limit),
    ).fetchall()
    ids = [row["hub_order_id"] for row in rows]
    if ids:
        placeholders = ",".join("?" for _ in ids)
        conn.execute(
            f"UPDATE monero_orders SET lease_until=? "
            f"WHERE hub_order_id IN ({placeholders}) AND status='pending'",
            (lease_until, *ids),
        )
    conn.commit()
    return [dict(row) for row in rows]
```

```python
async def poll_one_monero_order(order: dict, semaphore: asyncio.Semaphore):
    async with semaphore:
        return await asyncio.to_thread(
            monero_received_for_index,
            int(order["subaddress_index"]),
        )
```

For each completed RPC result, use `BEGIN IMMEDIATE` and `UPDATE ... WHERE status='pending' AND lease_until=?`; grant only when exactly one row is claimed. Add a process/DB lease so manual admin polling and the timer cannot overlap.

### M-5 — Invalid webhooks can amplify provider API calls and block the control plane

**Vulnerability type and severity:** Medium — CWE-400.

**Location:**

- OAuth on each PayPal API call: `server/wins_control_plane_setup_ONETOUCH.sh:6518-6536`
- PayPal webhook: `server/wins_control_plane_setup_ONETOUCH.sh:10766-10784`
- BTCPay webhook: `server/wins_control_plane_setup_ONETOUCH.sh:10923-10935`
- Nginx webhook route without a route-specific limit: `server/wins_control_plane_setup_ONETOUCH.sh:12659`

**Impact and exploit scenario:**

An invalid PayPal webhook containing expected headers can trigger a new OAuth request plus a provider-side signature verification request before it is rejected. Those calls are synchronous and lack a webhook-specific ingress/concurrency limit. Distributed traffic combined with provider slowness can consume provider quota and block the single API event loop.

**Exact code fix:**

Add a dedicated Nginx zone and a tighter body limit:

```nginx
limit_req_zone $binary_remote_addr zone=wins_webhooks:10m rate=2r/s;

location /webhook/ {
    client_max_body_size 128k;
    limit_req zone=wins_webhooks burst=10 nodelay;
    proxy_pass http://127.0.0.1:8000;
    include /etc/nginx/snippets/wins-hub-proxy-common.conf;
}
```

Cache the OAuth token under a lock:

```python
_paypal_token_lock = threading.Lock()
_paypal_token = ""
_paypal_token_expires_at = 0.0

def paypal_access_token() -> str:
    global _paypal_token, _paypal_token_expires_at
    now = time.monotonic()
    with _paypal_token_lock:
        if _paypal_token and now < _paypal_token_expires_at - 60:
            return _paypal_token
        body = fetch_paypal_access_token_response()
        token = str(body.get("access_token") or "")
        ttl = max(0, int(body.get("expires_in") or 0))
        if not token or ttl < 120:
            raise RuntimeError("invalid PayPal OAuth response")
        _paypal_token = token
        _paypal_token_expires_at = now + ttl
        return token
```

Run provider verification in a bounded thread/job pool. Keep signature verification mandatory; rate limiting is an additional boundary, not a substitute.

### M-6 — Monero price trust has no provenance, size, freshness, or deviation controls

**Vulnerability type and severity:** Medium — CWE-345 and economic-oracle integrity failure.

**Location:** `server/wins_control_plane_setup_ONETOUCH.sh:7186-7247`

**Impact and exploit scenario:**

The configured endpoint can redirect, responses are read without a byte cap, and any positive numeric value in several loose JSON shapes is accepted. A compromised or misconfigured price source can quote an extremely high XMR/USD price, causing the hub to request a tiny XMR payment for a valuable entitlement.

This is not request-controlled SSRF in the current code; changing the endpoint requires operator/environment control. The genuine risk is trusting one flexible economic oracle without bounds.

**Exact code fix:**

Use exact allowlisted HTTPS sources, a no-redirect opener, a response limit, timestamped quotes, and either a median of independent sources or an operator-reviewed deviation bound:

```python
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

PRICE_ORIGINS = {
    "https://api.kraken.com",
    "https://api.coingecko.com",
}

def fetch_bounded_price(url: str) -> Decimal:
    parsed = urllib.parse.urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.scheme != "https" or origin not in PRICE_ORIGINS:
        raise RuntimeError("unapproved Monero price origin")

    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "WinsVPN-Hub/1.0"},
    )
    with opener.open(request, timeout=10) as response:
        raw = response.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise RuntimeError("Monero price response too large")

    price = extract_xmr_usd_price(json.loads(raw))
    if price is None:
        raise RuntimeError("invalid Monero price")
    return price

def reviewed_monero_price(urls: list[str], previous: Decimal) -> Decimal:
    quotes = sorted(fetch_bounded_price(url) for url in urls)
    if len(quotes) < 2:
        raise RuntimeError("insufficient independent Monero quotes")
    median = quotes[len(quotes) // 2]
    if previous > 0 and abs(median - previous) / previous > Decimal("0.20"):
        raise RuntimeError("Monero quote changed beyond reviewed bound")
    return median
```

Persist quote value, sources, and timestamp with every order so settlement and incident review can reconstruct the exact pricing decision.

### M-7 — Public order creation permits durable provider/database growth

**Vulnerability type and severity:** Medium — CWE-400.

**Location:**

- Broad payment limiter: `server/wins_control_plane_setup_ONETOUCH.sh:6744-6752`
- BTCPay order creation: `server/wins_control_plane_setup_ONETOUCH.sh:8494-8558`
- Monero order creation: `server/wins_control_plane_setup_ONETOUCH.sh:8573-8659`
- Monero schema/no terminal cleanup: `server/wins_control_plane_setup_ONETOUCH.sh:4427-4447`, `4735`

**Impact and exploit scenario:**

The global per-option limit allows up to 1,000 creations per minute. BTCPay invoices, Monero subaddresses, and `monero_orders` rows are durable, and every pending Monero order increases future polling work. A distributed source can create substantial persistent provider/database state without paying.

**Exact code fix:**

Require a first-party intent/Turnstile token, add provider-specific global buckets, and archive terminal orders:

```python
def enforce_provider_creation_limit(
    conn: sqlite3.Connection,
    request: Request,
    provider: str,
) -> None:
    check_rate_limit(
        conn,
        rate_limit_bucket(f"{provider}-create-ip", request_origin_bucket_value(request)),
        5,
        600,
    )
    check_rate_limit(
        conn,
        rate_limit_bucket(f"{provider}-create-global", "all"),
        120,
        60,
    )
```

```python
def archive_terminal_payment_orders(conn: sqlite3.Connection) -> None:
    cutoff = (utcnow() - timedelta(days=180)).isoformat()
    conn.execute(
        """
        INSERT OR IGNORE INTO payment_order_archive
        SELECT * FROM payment_orders
        WHERE status IN ('settled', 'expired', 'failed')
          AND created_at < ?
        """,
        (cutoff,),
    )
    conn.execute(
        """
        DELETE FROM payment_orders
        WHERE status IN ('settled', 'expired', 'failed')
          AND created_at < ?
        """,
        (cutoff,),
    )
```

Do not delete records still needed for late-payment or manual-refund reconciliation.

### M-8 — Force-update enforcement is bypassable and races the first connection

**Vulnerability type and severity:** Medium — CWE-602 (Client-Side Enforcement of Server-Side Security) and state-race/TOCTOU.

**Location:**

- Reconnect paths: `lib/main.dart:3941-3956`, `5441-5472`
- Gate data ingestion: `lib/main.dart:5652-5707`
- Native connection path: `lib/main.dart:8195-8265`
- Toggle-only gate: `lib/main.dart:8426-8440`
- Server advertises but does not enforce: `server/wins_control_plane_setup_ONETOUCH.sh:8291-8302`

**Impact and exploit scenario:**

The UI checks `_appUpdateRequired` before `_connectWithSmartProtocol()`. That function can refresh `/nodes`, discover that an update is required, and still continue to native tunnel start without rechecking. Settings restart and server-switch paths call the connection method without the toggle gate. A modified or offline-cached client can also ignore the advisory value because server verification/config routes do not enforce the minimum.

**Exact code fix:**

Centralize and recheck at the final native-start boundary:

```dart
Future<bool> _blockIfUpdateRequired() async {
  if (!_appUpdateRequired) return false;
  await _promptAppUpdateRequired();
  return true;
}

Future<void> _connectWithSmartProtocol() async {
  if (await _blockIfUpdateRequired()) return;

  // Existing config refresh and key validation...

  // This must run after every awaited operation that can refresh /nodes and
  // immediately before _startTunnelCandidate/native start.
  if (await _blockIfUpdateRequired()) return;

  await _startValidatedTunnel();
}
```

On the hub, reject unsupported versions before issuing or refreshing tunnel credentials:

```python
def require_supported_app_version(app_version: str) -> None:
    minimum = app_update_policy()["min_supported_app_version"]
    current_tuple = parse_exact_app_version(app_version)
    minimum_tuple = parse_exact_app_version(minimum)
    if minimum_tuple and (current_tuple is None or current_tuple < minimum_tuple):
        raise HTTPException(
            status_code=426,
            detail={
                "code": "app_update_required",
                "min_supported_app_version": minimum,
                "update_url": trusted_app_update_url(),
            },
        )
```

Call it from `/verify`, `/free/verify`, configuration refresh, and Double VPN assignment before returning usable credentials. Do not abruptly disconnect an active tunnel from UI code unless leak-safe teardown is guaranteed; server-side credential policy is the authoritative boundary.

### M-9 — The force-update URL accepts any HTTPS host

**Vulnerability type and severity:** Medium — CWE-601 (Untrusted Navigation).

**Location:**

- Generic validator: `lib/local_security.dart:296-308`
- Launch prompt: `lib/main.dart:4089-4107`
- Unvalidated `/nodes` ingestion: `lib/main.dart:5698-5707`
- Admin setter: `server/wins_control_plane_setup_ONETOUCH.sh:10657-10693`

**Impact and exploit scenario:**

The client accepts any credential-free HTTPS URL, including a non-first-party host and nonstandard port. A compromised hub/admin session or device-trusted TLS interception could combine a high minimum version with a phishing/malware download page. The app does not automatically install the download, so Medium—not Claude's High—is consistent with the rubric.

A malformed nonempty hub URL also suppresses the known first-party fallback and then fails at launch.

**Exact code fix:**

Use a dedicated update validator on both sides:

```dart
const Set<String> _trustedUpdateHosts = {
  'winsvpn.org',
  'www.winsvpn.org',
};

Uri validatedAppUpdateUrl(String raw) {
  final uri = validatedHttpsUrl(raw);
  if (
    uri.port != 443 ||
    !_trustedUpdateHosts.contains(uri.host.toLowerCase()) ||
    uri.fragment.isNotEmpty
  ) {
    throw const FormatException('Untrusted application update URL');
  }
  return uri;
}
```

Validate during `/nodes` ingestion and store an empty value on rejection so the first-party fallback is used.

```python
TRUSTED_UPDATE_ORIGINS = {
    ("https", "winsvpn.org", 443),
    ("https", "www.winsvpn.org", 443),
}

def normalize_app_update_url(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.username or parsed.password or parsed.fragment:
        raise HTTPException(status_code=400, detail="invalid update URL")
    port = parsed.port or 443
    if (parsed.scheme, (parsed.hostname or "").lower(), port) not in TRUSTED_UPDATE_ORIGINS:
        raise HTTPException(status_code=400, detail="untrusted update URL")
    return urllib.parse.urlunsplit(parsed)
```

### M-10 — Forwarded client IP is spoofable if direct origin ingress is enabled

**Vulnerability type and severity:** Medium only under the non-default direct-origin condition — CWE-441/trust-boundary error affecting rate limiting and attribution.

**Location:**

- Forwarded-IP trust: `server/wins_control_plane_setup_ONETOUCH.sh:3655-3693`
- Nginx forwarding: `server/wins_control_plane_setup_ONETOUCH.sh:12617-12623`
- Optional global origin exposure: `server/wins_control_plane_setup_ONETOUCH.sh:12980-12990`

**Impact and exploit scenario:**

Nginx copies the incoming `CF-Connecting-IP` header unchanged, then connects to FastAPI over loopback. FastAPI sees a trusted loopback peer and prefers that caller-controlled header over `X-Real-IP`. When the default hidden-origin/Cloudflare-only boundary is disabled, a direct caller can rotate the apparent IP and weaken per-IP payment limits and security attribution.

**Exact code fix:**

Resolve trusted proxy IPs in Nginx and pass only the resolved address:

```nginx
# Generated from Cloudflare's authenticated IP-list source during deployment.
set_real_ip_from 127.0.0.1;
set_real_ip_from ::1;
# set_real_ip_from <each reviewed Cloudflare IPv4/IPv6 CIDR>;
real_ip_header CF-Connecting-IP;
real_ip_recursive on;

proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header CF-Connecting-IP $remote_addr;
```

FastAPI should prefer `X-Real-IP` and never trust an arbitrary client-supplied header solely because Nginx is the immediate peer:

```python
def _trusted_forwarded_client_ip(request: Request) -> str:
    peer = ipaddress.ip_address(request.client.host if request.client else "")
    if not any(peer in network for network in TRUSTED_PROXY_NETWORKS):
        return ""
    candidate = (request.headers.get("x-real-ip") or "").strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""
```

Keep `HIDE_CONTROL_ORIGIN=1` or Cloudflare-only direct ingress as the deployment default.

## Low findings

### L-1 — Event reservation is not an atomic future-safe idempotency claim

**Vulnerability type and severity:** Low in the current deployment — CWE-362 (Race Condition), defense-in-depth/future-scaling.

**Location:** `server/wins_control_plane_setup_ONETOUCH.sh:7609-7625`

The select-then-upsert helper can return `True` to two concurrent callers. A direct two-connection SQLite reproduction confirmed the helper-level race. Claude's claimed current High double-grant/duplicate-account exploit is nevertheless false because the deployed Uvicorn service has one worker, synchronous payment handlers serialize the event loop, and SQLite serializes writers. Existing-account writes also replace rather than add duration.

Replace the helper before adding workers or separate consumers:

```python
def reserve_payment_event(
    conn: sqlite3.Connection,
    event_id: str,
    event_type: str,
    subscription_id: str,
) -> bool:
    now = utcnow()
    lease_until = (now + timedelta(minutes=5)).isoformat()
    row = conn.execute(
        """
        INSERT INTO paypal_events (
            event_id, event_type, paypal_subscription_id, status,
            attempts, updated_at, lease_until
        ) VALUES (?, ?, ?, 'processing', 1, ?, ?)
        ON CONFLICT(event_id) DO UPDATE SET
            event_type=excluded.event_type,
            paypal_subscription_id=excluded.paypal_subscription_id,
            status='processing',
            attempts=paypal_events.attempts + 1,
            updated_at=excluded.updated_at,
            lease_until=excluded.lease_until
        WHERE paypal_events.status='failed'
           OR (
               paypal_events.status='processing'
               AND paypal_events.lease_until < excluded.updated_at
           )
        RETURNING event_id
        """,
        (event_id, event_type, subscription_id, now.isoformat(), lease_until),
    ).fetchone()
    return row is not None
```

### L-2 — Valid non-object JSON causes unhandled Worker exceptions

**Vulnerability type and severity:** Low — CWE-20.

**Location:** `web/_worker.js:136-167`, with dereferences at `454-455`, `507-509`, `723`, `752`, `865`, and `904`.

`readBoundedJson()` accepts `null`, strings, numbers, and arrays. Dynamic tests confirmed JSON `null` throws a `TypeError` in payment and AI handlers.

```javascript
const parsed = JSON.parse(new TextDecoder().decode(body));
if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
  const error = new Error("json_object_required");
  error.status = 400;
  throw error;
}
return parsed;
```

### L-3 — Version parsing accepts malformed values and treats overflow as zero

**Vulnerability type and severity:** Low — CWE-20.

**Location:** `lib/app_update_gate.dart:12-27`, `40-55`; expected fail-open behavior is codified at `test/app_update_gate_test.dart:40-46`.

Use an exact bounded triple:

```dart
List<int>? tryParseExactAppVersion(String raw) {
  final core = raw.trim().split('+').first;
  final match = RegExp(
    r'^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$',
  ).firstMatch(core);
  if (match == null) return null;
  return List<int>.generate(
    3,
    (index) => int.parse(match.group(index + 1)!),
  );
}
```

An invalid fresh response must not clear a previously accepted minimum during the same process.

### L-4 — Explicit `winn/3` and unknown versions silently execute `winn/1`

**Vulnerability type and severity:** Low, forward-looking — CWE-757.

**Location:** `lib/main.dart:2678-2765`, `7870-7909`.

No `winn/3` implementation currently ships, so there is no present post-quantum protocol to downgrade. This is an unsafe future negotiation contract, not a current broken-PQ vulnerability.

```dart
switch (protocolVersion) {
  case 'winn/1':
    break;
  case 'winn/3':
    throw UnsupportedError(
      'This app build does not support Winn Protocol v3. Update required.',
    );
  default:
    throw StateError('Unsupported tunnel protocol version.');
}
```

Do not let the hub advertise `winn/3` until all shipping clients have an authenticated v3 handler and downgrade tests.

### L-5 — Apple deactivation leaves PSK/Xray credentials in Keychain

**Vulnerability type and severity:** Low — CWE-459.

**Location:**

- Storage: `apple/WinsTunnelCore/WinsTunnelConfig.swift:1627-1767`
- iOS deletion: `ios/Runner/AppDelegate.swift:1324-1330`
- macOS deletion: `macos/Runner/MainFlutterWindow.swift:970-976`
- Dart wrapper/caller: `lib/main.dart:1068-1081`, `9979-9992`

The new `WinsTunnelSecretStore` holds the peer PSK and Xray UUID, but deactivation deletes only `WinsClientKeyStore`; Dart also swallows deletion errors. The residual values are device-only and insufficient without the removed private key, so this is cleanup hardening.

```swift
private func deleteClientKeyPairForAccount(
  _ arguments: Any?,
  result: @escaping FlutterResult
) {
  let scope = accountScope(from: arguments)
  var firstError: Error?

  do { try WinsTunnelSecretStore.delete(accountScope: scope) }
  catch { firstError = error }

  do { try WinsClientKeyStore.delete(accountScope: scope) }
  catch { if firstError == nil { firstError = error } }

  if let firstError {
    result(flutterError("APPLE_TUNNEL_CREDENTIAL_DELETE_FAILED", firstError))
  } else {
    result(true)
  }
}
```

Require a `true` result in Dart and surface cleanup failure without logging secret values.

### L-6 — BTCPay checkout navigation is HTTPS-only, not origin-bound

**Vulnerability type and severity:** Low — CWE-601/payment-integrity defense-in-depth.

**Location:** `web/_worker.js:676-698`, `915-925`; `web/index.html:3582-3585`.

A compromised/misconfigured hub or BTCPay response could direct a buyer to a different HTTPS origin. Bind it dynamically to the deployment's configured BTCPay origin:

```javascript
function validatedCheckoutUrl(raw, expectedOrigin) {
  const candidate = new URL(String(raw || ""));
  const expected = new URL(String(expectedOrigin || ""));
  if (
    candidate.protocol !== "https:" ||
    candidate.username ||
    candidate.password ||
    candidate.origin !== expected.origin
  ) {
    throw new Error("invalid_checkout_url");
  }
  return candidate.href;
}
```

Validate first on the hub against `BTCPAY_URL`, repeat in the Worker using a provisioned `BTCPAY_CHECKOUT_ORIGIN`, and have the browser compare the parsed origin rather than use a scheme regex.

### L-7 — Public config cache pins the first caller's CORS origin

**Vulnerability type and severity:** Low — cache-variant correctness/availability.

**Location:** `web/_worker.js:620-660`, `799-842`.

`Vary: Origin` is present, contrary to Claude's report, but the explicit Cache API uses one constant cache key. Dynamic reproduction confirmed that the second allowed origin receives the first origin's `Access-Control-Allow-Origin`.

```javascript
function publicConfigCacheKey(name, request) {
  const origin = request.headers.get("origin") || "";
  const variant = allowedOrigins.has(origin) ? origin : "no-origin";
  return new Request(
    `https://internal-cache.winsvpn.invalid/${name}/${encodeURIComponent(variant)}`,
    { method: "GET" }
  );
}
```

Use this for both wallet and crypto config caches.

### L-8 — Worker migration rate-limit bindings are incomplete

**Vulnerability type and severity:** Low — deployment hardening.

**Location:** `web/wrangler.jsonc:3-75`; binding references at `web/_worker.js:632`, `713`, `742`, `811`, `855`, and `894`.

Only translation and AI bindings are declared. If this Pages project is later migrated to a Worker, payment bindings remain undefined and silently fall back to isolate-local maps.

Add all referenced names. A shared payment namespace is acceptable because the keys already include route prefixes:

```jsonc
{
  "name": "RATE_LIMITER_WALLET_ORDER",
  "namespace_id": "<ACCOUNT_UNIQUE_POSITIVE_INTEGER>",
  "simple": { "limit": 20, "period": 60 }
},
{
  "name": "RATE_LIMITER_WALLET_CAPTURE",
  "namespace_id": "<SAME_PAYMENT_NAMESPACE_ID>",
  "simple": { "limit": 20, "period": 60 }
},
{
  "name": "RATE_LIMITER_MONERO_ORDER",
  "namespace_id": "<SAME_PAYMENT_NAMESPACE_ID>",
  "simple": { "limit": 20, "period": 60 }
},
{
  "name": "RATE_LIMITER_CRYPTO_INVOICE",
  "namespace_id": "<SAME_PAYMENT_NAMESPACE_ID>",
  "simple": { "limit": 20, "period": 60 }
}
```

Cloudflare documents that `namespace_id` is an operator-chosen positive integer, shared IDs share counters for the same key, and binding limits are location-scoped/eventually consistent—not global accounting.

### L-9 — Settled Monero orders without an email remain pending and repeat alerts

**Vulnerability type and severity:** Low operational integrity.

**Location:** `server/wins_control_plane_setup_ONETOUCH.sh:8564-8588`, `7391-7404`.

Require a valid delivery address before minting a subaddress, or issue a privacy-preserving single-use claim token. A paid but unclaimable order must leave the polling queue and alert once:

```python
if not buyer_email:
    conn.execute(
        """
        UPDATE monero_orders
        SET status='manual_review'
        WHERE hub_order_id=? AND status='pending'
        """,
        (hub_order_id,),
    )
    alert_once(conn, f"monero-no-email:{hub_order_id}", severity=1)
    continue
```

### L-10 — Several bounded-input and operational edge cases remain

**Vulnerability type and severity:** Low — CWE-20/CWE-400/operational hardening.

**Location:**

- Unbounded outbound reads: `server/wins_control_plane_setup_ONETOUCH.sh:6504-6506`, `6982-6984`, `7155-7157`, `7235-7237`
- Email regexes: `server/wins_control_plane_setup_ONETOUCH.sh:5981-5986`, `8507-8509`, `8586-8588`
- Unverified event type logged: `server/wins_control_plane_setup_ONETOUCH.sh:10773-10779`
- Wallet capture accepts any syntactically valid provider order: `server/wins_control_plane_setup_ONETOUCH.sh:8435-8482`
- Late Monero payment policy: `server/wins_control_plane_setup_ONETOUCH.sh:7379-7389`

Use bounded response reads and full email matching:

```python
def read_json_response_bounded(response, maximum: int = 1_048_576) -> dict:
    raw = response.read(maximum + 1)
    if len(raw) > maximum:
        raise RuntimeError("provider response too large")
    parsed = json.loads(raw or b"{}")
    if not isinstance(parsed, dict):
        raise RuntimeError("provider response must be an object")
    return parsed

EMAIL_RE = re.compile(
    r"(?=.{3,254}\Z)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)

def normalize_buyer_email(raw: str) -> str:
    value = raw.strip().lower()
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("email contains control characters")
    if not EMAIL_RE.fullmatch(value):
        raise ValueError("invalid email")
    return value
```

Record PayPal wallet order IDs locally before capture. Log only sanitized event types after signature verification. Move expired orders receiving late funds to `manual_review` with a documented refund/claim procedure rather than permanently ignoring them.

## Functional release blocker — Apple Pay and Google Pay are not implemented using their documented flows

**Location:**

- Wallet UI: `web/index.html:3280-3374`
- Permissions policy: `web/_headers:6`
- Worker header mirror: `web/_worker.js:1018-1022`
- Apple association placeholder: `web/.well-known/apple-developer-merchantid-domain-association`

The current page treats Apple Pay and Google Pay as ordinary `paypal.Buttons()` funding sources. It does not load the Apple/Google browser SDKs, call `paypal.Applepay().config()/validateMerchant()/confirmOrder()`, call `paypal.Googlepay().config()/confirmOrder()`, or send wallet tokens to PayPal.

PayPal's current official flows require those APIs:

- [PayPal Apple Pay integration](https://developer.paypal.com/docs/checkout/apm/apple-pay/)
- [PayPal Google Pay integration](https://developer.paypal.com/docs/checkout/apm/google-pay/)

The current `Permissions-Policy: payment=()` also disables the Payment Request feature. Do not expose these wallet methods as production-ready until the documented implementations are complete, the provider-issued Apple association file is deployed byte-for-byte, and real sandbox transactions pass on supported Apple/Google devices.

A compatible policy must be deliberately scoped rather than globally disabled:

```http
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(self "https://www.paypal.com" "https://www.sandbox.paypal.com" "https://pay.google.com"), usb=()
```

Update CSP only for the exact SDK origins required by the completed implementation.

## Claude finding adjudication

| Claude claim | Decision | Correct severity/reason |
|---|---|---|
| Concurrent PayPal event race causes High duplicate accounts/double grants | **Materially false for the current deployment** | The helper is non-atomic, but one synchronous Uvicorn worker and SQLite writer serialization prevent the described current exploit. Keep as Low future-scaling hardening. |
| Force-update URL accepts arbitrary HTTPS | **Real** | Medium, not High: navigation requires a compromised trusted source and does not auto-install software. |
| Force-update gate is porous/client-only | **Real and understated** | Medium; includes a first-connect refresh race and bypassing reconnect paths. |
| Broad AWG newline/config injection | **False positive in the reachable flow** | Strict validators reject CR/LF/NUL and malformed keys/endpoints; locally generated client keys overwrite served values; native backends revalidate. |
| `client_public_key` alone allows AWG injection | **Not currently exploitable** | Optional Low sink-level assertion only. |
| Payment POSTs allow cost abuse | **Real** | Medium. Cross-origin `text/plain` was dynamically reproduced. Persistent hub limits exist, so isolate-local limits are not the only defense. |
| Monero order creation sends spam email | **False** | No email is sent until confirmed settlement. |
| BTCPay monthly/yearly amount validation is weak | **Real** | The deeper issue is High: there is no hub-owned invoice provenance/expected-price record. |
| Monero sweeps can overlap and double-settle now | **False as described** | Current systemd oneshot/single event loop/SQLite serialization prevents it; the real Medium problem is long DB/event-loop blocking. |
| Missing Monero email repeats alerts | **Real** | Low operational issue; paid orders stay pending instead of moving to manual review. |
| Late Monero payments are ignored | **Real policy gap** | Low; require manual-review/refund handling. |
| Monero orders never purge | **Real** | Included in Medium durable-state/resource growth. |
| Single external price source is unsafe | **Real** | Medium economic-oracle risk; not user-controlled SSRF. |
| `winn/3` falls through to v1 | **Real future hazard, not present PQ break** | Low release-gating issue while v3 does not ship. |
| Optional PSK is a cryptographic vulnerability | **False/intentional** | Classical WireGuard/AWG remains cryptographically sound without the optional PSK. |
| Missing TLS certificate pinning is a vulnerability | **Not independently valid** | Standard platform TLS is normal; pinning is optional hardening with rotation/recovery tradeoffs and does not replace server enforcement. |
| Localhost CORS origins are a production vulnerability | **Not meaningful here** | Public, credentialless endpoints expose no user authority through CORS. Separate dev/prod lists for hygiene. |
| Cached CORS response lacks `Vary: Origin` | **Partly false** | `Vary` exists, but the constant Cache API key still pins the first origin. Low correctness bug. |
| CSP sandbox/marketing origins are exploitable | **Not verified** | Current CSP hashes match. Sandbox and marketing origins are intentional deployment choices; reduce them in production where practical. |
| Apple association placeholder is a vulnerability | **False; pre-launch state** | It is a release blocker until replaced and verified, not a secret or exploitable bug by itself. |

## Dependency and supply-chain result

The payment-plane Python pins are:

- FastAPI `0.139.2`
- Uvicorn `0.51.0`
- Pydantic `2.13.4`
- python-multipart `0.0.32`
- python-dateutil `2.9.0.post0`
- tzdata `2026.2`
- Starlette `1.3.1` through the hash-locked transitive dependency set

`pip-audit` against `server/control-plane-requirements.lock` reported **no known vulnerabilities** on 2026-07-24. Starlette `1.3.1` is at or above the fixes for the reviewed 2026 advisories:

- [CVE-2026-54283](https://nvd.nist.gov/vuln/detail/CVE-2026-54283)
- [CVE-2026-54282](https://nvd.nist.gov/vuln/detail/CVE-2026-54282)
- [CVE-2026-48710](https://nvd.nist.gov/vuln/detail/CVE-2026-48710)
- [CVE-2026-48818](https://nvd.nist.gov/vuln/detail/CVE-2026-48818)

This is a time-bounded result, not a guarantee that no future advisory will apply. Keep the hashed lock regeneration on Linux/CPython 3.12, run `pip-audit` in CI, and require review for dependency changes.

The current Dart dependency review found only minor available updates and no identified applicable CVE in the payment/update path. Do not upgrade blindly; regenerate and test platform locks in the controlled release lanes.

## Secret and credential review

No tracked high-confidence private key, live-provider token pattern, or newly hardcoded PayPal/BTCPay/Monero/SMTP/Cloudflare secret was found in the audited implementation. Provider secrets are referenced through environment/configuration variables. No secret value is reproduced in this report.

Gitignored test/deployment credentials were intentionally excluded, consistent with the audit requirement.

## Areas checked with no additional significant finding

- **Android:** No payment-provider secret or native payment processing was added. External purchase visibility is gated for Play builds, and the native URL launcher applies a scheme allowlist. No new significant Android vulnerability was found.
- **iOS/macOS:** No provider secret is held in the application. Native external URL validation remains in place. The one new issue is the Low incomplete deletion of `WinsTunnelSecretStore` recorded above.
- **Windows/Linux clients:** External payment URLs are passed as process arguments rather than shell strings. No new shell injection or provider-secret finding was found.
- **Shared Flutter core:** No payment credentials or wallet keys were added. Force-update and protocol-seam findings are recorded above. The broad AWG injection claim did not survive reachability analysis.
- **Apple tunnel engine:** Private key, PSK, and Xray UUID redaction/restoration is correctly designed around a device-only Keychain item. `AfterFirstUnlock` is intentional for background Packet Tunnel reconnection rather than a standalone vulnerability.
- **Server SQL and command execution:** Reviewed payment queries are parameterized. No payment-derived shell command injection or SQL injection was found.
- **Provider authenticity:** PayPal provider verification and BTCPay HMAC comparison are fail-closed and constant-time where appropriate. The BTCPay defect is authorization/provenance after valid provider authentication, not missing HMAC verification.
- **Cryptographic arithmetic:** Monero uses integer atomic units and `Decimal`, not float. No rounding-based underpayment was verified.
- **Web UI:** Payment/provider strings use safe DOM construction/`textContent`; no payment XSS sink or request-controlled open proxy was found.
- **Deployment/CI:** No new command-order firewall bug or plaintext secret-on-command-line defect was found in the new payment deployment path. The conditional forwarded-IP trust and Monero RPC configuration findings are recorded above.
- **GitHub workflows:** No new workflow credential interpolation or untrusted-code secret exposure was found in the payment changes.
- **`wins-backend/`:** No separate active payment implementation requiring additional findings was present; the operative serverless relay is `web/_worker.js`.
- **Installer/build scripts:** No new privilege-escalation or unsafe file-permission issue attributable to these features was verified.

## Verification performed

- Embedded generated FastAPI `main.py` compiled successfully.
- `bash -n` passed for the control-plane setup script.
- `python3 tools/validate_deployment_scripts.py` passed: 3 roles, 177 heredocs, 22 embedded Python blocks, 37 Bash helpers, and 52 systemd units.
- `python3 tools/website_security_audit.py` passed 50/50 checks.
- `python3 tools/test_rate_limiter_hardening.py` passed 17/17 tests.
- `python3 tools/test_paypal_entitlement_contract.py` passed.
- `flutter test test/app_update_gate_test.dart` passed 6/6 tests.
- Worker ES-module syntax validation passed.
- `pip-audit -r server/control-plane-requirements.lock` reported no known vulnerabilities.
- A focused SQLite concurrency reproduction confirmed that `reserve_paypal_event()` is non-atomic at the helper level; deployment reachability analysis reduced it to Low for the current single-worker architecture.
- A focused Worker reproduction confirmed cross-origin `text/plain` JSON reaches payment side-effect handlers.
- A focused Cache API reproduction confirmed the first allowed Origin is replayed to a later allowed Origin under the constant cache key.
- Focused JSON tests confirmed `null` produces unhandled handler exceptions.

## Missing release tests

Existing tests do not exercise BTCPay creation/settlement, Monero order/late-payment settlement, wallet capture ownership, entitlement merging/refund ordering, Worker Origin/media-type rejection, Cache API CORS variants, checkout-origin binding, or the documented Apple/Google Pay token flow.

Before production enablement, add:

1. Provider-contract tests using recorded, scrubbed fixtures and negative provenance/amount cases.
2. Concurrency tests with multiple workers/processes after the atomic claim/lease implementation.
3. Monero tests for underpayment, split payments, confirmation transitions, late payment, missing email, RPC timeout, and quote deviation.
4. Entitlement tests for overlapping PayPal/BTCPay/Monero purchases and out-of-order refunds/cancellations.
5. Worker tests for hostile Origin, `text/plain`, missing/invalid Turnstile, non-object JSON, cache variants, and hostile checkout origins.
6. Real PayPal sandbox Apple Pay and Google Pay transactions on supported devices, including failure and 3DS/payer-action paths.

## External operational checks not proven by repository review

Repository inspection cannot prove the live Cloudflare WAF/rate-limit deployment, provider dashboard webhook destinations, PayPal wallet onboarding, Apple domain registration, BTCPay store permissions, Monero wallet mode, or Google budget alarms. These must be included in a go-live runbook with screenshots/API exports and a second-person review.

Cloudflare's current binding behavior is documented at [Rate Limiting · Cloudflare Workers](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/): binding counters are location-scoped, permissive/eventually consistent, and not an accounting system. Persistent hub limits and zone WAF controls must remain in the design.
