# Codex Deep Audit Report: Opus 5 (Claude Code Extra High)

- Model Identifier: `opus`
- Reasoning Effort: `xhigh / max`
- Collected: `2026-09-16T10:27:04.411863+00:00`
- Process Exit Code: `0`
- Content Source: `lane report file (/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/opus/docs/evidence/codex_opus_5_audit.md)`
- Usage Metadata: `{"input_tokens": 166, "cache_creation_input_tokens": 259281, "cache_read_input_tokens": 11644595, "output_tokens": 110995, "output_tokens_details": {"thinking_tokens": 34760}, "server_tool_use": {"web_search_requests": 0, "web_fetch_requests": 0}, "service_tier": "standard", "cache_creation": {"ephemeral_1h_input_tokens": 259281, "ephemeral_5m_input_tokens": 0}, "inference_geo": "not_available", "iterations": [{"input_tokens": 2, "output_tokens": 1109, "cache_read_input_tokens": 258065, "cache_creation_input_tokens": 1216, "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 1216}, "type": "message"}], "speed": "standard", "cost": 11.250101749999994}`

## Audit Findings & Exact Fix Implementations

# Win's VPN Ecosystem: Round 33 Independent Security, Correctness and Performance Audit

**Author:** Opus 5 (Claude Code Extra High)
**Audit date:** 2026-09-16
**Workspace:** `/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes/opus`
**Production tree:** never read, never modified.
**Live-site rules honoured:** GET, DNS, TLS and header probes only. Every browser-driven probe ran behind a hard route interlock that aborted every non-GET request. No account created, no payment order minted, no email dispatched, no server state changed.

---

## 1. Executive summary

Thirteen target domains were audited. The codebase is in strong shape: 107 Go packages pass under the race detector, `flutter analyze` reports zero issues, all 59 invariant rulings plus 6 Apple `enforceRoutes` rulings pass, `shellcheck -S error` is clean across all five major deployment scripts, and the live site serves with zero Content Security Policy violations in a real Blink engine.

Ten defects survived verification. Three are High. The headline one is the user-reported bug, and it reproduces.

| ID | Severity | Domain | One-line |
|----|----------|--------|----------|
| W-01 | **High** | Website / payments | Crypto checkout presents **20,794 ms measured** with zero clickable controls and a message that calls a normal load "unavailable". This is the reported bug. |
| W-02 | **High** | Cloudflare Worker | Both payment-config endpoints return `Cache-Control: public, max-age=300` **on their 503 failure path**, so one transient hub blip becomes a 5-minute cached checkout outage at any shared proxy. |
| E-01 | **High** | Browser extensions | Release build is time-bombed: the Chrome/Edge store-identity receipt expires after 72 hours. `python3 extension/build.py` **exits 3 right now**. Chrome and Edge packages cannot be produced. |
| R-01 | Medium | Smart Router (aicore) | `RestrictAddressFamilies=AF_UNIX AF_INET` blocks the `[::1]:8002` vLLM form that `local_gemma_client.py` explicitly accepts, silently forcing every distress decision to the external Gemini API. |
| S-01 | Medium | Data plane server | `ipt6()` swallows every IPv6 firewall failure (`2>/dev/null \|\| true`) while the same file's `apply_disabled_chain` correctly fails closed. The IPv6 default-DROP policy is fail-open. |
| W-03 | Medium | Website | `renderCryptoUnavailable()` is destructive and reachable from a healthy state: it calls `row.replaceChildren()` and wipes an already-built working checkout row. |
| W-04 | Medium | Cloudflare Worker | Unknown `/api/...` paths fall through to the SPA and return **HTTP 200 `text/html`** (411 KB of index.html) instead of a JSON 404. |
| W-05 | Low | Website | `mountInlineCryptoRetry()` mounts the retry control inside a container that is itself `hidden` in the default collapsed state, so it does not achieve the discoverability its own source comment claims. |
| C-01 | Low | Core app (Dart) | One em dash remains in a Dart string literal, violating the stated zero-em-dash invariant. |
| N-01 | Low | DNS | No CAA record on `winsvpn.org`. Any public CA may issue for the domain. |

One informational item: `router/tests/test_router_supply_chain.py` asserts on `git ls-files` and therefore fails in any non-git export of the tree. That is an environment coupling in the test, not a product defect.

---

## 2. Verification matrix: what was actually executed

Every row below was run in this workspace and its output read. Nothing here is inferred.

| Check | Command | Result |
|---|---|---|
| Go protocol engine, race detector | `cd winn_protocol_experimental && go test -race ./...` | **107 packages ok, 0 FAIL, exit 0** |
| Dart static analysis | `flutter analyze --no-pub` | **No issues found (1.8 s), exit 0** |
| Invariant rulings | `bash tools/verify_rulings.sh` | **59/59 invariants + 6/6 Apple enforceRoutes, exit 0** |
| Smart Router suite | `python3 -m pytest router/tests -q` | 421 passed, **1 failed**, 1 skipped (the failure is the `git ls-files` environment coupling) |
| Extension release build | `python3 extension/build.py` | **exit 3, gate 4/4 REFUSED** (finding E-01) |
| Shell deployment scripts | `shellcheck -S error` on control plane, data plane, winn3 gateway, `tools/build_linux_release.sh`, `router/install_aicore_router.sh` | **0 errors across all five** |
| Live site availability | `curl -D` on `https://winsvpn.org/` | HTTP/2 200, 411,186 bytes, HSTS `max-age=63072000; includeSubDomains` |
| Live CSP hash integrity | SHA-256 of every inline `<script>` and `<style>` in the live bytes vs the served CSP | **3/3 match** (ld+json 2,289 B; inline script 170,468 B; style 93,812 B) |
| Live deployed vs local source | `shasum -a 256 web/index.html /tmp/live_index.html` | **byte identical** (`1ab050ec…b70d1`) |
| Real-browser CSP violations | Chrome for Testing **151.0.7922.34**, headless, third parties allowed | **0 CSP violations, 0 page errors** |
| Crypto config endpoint latency | 12 sequential cache-busted GETs | 200 every time, 58 ms to 101 ms |
| Kansas Hub `/nodes` latency | 6 sequential GETs to `sync.winsvpn.org` | 200 every time, 117 ms to 231 ms, 14,271 B |
| Worst-case checkout dead window | Playwright, iPhone viewport, Worker 6 s budget reproduced x3 | **20,794 ms with no interactive control** (finding W-01) |
| Em/en dash census | `grep -rP '[\x{2014}\x{2013}]'` | extension/ **0**, web/index.html **0**, router/*.py **0**, lib/ string literals **2** (one intentional regex class, one violation) |

Tooling versions used: Python 3 (Homebrew), Go (`~/.local/go`), Flutter/Dart (`~/.local/flutter`), shellcheck (Homebrew), jsdom 27-era from `~/node_modules`, `playwright-core` driving the cached Chrome for Testing 151 build.

---

## 3. Finding W-01 (High): the reported crypto payments bug, reproduced and quantified

### 3.1 The report

> "I can't even seem to click the crypto payments button on the live website."

### 3.2 What I first ruled out

Before blaming the application I eliminated the classic total-failure causes, each with a direct measurement:

1. **CSP blocking the inline script.** Ruled out. The live CSP carries `'sha256-4Nuo5ci7F3sOW+YBzr7QzQ1GZqtcJ2dGcv/XqjnL/2E='` and `'sha256-uV+Lf1Fylqf9F1qVJrJAuBzf/a8dp3anqcMr4NbxDp4='`; I hashed the live bytes of both inline scripts and both match exactly. The style hash matches too. Zero inline event-handler attributes, zero `javascript:` URLs.
2. **A full-viewport overlay eating the click.** Ruled out. `.crypto-modal-backdrop` is `position: fixed; inset: 0; z-index: 9999`, but `web/index.html:1179` carries `.crypto-modal-backdrop[hidden] { display: none; }`. A live hit test enumerated every fixed/absolute element covering 90 percent or more of the viewport with `pointer-events` not `none`: the list came back empty.
3. **The button being disabled or covered.** Ruled out. Live computed style on `.crypto-plan-btn`: `display: flex`, `visibility: visible`, `opacity: 1`, `pointerEvents: auto`, `disabled: false`.
4. **A stale deployment.** Ruled out. Local `web/index.html` and the live bytes are byte-identical.
5. **A broken backend.** Ruled out. `/api/site/crypto-config` answers `{"monero_enabled":true,"crypto_enabled":true}` in 58 to 101 ms, and the hub's `/nodes` answers in 117 to 231 ms.
6. **Third-party breakage.** Ruled out. With all third parties loading, zero CSP violations and zero page errors, and the crypto row still built with all three coins enabled.

The fully settled page is healthy. Desktop and mobile both complete the intended path: plan button expands, coin buttons enable, the Monero panel opens.

### 3.3 The actual defect

The failure lives entirely in the **loading window**, and it is a user-experience fail-closed that presents itself as a broken button.

`setupCryptoPayments()` (`web/index.html:6715`) opens by synchronously disabling every coin selector:

```js
cards.forEach((card) => {
  setCryptoCoinSelectors(card, false, false, false);
  card.querySelectorAll(".crypto-retry-button").forEach((button) => {
    button.disabled = true;
  });
});
```

It then runs up to `CRYPTO_CONFIG_ATTEMPTS = 3` sequential fetches with `CRYPTO_CONFIG_BACKOFF_MS = [700, 2100]`. The Cloudflare Worker's `handleCryptoConfig` gives the hub a **6,000 ms** budget (`web/_worker.js`, `setTimeout(() => controller.abort(), 6000)`) and then returns 503. So the client's own 8,000 ms `AbortController` never even fires; each attempt costs the Worker's 6 s.

Worst case: `6000 + 700 + 6000 + 2100 + 6000 = 20,800 ms`.

Independently, the plan-button handler (`web/index.html:6987`) injects this on expansion when the row is still empty:

```js
notice.textContent = translateRuntimeText("Crypto checkout is loading or unavailable. Please retry shortly or choose another payment method.");
```

Put together, a user on a slow path or during a hub hiccup sees, for up to ~21 seconds:

- three greyed-out coin buttons (`disabled`, so **no click event fires at all**, no cursor feedback, and on touch no tooltip),
- a message asserting the checkout may be "unavailable" during what is a completely normal load,
- no spinner, no progress affordance, no enabled control anywhere in the crypto area.

That is precisely "I can't even seem to click the crypto payments button."

### 3.4 Measured proof

Playwright, iPhone 390x844 viewport, the Worker's real 6 s budget reproduced on each of three attempts:

```
first interactive control at 20794 ms -> {"anyCoinEnabled":false,"anyRetryEnabled":true,
  "msg":"Automated crypto checkout is unavailable. Please retry shortly or choose another payment m"}
crypto-config attempts observed: 3
final: {"coins":"btc=OFF,dash=OFF,xmr=OFF", ...}
```

A shorter 5 s delay run captured the mid-flight state directly, showing the exact conflated copy:

```
[immediately after early plan click @214ms] {"expanded":"true","rowKids":1,
  "coins":"btc=OFF,dash=OFF,xmr=OFF","coinTitle":"Checking availability.",
  "rowText":"Crypto checkout is loading or unavailable. Please retry shortly or choose another payment method."}
coin click attempt while loading -> DISABLED: click event never fires
```

`DISABLED: click event never fires` is the literal mechanism behind the report.

### 3.5 Root cause

Three separable mistakes compound:

1. **Latency budget.** Three fully sequential attempts, each bounded by a server-side 6 s budget the client cannot see, with additive backoff. The client's 8 s timeout is dead code because the Worker always answers first.
2. **No busy affordance.** The "known" flag added in a prior round correctly distinguishes `Checking availability.` from `This currency is not available right now.` on the coin `title` attribute and in the tier notice, but a `title` is invisible on touch and the row-level message was never given the same treatment.
3. **Recovery arrives only after total failure.** `renderCryptoUnavailable()` (and with it the only enabled control, the retry button) runs only after all three attempts are exhausted. The user has no escape hatch during the window.

### 3.6 Exact fix

Three targeted edits in `web/index.html`. Each is a complete replacement, no placeholders.

**Edit 1.** Replace the three tuning constants (currently at `web/index.html:6645-6647`):

```js
      const CRYPTO_CONFIG_ATTEMPTS = 3;
      const CRYPTO_CONFIG_BACKOFF_MS = [700, 2100];
      const CRYPTO_CONFIG_TIMEOUT_MS = 8000;
```

with:

```js
      // The Worker gives the hub a 6000 ms budget and answers 503 itself, so a
      // client timeout above 6000 ms was dead code: the response always arrived
      // first. Three sequential attempts at that budget plus backoff produced a
      // measured 20794 ms window in which every control in the crypto area was
      // disabled. The budget below bounds the whole sequence to roughly 7
      // seconds and the recovery control is mounted after the FIRST miss, not
      // after the last.
      const CRYPTO_CONFIG_ATTEMPTS = 3;
      const CRYPTO_CONFIG_BACKOFF_MS = [400, 900];
      const CRYPTO_CONFIG_TIMEOUT_MS = 2600;
      const CRYPTO_LOADING_MESSAGE = "Checking crypto checkout availability.";
      const CRYPTO_UNAVAILABLE_MESSAGE = "Automated crypto checkout is unavailable. Please retry shortly or choose another payment method.";
      // Read by the plan-button expansion handler further down this script so a
      // normal in-flight load is never described to the user as a failure.
      let cryptoConfigResolved = false;
```

**Edit 2.** Replace the whole of `setupCryptoPayments` and its `cryptoSetupInFlight` declaration (currently `web/index.html:6714-6770`, from `let cryptoSetupInFlight = false;` through the closing brace of the function) with:

```js
      let cryptoSetupInFlight = false;

      // Renders the in-flight state: selectors stay disabled (fail-closed and
      // correct, an enabled button that cannot mint an order is worse) but the
      // user is told this is a load, not a failure, and is given a live control.
      function renderCryptoLoading(card) {
        if (!card) return;
        const row = card.querySelector("[data-crypto-row]");
        if (!row) return;
        row.replaceChildren();
        const notice = document.createElement("p");
        notice.className = "crypto-pay-status crypto-pay-loading";
        notice.setAttribute("role", "status");
        notice.setAttribute("aria-busy", "true");
        notice.textContent = translateRuntimeText(CRYPTO_LOADING_MESSAGE);
        row.appendChild(notice);
        const trigger = card.querySelector(".crypto-plan-btn");
        row.hidden = trigger ? trigger.getAttribute("aria-expanded") !== "true" : false;
      }

      async function setupCryptoPayments() {
        if (cryptoSetupInFlight) return;
        const cards = [...document.querySelectorAll("[data-plan-key]")];
        if (!cards.length) return;
        cryptoSetupInFlight = true;
        cryptoConfigResolved = false;
        cards.forEach((card) => {
          setCryptoCoinSelectors(card, false, false, false);
          renderCryptoLoading(card);
          card.querySelectorAll(".crypto-retry-button").forEach((button) => {
            button.disabled = true;
          });
        });
        try {
          let config = null;
          let lastError = null;
          for (let attempt = 0; attempt < CRYPTO_CONFIG_ATTEMPTS; attempt += 1) {
            try {
              config = await fetchCryptoConfigOnce();
              lastError = null;
              break;
            } catch (error) {
              lastError = error;
              // Mount the escape hatch after the FIRST miss. Retrying in the
              // background is still worth doing, but the user must never be
              // left with nothing clickable while it happens.
              cards.forEach((card) => mountInlineCryptoRetry(card));
              const backoff = CRYPTO_CONFIG_BACKOFF_MS[attempt];
              if (backoff === undefined) break;
              await cryptoDelay(backoff);
            }
          }
          if (lastError !== null || config === null) {
            cryptoConfigResolved = true;
            cards.forEach((card) => renderCryptoUnavailable(card, CRYPTO_UNAVAILABLE_MESSAGE));
            return;
          }
          const moneroEnabled = Boolean(config && config.monero_enabled === true);
          const cryptoEnabled = Boolean(config && config.crypto_enabled === true);
          cryptoConfigResolved = true;
          if (!moneroEnabled && !cryptoEnabled) {
            cards.forEach((card) => renderCryptoUnavailable(card, CRYPTO_UNAVAILABLE_MESSAGE));
            return;
          }
          for (const card of cards) {
            const planKey = card.dataset.planKey;
            const row = card.querySelector("[data-crypto-row]");
            if (!row || !planKey) continue;
            try {
              buildCryptoRow(row, planKey, moneroEnabled, cryptoEnabled);
              setCryptoCoinSelectors(card, moneroEnabled, cryptoEnabled);
              clearInlineCryptoRetry(card);
            } catch (_) {
              renderCryptoUnavailable(card, CRYPTO_UNAVAILABLE_MESSAGE);
            }
          }
        } catch (_) {
          cryptoConfigResolved = true;
          cards.forEach((card) => renderCryptoUnavailable(card, CRYPTO_UNAVAILABLE_MESSAGE));
        } finally {
          cryptoSetupInFlight = false;
        }
      }
```

**Edit 3.** In the plan-button expansion handler, replace (currently `web/index.html:6981-6988`):

```js
            if (!row.childElementCount) {
              var notice = document.createElement("p");
              notice.className = "crypto-pay-status";
              notice.setAttribute("role", "status");
              notice.textContent = translateRuntimeText("Crypto checkout is loading or unavailable. Please retry shortly or choose another payment method.");
              row.appendChild(notice);
            }
```

with:

```js
            if (!row.childElementCount) {
              var notice = document.createElement("p");
              notice.className = "crypto-pay-status";
              notice.setAttribute("role", "status");
              // Never conflate "still loading" with "unavailable". A load that
              // has not answered yet is not a failure and must not read as one
              // on a payment page.
              if (cryptoConfigResolved) {
                notice.textContent = translateRuntimeText(CRYPTO_UNAVAILABLE_MESSAGE);
              } else {
                notice.className = "crypto-pay-status crypto-pay-loading";
                notice.setAttribute("aria-busy", "true");
                notice.textContent = translateRuntimeText(CRYPTO_LOADING_MESSAGE);
              }
              row.appendChild(notice);
            }
```

**Edit 4.** Add the busy style next to the existing `.crypto-pay-status` rule in the inline `<style>` block:

```css
    .crypto-pay-loading {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .crypto-pay-loading::before {
      content: "";
      width: 14px;
      height: 14px;
      border-radius: 50%;
      border: 2px solid rgba(255, 255, 255, 0.28);
      border-top-color: rgba(255, 255, 255, 0.92);
      animation: cryptoSpin 0.9s linear infinite;
      flex: none;
    }
    @keyframes cryptoSpin {
      to { transform: rotate(360deg); }
    }
    @media (prefers-reduced-motion: reduce) {
      .crypto-pay-loading::before { animation: none; }
    }
```

### 3.7 Verification

```bash
cd <repo>
python3 web/update_style_csp.py          # regenerate the inline style + script hashes
python3 web/verify_inline_csp.py         # must report every inline hash present in _headers and _worker.js
python3 tools/website_security_audit.py  # expected: 56 PASS, 0 FAIL
```

Then re-run the measurement harness against the edited page with the 6 s budget reproduced three times. Expected result: the first interactive control appears in **under 3,500 ms** instead of 20,794 ms, and the in-flight row reads `Checking crypto checkout availability.` rather than `Crypto checkout is loading or unavailable.`

---

## 4. Finding W-02 (High): 503 payment-config responses are marked publicly cacheable for 5 minutes

### 4.1 Evidence

`web/_worker.js`, `handleCryptoConfig`:

```js
  const headers = {
    ...corsHeaders(request),
    "cache-control": `public, max-age=${cryptoConfigCacheSeconds}`,
    vary: "Origin",
  };
  const result = reachedHub
    ? json({ monero_enabled: moneroEnabled, crypto_enabled: cryptoEnabled }, 200, headers)
    : json({ error: "crypto_not_configured", monero_enabled: false, crypto_enabled: false }, 503, headers);
```

`handleWalletConfig` has the identical shape:

```js
  const result = clientId
    ? json({ paypal_client_id: clientId }, 200, headers)
    : json({ error: "wallet_not_configured" }, 503, headers);
```

`cryptoConfigCacheSeconds` is 300.

### 4.2 Root cause

One `headers` object is built once and reused for both the success and the failure branch. The Cloudflare edge cache is correctly guarded (`if (edgeCache && reachedHub)` / `if (edgeCache && clientId)`), so Cloudflare itself will not store the 503. But the **header still goes to the client**, and per RFC 9111 a 503 is cacheable when it carries explicit freshness information. Any shared forward proxy, corporate cache, or ISP transparent cache between the user and Cloudflare is entitled to store that 503 and replay it to every user behind it for five minutes.

The page's own fetch uses `cache: "no-store"`, which protects the in-page retry from the *browser* cache but does nothing about a shared intermediary.

Consequence: a hub restart lasting two seconds becomes a five-minute crypto-and-PayPal checkout outage for an entire population behind one proxy. This is a plausible independent contributor to the user's report.

### 4.3 Exact fix

In `web/_worker.js`, replace the `handleCryptoConfig` tail:

```js
  const headers = {
    ...corsHeaders(request),
    "cache-control": `public, max-age=${cryptoConfigCacheSeconds}`,
    vary: "Origin",
  };
  const result = reachedHub
    ? json({ monero_enabled: moneroEnabled, crypto_enabled: cryptoEnabled }, 200, headers)
    : json({ error: "crypto_not_configured", monero_enabled: false, crypto_enabled: false }, 503, headers);
```

with:

```js
  // A failure must never be marked publicly cacheable. Cloudflare's own edge
  // cache is already guarded by `reachedHub` below, but the header reaches the
  // client too, and RFC 9111 makes a 503 cacheable precisely because explicit
  // freshness information is present. Any shared forward proxy would otherwise
  // pin a two-second hub blip as a five-minute checkout outage for everyone
  // behind it.
  const headers = {
    ...corsHeaders(request),
    "cache-control": reachedHub
      ? `public, max-age=${cryptoConfigCacheSeconds}`
      : "no-store",
    vary: "Origin",
  };
  const result = reachedHub
    ? json({ monero_enabled: moneroEnabled, crypto_enabled: cryptoEnabled }, 200, headers)
    : json({ error: "crypto_not_configured", monero_enabled: false, crypto_enabled: false }, 503, headers);
```

And the identical change in `handleWalletConfig`:

```js
  const headers = {
    ...corsHeaders(request),
    "cache-control": clientId
      ? `public, max-age=${walletConfigCacheSeconds}`
      : "no-store",
    vary: "Origin",
  };
  const result = clientId
    ? json({ paypal_client_id: clientId }, 200, headers)
    : json({ error: "wallet_not_configured" }, 503, headers);
```

### 4.4 Verification

```bash
# Success path must still be cacheable:
curl -sSI https://winsvpn.org/api/site/crypto-config | grep -i cache-control
# expected: cache-control: public, max-age=300

curl -sSI https://winsvpn.org/api/site/wallet-config | grep -i cache-control
# expected: cache-control: public, max-age=300
```

For the failure path, run the Worker locally with `HOPPY_API_BASE` pointed at a closed port and assert `cache-control: no-store` on the 503. A unit assertion belongs in the website test suite:

```
assert response.status == 503
assert response.headers["cache-control"] == "no-store"
```

---

## 5. Finding E-01 (High): the browser-extension release build is time-bombed on a 72-hour fuse

### 5.1 Evidence

```
$ python3 extension/build.py
build: REFUSING: a native-messaging manifest still names a PLACEHOLDER extension id whose store-listing value is known
gate 1/4: leakscan self-test               ... all cases correct
gate 2/4: copy-honesty self-test           ... all cases correct
gate 3/4: the bridge contract              ... ok (25 cases, 2 implementations)
gate 4/4: native-messaging manifests name the store-listing extension ids
  FAIL stale identity receipt
  firefox: allowed_extensions matches the canonical gecko id companion@winsvpn.org
  FAIL chrome: allowed_origins names 'lnehjdblendkagjbmdclepjalahdhbbn' which is a syntactically valid
       store-id shape, but it is not bound to a current owner-issued identity receipt.
  FAIL edge:   allowed_origins names 'glgihadopbjoandhoihghddecoibcldf' ... same refusal
  result: REFUSED (Chrome/Edge owner-blocked without a current identity receipt)
EXT_BUILD_EXIT=3
```

Receipt state, measured:

```
/var/lib/winsvpn/browser-extension-store-identity.json
created_utc = 2026-09-11T15:15:54Z
age = 4 days, 18:54:30   |   MAX_AGE = 72:00:00   |   STALE = True
```

`tools/native_messaging/render_host_manifest.py:63`:

```python
OWNER_IDENTITY_MAX_AGE = timedelta(hours=72)
```

`tools/native_messaging/render_host_manifest.py:180-186`:

```python
    now = datetime.now(timezone.utc)
    if (
        created.year < 2026
        or created > now + OWNER_IDENTITY_CLOCK_SKEW
        or now - created > OWNER_IDENTITY_MAX_AGE
    ):
        raise OwnerIdentityInvalid("stale identity receipt")
```

The last successful build produced `extension/dist/*.zip` on Sep 14 at 08:47, roughly 65 hours after issuance. Those artifacts are now unreproducible.

### 5.2 Root cause

The receipt exists to prove that a human owner authorized these specific Chrome Web Store and Edge Add-ons listing IDs, and to make it impossible for an automated agent to invent a syntactically valid `[a-p]{32}` substitute. That control is correct and should stay. The external-path requirement, the `O_NOFOLLOW` open, the refusal of any receipt inside the repository, the duplicate-key rejection, and the `chrome_id != edge_id` check are all well built.

The defect is that **freshness is being used to express authorization over an immutable fact**. A published store-listing ID does not change. Applying a 72-hour expiry to it means:

- no CI system can ever build the Chrome or Edge extension,
- a security patch to the extension cannot be shipped unless a human is physically present to re-mint a receipt within a 3-day window,
- every reproducible-build claim about the Chrome and Edge artifacts expires after 3 days.

The security consequence runs the wrong way: the control designed to protect release integrity is now the thing delaying security releases.

### 5.3 Exact fix

Keep every existing property. Add an optional, owner-chosen `expires_utc` with a hard ceiling, and keep the 72-hour behaviour as the default when it is absent. This is strictly backwards compatible: an existing receipt without `expires_utc` behaves exactly as today.

In `tools/native_messaging/render_host_manifest.py`, replace the constants block (currently lines 51-64):

```python
OWNER_IDENTITY_KEYS = (
    "contract",
    "schema_version",
    "authenticated",
    "issuer",
    "issuance_id",
    "created_utc",
    "chrome",
    "edge",
    "firefox",
)
OWNER_IDENTITY_MAX_BYTES = 64 * 1024
OWNER_IDENTITY_MAX_AGE = timedelta(hours=72)
OWNER_IDENTITY_CLOCK_SKEW = timedelta(minutes=5)
```

with:

```python
OWNER_IDENTITY_KEYS = (
    "contract",
    "schema_version",
    "authenticated",
    "issuer",
    "issuance_id",
    "created_utc",
    "chrome",
    "edge",
    "firefox",
)
# Optional and owner-chosen. A published Chrome Web Store / Edge Add-ons
# listing id is an immutable fact, so expressing the owner's authorization over
# it with a 72-hour freshness window meant no CI run and no out-of-hours
# security patch could ever build the Chrome or Edge package. The external-path
# requirement, the O_NOFOLLOW open, the in-repo refusal and the distinct
# chrome/edge check are the controls that actually prevent a synthesized id;
# none of them are relaxed here. When expires_utc is absent the legacy
# 72-hour rule below still applies unchanged.
OWNER_IDENTITY_OPTIONAL_KEYS = ("expires_utc",)
OWNER_IDENTITY_MAX_BYTES = 64 * 1024
OWNER_IDENTITY_MAX_AGE = timedelta(hours=72)
# Ceiling on an owner-chosen validity span, matching the CA/Browser Forum
# baseline maximum certificate lifetime. An owner may choose less; never more.
OWNER_IDENTITY_MAX_VALIDITY = timedelta(days=400)
OWNER_IDENTITY_CLOCK_SKEW = timedelta(minutes=5)
```

Then replace the key-set check and the freshness check inside `parse_owner_identity_document`. Replace:

```python
    parsed = _load_strict_json_object(data, "browser extension store identity")
    if set(parsed) != set(OWNER_IDENTITY_KEYS):
        raise OwnerIdentityInvalid(
            "browser extension store identity fields are incomplete or unexpected"
        )
```

with:

```python
    parsed = _load_strict_json_object(data, "browser extension store identity")
    present = set(parsed)
    required = set(OWNER_IDENTITY_KEYS)
    permitted = required | set(OWNER_IDENTITY_OPTIONAL_KEYS)
    if not required.issubset(present) or not present.issubset(permitted):
        raise OwnerIdentityInvalid(
            "browser extension store identity fields are incomplete or unexpected"
        )
```

and replace:

```python
    created = _parse_utc(
        _exact_str(parsed["created_utc"], "identity created_utc"), "identity created_utc"
    )
    now = datetime.now(timezone.utc)
    if (
        created.year < 2026
        or created > now + OWNER_IDENTITY_CLOCK_SKEW
        or now - created > OWNER_IDENTITY_MAX_AGE
    ):
        raise OwnerIdentityInvalid("stale identity receipt")
```

with:

```python
    created = _parse_utc(
        _exact_str(parsed["created_utc"], "identity created_utc"), "identity created_utc"
    )
    now = datetime.now(timezone.utc)
    if created.year < 2026 or created > now + OWNER_IDENTITY_CLOCK_SKEW:
        raise OwnerIdentityInvalid("stale identity receipt")
    if "expires_utc" in parsed:
        expires = _parse_utc(
            _exact_str(parsed["expires_utc"], "identity expires_utc"),
            "identity expires_utc",
        )
        if expires <= created or expires - created > OWNER_IDENTITY_MAX_VALIDITY:
            raise OwnerIdentityInvalid("identity receipt validity span is invalid")
        if now > expires + OWNER_IDENTITY_CLOCK_SKEW:
            raise OwnerIdentityInvalid("stale identity receipt")
    elif now - created > OWNER_IDENTITY_MAX_AGE:
        raise OwnerIdentityInvalid("stale identity receipt")
```

The two existing test suites that exercise this path (`tools/native_messaging/test_native_host_registration.py` and `tools/test_extension_cross_store_minification_and_chromium_identity_receipt.py`) both assert `OwnerIdentityInvalid("stale identity receipt")` for a receipt older than the window; both keep passing because the legacy branch is untouched. Add these two cases:

```python
def test_owner_receipt_honours_an_owner_chosen_expiry(tmp_path):
    created = datetime.now(timezone.utc) - timedelta(days=30)
    document = _receipt(created_utc=created, expires_utc=created + timedelta(days=365))
    parsed = render_host_manifest.parse_owner_identity_document(document)
    assert parsed["chrome"] != parsed["edge"]


def test_owner_receipt_refuses_a_validity_span_above_the_ceiling(tmp_path):
    created = datetime.now(timezone.utc) - timedelta(days=1)
    document = _receipt(created_utc=created, expires_utc=created + timedelta(days=401))
    with pytest.raises(render_host_manifest.OwnerIdentityInvalid,
                       match="validity span is invalid"):
        render_host_manifest.parse_owner_identity_document(document)
```

### 5.4 Verification

```bash
python3 -m pytest tools/native_messaging/test_native_host_registration.py -q
python3 -m pytest tools/test_extension_cross_store_minification_and_chromium_identity_receipt.py -q
# Re-issue a receipt carrying expires_utc, then:
python3 extension/build.py
# expected: gate 4/4 passes, exit 0, four archives regenerated in extension/dist/
python3 extension/tools/test_chromium_native_identity.py    # expected 22/22
```

---

## 6. Finding R-01 (Medium): the router systemd unit blocks the `[::1]` vLLM endpoint its own client accepts

### 6.1 Evidence

`router/local_gemma_client.py:24`:

```python
INSTALLER_LOOPBACK_HOSTS = {"127.0.0.1", "::1"}
```

`router/local_gemma_client.py:74-76`:

```python
    if hostname == "::1":
        return "http://[::1]:8002"
    return "http://127.0.0.1:8002"
```

`router/wins-edge-router.service.example:51-52`:

```
# Binds 127.0.0.1:8090 only. AF_INET6 was allowed but never used.
RestrictAddressFamilies=AF_UNIX AF_INET
```

The unit is SHA-256 pinned. `router/install_aicore_router.sh:13` carries `CANONICAL_UNIT_SHA256="6dbd9f0eae77a800e6a812faabc44bfa0f31549f9f2920d17da28d3c53e39f29"`, and I confirmed the file hashes to exactly that value.

### 6.2 Root cause

`RestrictAddressFamilies` restricts **every** socket the unit may create, not only the ones it listens on. The comment reasons only about the listener (`--host 127.0.0.1`), and forgot the outbound connection to the vLLM sibling. With `AF_INET6` absent, `socket(AF_INET6, SOCK_STREAM, 0)` returns `EAFNOSUPPORT`.

The audit target itself specifies the topology as "Strict loopback-only binding (127.0.0.1:8002 / [::1]:8002)", and `local_gemma_client.py` validates and normalizes exactly that second form. So an operator who sets `SMART_ROUTER_GEMMA_URL=http://[::1]:8002`, a value the code certifies as legal, gets a router that can never open the socket.

The failure is silent by design. The documented decision order is: local Gemma on the 5060 Ti first, then Google Gemini on failure, then the deterministic scorer. A transport-level `EAFNOSUPPORT` is a local-Gemma failure, so step 3 takes over. Every distress routing decision, together with the node-health telemetry it carries, then leaves the box and goes to an external API, on every distress event, with no operator-visible signal beyond provider-mix counters. That is a privacy regression as well as a latency and cost regression.

### 6.3 Exact fix

In `router/wins-edge-router.service.example`, replace:

```
# Binds 127.0.0.1:8090 only. AF_INET6 was allowed but never used.
RestrictAddressFamilies=AF_UNIX AF_INET
```

with:

```
# Binds 127.0.0.1:8090 only. AF_INET6 stays permitted because
# router/local_gemma_client.py accepts the installer loopback form
# http://[::1]:8002 for the vLLM sibling; without AF_INET6 that configuration
# cannot open a socket and every distress decision silently falls through to
# the external Gemini provider.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

Then update the pin in `router/install_aicore_router.sh:13`:

```bash
readonly CANONICAL_UNIT_SHA256="3058a4363a3fded55c4b3bba02d1a6ee088f5f479a4e289b0070a834ff322caf"
```

That hash is the measured SHA-256 of the edited unit exactly as written above; I computed it from the produced file, I did not estimate it.

The equally valid alternative, if IPv6 is genuinely never wanted on this host, is to keep `AF_UNIX AF_INET` and narrow the client instead:

```python
INSTALLER_LOOPBACK_HOSTS = {"127.0.0.1"}
```

together with removing the `::1` branch in `get_local_url()`. Do one or the other. What must not persist is the current state where two artifacts in the same component disagree about whether IPv6 loopback is supported.

### 6.4 Verification

```bash
shasum -a 256 router/wins-edge-router.service.example
# expected: 3058a4363a3fded55c4b3bba02d1a6ee088f5f479a4e289b0070a834ff322caf
grep -n CANONICAL_UNIT_SHA256 router/install_aicore_router.sh   # must match the line above
python3 -m pytest router/tests/test_aicore_install.py router/tests/test_systemd_provider_independence.py -q
sudo bash router/install_aicore_router.sh --preflight   # read-only gate, must pass
```

On the host, prove the socket family is actually usable:

```bash
sudo systemd-run --uid=aicore --gid=aicore --property=RestrictAddressFamilies='AF_UNIX AF_INET AF_INET6' \
  --pty /usr/bin/python3 -c "import socket; socket.socket(socket.AF_INET6).close(); print('AF_INET6 ok')"
# expected: AF_INET6 ok
```

---

## 7. Finding S-01 (Medium): IPv6 default-DROP on the data plane is fail-open

### 7.1 Evidence

`server/wins_data_plane_setup_ONETOUCH.sh:6706`:

```bash
ipt6() { ip6tables -w 10 "$@" 2>/dev/null || true; }
```

Used at lines 6944 to 6946:

```bash
  ipt6 -P INPUT DROP
  ipt6 -P FORWARD DROP
  ipt6 -P OUTPUT DROP
```

The same file already demonstrates the correct pattern at lines 6320 to 6321, inside `apply_disabled_chain`:

```bash
  "${IP6TABLES_BIN}" -w 10 -P INPUT DROP || return 1
  "${IP6TABLES_BIN}" -w 10 -P FORWARD DROP || return 1
```

### 7.2 Root cause

`2>/dev/null || true` discards both the diagnostic and the exit status. If `ip6tables` is absent, if the `ip6_tables` kernel module is unavailable, or if the call is refused inside a restricted namespace, all three policy changes fail and the script continues as though the IPv6 posture had been established. The preceding `sysctl` calls that disable IPv6 are likewise all suffixed `>/dev/null 2>&1 || true`, so there is no independent guarantee either.

The result is a node whose IPv4 posture is meticulously fail-closed (`WINVPN-*` chains, transaction staging, `cleanup_edge_firewall_transaction` on any mangle failure) sitting behind an IPv6 posture that is established on a best-effort basis and never verified. The exposure is the node's own IPv6 INPUT surface escaping the `WINVPN-*` policy, not client traffic (the tunnel hands out IPv4 only: `Address = 10.8.1.1/16`), which is why this is Medium and not High.

### 7.3 Exact fix

Replace the helper at `server/wins_data_plane_setup_ONETOUCH.sh:6706`:

```bash
ipt6() { ip6tables -w 10 "$@" 2>/dev/null || true; }
```

with:

```bash
# The IPv4 posture on this node is transactional and fails closed on any rule
# error. The IPv6 posture must hold to the same standard: swallowing the exit
# status here meant an absent ip6_tables module, or a refusal inside a
# restricted namespace, left the kernel default-ACCEPT policy in place while
# the script reported success. Diagnostics are preserved rather than discarded.
ipt6() {
  if ! "${IP6TABLES_BIN}" -w 10 "$@"; then
    err "Failed to apply IPv6 firewall rule: $*"
    return 1
  fi
}
```

and replace the three call sites at lines 6944 to 6946:

```bash
  ipt6 -P INPUT DROP
  ipt6 -P FORWARD DROP
  ipt6 -P OUTPUT DROP
```

with:

```bash
  ipt6 -P INPUT DROP || return 1
  ipt6 -P FORWARD DROP || return 1
  ipt6 -P OUTPUT DROP || return 1
  # Read the policy back rather than trusting the write. A node that cannot
  # prove IPv6 is default-DROP must not be allowed to report a healthy posture.
  if ! "${IP6TABLES_BIN}" -w 10 -S 2>/dev/null | grep -qx -- '-P FORWARD DROP'; then
    err "IPv6 FORWARD policy is not DROP after configuration"
    return 1
  fi
```

Because the enclosing function is now able to fail, confirm its caller propagates the status. If the caller currently invokes it bare, change that call site to `configure_ipv6_posture || die "IPv6 posture could not be established"` using the script's existing `die` helper.

### 7.4 Verification

```bash
shellcheck -S error server/wins_data_plane_setup_ONETOUCH.sh   # expected: 0 errors
bash -n server/wins_data_plane_setup_ONETOUCH.sh               # expected: exit 0
```

On a staging node:

```bash
ip6tables -S | grep -E '^-P (INPUT|FORWARD|OUTPUT)'
# expected exactly:
#   -P INPUT DROP
#   -P FORWARD DROP
#   -P OUTPUT DROP
```

Negative test: rename `ip6tables` out of `PATH` on a scratch node and re-run the firewall step. Expected: the script aborts with `Failed to apply IPv6 firewall rule`, instead of completing and claiming success.

---

## 8. Finding W-03 (Medium): the unavailable renderer destroys a healthy checkout row

### 8.1 Evidence

`web/index.html`, the coin-selector click handler:

```js
            if (!triggered) {
              renderCryptoUnavailable(card, "Automated crypto checkout is unavailable. Please retry shortly or choose another payment method.");
            }
```

`renderCryptoUnavailable` begins by disabling every selector and then wiping the row:

```js
        setCryptoCoinSelectors(card, false, false);
        const row = card.querySelector("[data-crypto-row]");
        if (!row) return;
        row.replaceChildren();
```

Reproduced in jsdom against the live bytes. Starting state was healthy (`rowKids: 4`, all three coins enabled, both provider panels present). After one coin click taken while `automatedRow.hidden` was true:

```
rowKids: 2, coins: btc=DISABLED, dash=DISABLED, xmr=DISABLED
rowText: "Automated crypto checkout is unavailable. Please retry shortly or choose another payment method.Retry crypto checkout"
```

A working, fully provisioned checkout was converted into a hard failure state by a single click, with no network request involved.

### 8.2 Root cause

`triggered` is used as a proxy for two different questions at once: "is the provider button present?" and "is the row currently expanded?". The guard is `if (automatedRow && !automatedRow.hidden)`, so a collapsed row takes the `!triggered` branch and is treated as a provisioning failure even when it is fully provisioned.

In the current markup `.crypto-tier-options` and `[data-crypto-row]` are toggled together, so the path is not reachable by ordinary pointer interaction today. It is one markup change, one stylesheet change, or one assistive-technology activation path away from being reachable, and the blast radius is a destroyed payment flow. The correct behaviour when the row is merely collapsed is to expand it, not to declare the checkout dead.

### 8.3 Exact fix

Replace the coin-selector click handler body in `web/index.html` (the `document.querySelectorAll(".crypto-coin-selector-grid .crypto-coin-btn").forEach(...)` block) with:

```js
        document.querySelectorAll(".crypto-coin-selector-grid .crypto-coin-btn").forEach(function (coinBtn) {
          coinBtn.addEventListener("click", function (e) {
            e.preventDefault();
            var coin = coinBtn.getAttribute("data-switch") || "btc";
            var card = coinBtn.closest("[data-plan-key]");
            var automatedRow = card ? card.querySelector("[data-crypto-row]") : null;
            if (!automatedRow) {
              renderCryptoUnavailable(card, CRYPTO_UNAVAILABLE_MESSAGE);
              return;
            }
            // A COLLAPSED row is not a FAILED row. The previous code conflated
            // the two and answered a click on a fully provisioned checkout by
            // calling renderCryptoUnavailable(), which wipes the row with
            // replaceChildren() and disables every selector. Expand instead,
            // and only fall through to the failure renderer when the provider
            // button genuinely is not there.
            if (automatedRow.hidden) {
              var planTrigger = card.querySelector(".crypto-plan-btn");
              if (planTrigger && planTrigger.getAttribute("aria-expanded") !== "true") {
                planTrigger.click();
              } else {
                automatedRow.hidden = false;
              }
            }

            var providerClass = coin === "xmr" ? ".crypto-monero-button" : ".crypto-btcpay-button";
            var providerName = coin === "xmr" ? "monero" : "btcpay";
            var providerBtn = automatedRow.querySelector(providerClass);
            var providerPanel = automatedRow.querySelector("[data-crypto-provider='" + providerName + "']");
            if (!providerBtn) {
              renderCryptoUnavailable(card, CRYPTO_UNAVAILABLE_MESSAGE);
              return;
            }
            if (!providerPanel || providerPanel.hidden) {
              providerBtn.click();
            }
            if (typeof automatedRow.scrollIntoView === "function") {
              automatedRow.scrollIntoView({ behavior: "smooth", block: "nearest" });
            }
          });
        });
```

The `typeof automatedRow.scrollIntoView === "function"` guard also removes a real robustness hazard I hit during testing: in an environment without `scrollIntoView` the original code threw out of the handler after `providerBtn.click()` had already fired, leaving the flow half-applied.

`CRYPTO_UNAVAILABLE_MESSAGE` is the constant introduced in the W-01 fix; apply W-01 first, or inline the literal string.

### 8.4 Verification

```bash
python3 web/update_style_csp.py && python3 web/verify_inline_csp.py
python3 tools/website_security_audit.py    # expected 56 PASS, 0 FAIL
```

Regression assertion, against the built page: expand a plan, confirm `rowKids === 4`, collapse it with a second click on the plan button, then click a coin button. Expected: the row re-expands and the corresponding provider panel becomes visible. Required: `rowKids` never drops below 4 and no coin button becomes `disabled`.

---

## 9. Finding W-04 (Medium): unknown API paths return HTTP 200 HTML

### 9.1 Evidence

```
$ curl -sS -w "http=%{http_code}" https://winsvpn.org/api/site/config
http=200  content-type: text/html; charset=utf-8  content-length: 411186

$ curl -sS -w "http=%{http_code}" https://winsvpn.org/api/site/status
http=200  content-type: text/html; charset=utf-8  content-length: 411186
```

Both return the full SPA index page.

### 9.2 Root cause

The Worker's router dispatches a fixed list of `/api/...` pathnames and everything else falls through to `env.ASSETS.fetch(request)`, which for a single-page-app Pages project resolves to `index.html`. There is no namespace guard, so the asset fallthrough claims the entire `/api/` namespace.

Two concrete consequences. First, a client calling a mistyped or future endpoint and doing `response.json()` receives a JSON parse error on 411 KB of HTML rather than a clean `404`, which makes the failure far harder to diagnose in the field. Second, every one of those responses is a full 411 KB transfer, so a trivial loop over invented `/api/` paths becomes a cheap bandwidth amplifier against the Pages project.

### 9.3 Exact fix

In `web/_worker.js`, immediately before the final asset fallthrough in the `fetch` handler, insert:

```js
    // The asset fallthrough below resolves any unmatched path to index.html,
    // which meant the entire /api/ namespace answered 200 text/html with 411 KB
    // of SPA markup. A client doing response.json() on a mistyped or
    // not-yet-deployed endpoint got a parse error instead of a 404, and a loop
    // over invented /api/ paths was a cheap bandwidth amplifier. The API
    // namespace is closed: unmatched means 404, in JSON, like every other API
    // answer this Worker gives.
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      return json({ error: "not_found" }, 404, {
        ...corsHeaders(request),
        "cache-control": "no-store",
      });
    }
```

Place it after every legitimate `/api/...` branch has been evaluated and before `return env.ASSETS.fetch(request);`.

### 9.4 Verification

```bash
curl -sS -o /dev/null -w "%{http_code} %{content_type} %{size_download}\n" https://winsvpn.org/api/site/config
# expected: 404 application/json;\ charset=utf-8 <small>

curl -sS -o /dev/null -w "%{http_code} %{size_download}\n" https://winsvpn.org/api/site/crypto-config
# expected: 200 45      (the real endpoint must be unaffected)

curl -sS -o /dev/null -w "%{http_code}\n" https://winsvpn.org/
# expected: 200         (the SPA must be unaffected)
```

---

## 10. Finding W-05 (Low): the inline retry control is mounted inside a hidden container

`mountInlineCryptoRetry()` appends its button to `card.querySelector(".crypto-tier-options")`. That element carries the `hidden` attribute in the markup and is only unhidden by the plan-button expansion handler.

The source comment states the intent:

```js
        // The row above is collapsed until the plan button is expanded, so a
        // user looking at four greyed-out coin buttons would never see that
        // retry control. Mirror it next to the coin grid, which is the element
        // the user just tried to click.
```

Measured default state after a hard config failure on a mobile viewport:

```
{"expanded":"false","optsHidden":true,"rowHidden":true,"rowKids":2,
 "coins":"btc=OFF,dash=OFF,xmr=OFF","inlineRetry":true}
```

`inlineRetry` exists in the DOM but `optsHidden` is `true`, so it is not rendered. The premise the comment describes, a user looking at greyed-out coin buttons without a visible retry, cannot occur in the collapsed state because the coin buttons are hidden too. In the expanded state, where the coin buttons are visible, the row-level retry button is visible as well. The mirrored control therefore adds nothing in either state.

This is not harmful, so the fix is cleanup rather than repair. Either drop `mountInlineCryptoRetry` and `clearInlineCryptoRetry` entirely along with their call sites, or make the mount unconditional on visibility:

```js
      function mountInlineCryptoRetry(card) {
        const options = card.querySelector(".crypto-tier-options");
        if (!options) return;
        let inline = options.querySelector(".crypto-inline-retry");
        if (!inline) {
          inline = document.createElement("button");
          inline.type = "button";
          inline.className = "button primary crypto-retry-button crypto-inline-retry";
          inline.addEventListener("click", () => { void setupCryptoPayments(); });
          options.appendChild(inline);
        }
        inline.textContent = translateRuntimeText("Retry crypto checkout");
        inline.disabled = false;
        inline.hidden = false;
        // The container is hidden until the plan button is expanded, so the
        // control this function exists to surface was never actually rendered
        // in the collapsed default state. Unhide the container when there is a
        // recovery action to offer.
        options.hidden = false;
      }
```

Verify with `python3 tools/website_security_audit.py` (expected 56 PASS, 0 FAIL) plus the CSP hash regeneration steps listed under W-01.

---

## 11. Finding C-01 (Low): one em dash remains in a Dart string literal

The stated invariant is zero em dashes outside the exempt regex. I parsed every Dart string literal under `lib/` (excluding comment lines) and found exactly two containing U+2014 or U+2013:

| Location | Content | Assessment |
|---|---|---|
| `lib/main.dart:4866` | `'\s*(?:[-\u2013\u2014]\s*Free\|\(Free\))\s*$'` (shown with the two dash codepoints escaped; the file holds them literally) | **Correct and required.** A regex character class that must match server-supplied node labels using either dash. Leave it. |
| `lib/winn_protocol_dev_session.dart:1654` | `'WINN DEV SESSION: this document ASKS for containment <U+2014> it carries '` (the placeholder stands for a literal U+2014 in the file) | **Violation.** |

The 107 other occurrences under `lib/` are all inside `///` doc comments, which the invariant exempts.

Fix, in `lib/winn_protocol_dev_session.dart:1654`:

```dart
    'WINN DEV SESSION: this document ASKS for containment: it carries '
```

Verification:

```bash
python3 - <<'PY'
import re, pathlib
pats = (re.compile(r"'(?:[^'\\\n]|\\.)*'"), re.compile(r'"(?:[^"\\\n]|\\.)*"'))
bad = []
for p in sorted(pathlib.Path('lib').rglob('*.dart')):
    for i, line in enumerate(p.read_text(encoding='utf-8').splitlines(), 1):
        if line.lstrip().startswith('//'):
            continue
        for pat in pats:
            for m in pat.finditer(line):
                if '\u2014' in m.group(0) or '\u2013' in m.group(0):
                    bad.append(f"{p}:{i}")
print(bad)
PY
# expected: ['lib/main.dart:4866']   (the intentional regex class only)

flutter analyze --no-pub        # expected: No issues found!
bash tools/verify_rulings.sh    # expected: all 59 invariant checks passed
```

---

## 12. Finding N-01 (Low): no CAA record on winsvpn.org

```
$ dig +short winsvpn.org CAA
(empty)
```

The live certificate is issued by Google Trust Services (`CN=WE1`, valid 2026-09-01 to 2026-11-30), consistent with Cloudflare's universal SSL. With no CAA record, any publicly trusted CA is permitted to issue for the domain, so a successful domain-control-validation attack against any one of roughly a hundred CAs yields a trusted certificate.

Fix, added at the Cloudflare DNS zone for `winsvpn.org`:

```
winsvpn.org.  3600  IN  CAA  0 issue "pki.goog"
winsvpn.org.  3600  IN  CAA  0 issue "letsencrypt.org"
winsvpn.org.  3600  IN  CAA  0 issuewild ";"
winsvpn.org.  3600  IN  CAA  0 iodef "mailto:security@winsvpn.org"
```

Include `letsencrypt.org` alongside `pki.goog` because Cloudflare Universal SSL may rotate between backing CAs; omitting it risks a renewal failure. Set `issuewild ";"` only if no wildcard certificate is in use; verify first.

Verification:

```bash
dig +short winsvpn.org CAA
# expected: the four records above

# Confirm renewal is unaffected 24 hours later:
echo | openssl s_client -connect winsvpn.org:443 -servername winsvpn.org 2>/dev/null \
  | openssl x509 -noout -issuer -dates
```

Apply this to `winsvpn.com` and `sync.winsvpn.org` as well.

---

## 13. Platform-by-platform findings

### 13.1 Windows (x64, ARM64): no defects found

The privileged split between `WINS_TUNNEL_SERVICE_CORE` and the unprivileged UI is the strongest single piece of native code in this tree.

**Pipe DACL.** `windows/runner/windows_tunnel_service_main.cpp:735` uses `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`. Protected (`P`, no inheritance), full control to LocalSystem and BUILTIN\Administrators, read/write to Interactive Users. Created with `PIPE_REJECT_REMOTE_CLIENTS` and `FILE_FLAG_FIRST_PIPE_INSTANCE`, which blocks both remote SMB access and name-squatting by a pre-created pipe.

**Caller authorization.** `AuthorizePipeClientBeforeRead` runs **before** any header or payload read, so an unauthorized client cannot occupy the single pipe instance on a timed wait. `IsAuthorizedAppPipeClient` layers: active-console-session match via `WTSGetActiveConsoleSessionId` and `ProcessIdToSessionId`; `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`; `GetNamedPipeClientProcessId` rechecked **before and after** `QueryFullProcessImageNameW`, which brackets the PID-reuse window around the image-path read; `GetExitCodeProcess` liveness; `SamePath` against `ModuleDirectory()\wins_vpn.exe`; then `ImpersonateNamedPipeClient` with a token-session match and explicit rejection of `WinLocalSystemSid`, `WinLocalServiceSid` and `WinNetworkServiceSid`; then `RevertToSelf`, whose return value is required for the authorization to hold.

**Role separation.** `PipeClientRole::kElevatedAdmin` is authorized for `Command::kStatus` only; `kStart` and `kStop` require `kInstalledApp`. Checked after the header read, which is the earliest point the command is known.

**Client side.** `windows/runner/windows_tunnel_backend.cpp:1868` opens with `FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, capping the server at identification-level impersonation.

**System binary resolution.** `SystemExecutablePath` (line 337) resolves through `GetSystemDirectoryW`, and `sc.exe` is invoked via that absolute path and `Quote()`-wrapped. No unqualified system binary reached `RunCommand`.

**Job objects.** All three spawn sites (lines 375, 1987, 3595) set `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` via `SetInformationJobObject(JobObjectExtendedLimitInformation)` before `AssignProcessToJobObject`, with the assignment failure checked. Child cleanup is guaranteed on handle close.

**Memory.** Every `ConvertStringSecurityDescriptorToSecurityDescriptorW` and `ConvertSidToStringSidW` allocation in the file is matched by a `LocalFree` on both the success and the error path, including the awkward cases in `WriteBytesSecureAtomic`, which frees the descriptor after the 32-attempt `CREATE_NEW` loop regardless of outcome.

**WOW64 and ARM64.** No `IsWow64Process2` handling is present, and none is needed: `GetSystemDirectoryW` is correct for a native x64 process and for a native ARM64 process, and the only system binaries invoked (`sc.exe`, `netsh`) exist in both `System32` and `SysWOW64`. There is no 32-bit x86 runner configuration in `windows/CMakeLists.txt`, so the `Sysnative` redirection case does not arise. **If a 32-bit x86 target is ever added**, `SystemExecutablePath` must switch to `Wow64DisableWow64FsRedirection` or to the `%WINDIR%\Sysnative` alias for any 64-bit-only tool. I am flagging that as a forward constraint, not a present defect.

One observation, not a finding: `nMaxInstances` is 1, so a local interactive user could in principle connect-and-hold to starve the legitimate UI. The design already mitigates this well (`PIPE_NOWAIT`, the bounded `ReadPipeExact` deadline, and rejection before any read), and the remaining window is small enough that closing it would cost more complexity than it buys.

### 13.2 Linux (x64, ARM64): no defects found

**Root custody.** `validate_root_owned_path` (`linux/runner/linux_tunnel_backend.cc:1465`) canonicalizes with `readlink -f` falling back to `realpath`, then walks **every** ancestor to `/`, requiring `uid == 0` and `(mode & 0022) == 0` at each level. Because the walk operates on an already-canonical path, the string-based parent derivation (`${vrp_check%/*}`) cannot be subverted by a symlink. `stat -Lc` failing on a non-GNU system returns 65, which is a refusal. Correct and fail-closed. It is invoked on both `BUNDLE_DIR` (lines 1552, 2538) and `BPF_HELPER` (line 2542).

**eBPF helper identity.** Lines 2044 and 2052 verify `readlink -f /proc/$bpf_pid/exe` equals the expected absolute helper path, re-checking after the spawn. The same pattern guards the Xray process at line 1589.

**Signal handling.** `linux/runner/main.cc` registers `SIGHUP`, `SIGINT` and `SIGTERM` through `g_unix_signal_add`, and handles `SIGQUIT` through a `sigaction` that forwards to `SIGTERM` via `ForwardQuitToTermination` (GLib provides no `SIGQUIT` source). The previous handler is restored on teardown. All four paths reach `ShutdownLinuxTunnelBackend`.

**Process containment.** `RunArgv` uses `POSIX_SPAWN_SETPGROUP`, non-blocking pipe reads, a 15-second monotonic deadline, a `poll` loop with `WNOHANG` `waitpid`, then `kill(-pid, SIGTERM)` to the whole process group followed by `SIGKILL`, returning 124 on timeout. No orphaned children, no blocked reader.

**shellcheck.** `tools/build_linux_release.sh` reports zero errors at `-S error`.

### 13.3 macOS and iOS/tvOS: no defects found

**Route posture.** `bash tools/verify_rulings.sh` runs six dedicated Apple checks and all six pass:

```
RULINGS(apple): ok   REQUIRE macos/Runner/RouteAudit.swift :: static let enforceRoutes = true
RULINGS(apple): ok   FORBID  macos/Runner/RouteAudit.swift :: static let enforceRoutes = false
RULINGS(apple): ok   REQUIRE macos/Runner/MainFlutterWindow.swift :: tunnelProtocol.enforceRoutes = WinsMacRoutePosture.enforceRoutes
RULINGS(apple): ok   FORBID  macos/Runner/MainFlutterWindow.swift :: enforceRoutes = false
RULINGS(apple): ok   REQUIRE ios/Runner/AppDelegate.swift :: tunnelProtocol.enforceRoutes = true
RULINGS(apple): ok   FORBID  ios/Runner/AppDelegate.swift :: enforceRoutes = false
```

`ios/Runner/AppDelegate.swift:1589-1590` sets both `enforceRoutes = true` and `excludeLocalNetworks = true` together, and `WinsRoutePosture` requires both to match, with the source documenting why setting `enforceRoutes` alone produces the local-capture deadlock.

**Memory ceiling.** `ios/PacketTunnel/PacketTunnelProvider.swift:1253` pins `winnStrictPhysicalFootprintCeilingBytes = 15 * 1024 * 1024`. The watchdog samples `TASK_VM_INFO.phys_footprint`, which is the figure jetsam actually accounts, and issues `cancelTunnelWithError` with code 1038 on breach. `startWinnMemoryWatchdog` is armed at five distinct entry points (lines 317, 1729, 1959, 2358, 2602), covering initial datapath proof, standalone convergence and each reconnect path, so AWG, Xray and Winn sessions are all protected.

**Keepalive.** `apple/WinsTunnelCore/WinsTunnelConfig.swift:1042-1056`: default 25 s, floor 15 s, ceiling 120 s, clamped with `min(max(parsed, floor), ceiling)`. That sits squarely in the 20 to 25 s band the mobile-resilience target specifies, holds CGNAT UDP bindings whose carrier timeouts run 20 to 30 s, and stays far enough above the 5 s figure that would pin the radio out of RRC Idle.

**MTU.** `WinsTunnelConfig.swift:1027` defaults to 1,280 and validates through `Self.validMTU(mtu)`.

### 13.4 Android and Android TV: no defects found

**Leanback compatibility.** `android/app/src/tv/AndroidManifest.xml` declares both `android.software.leanback` and `android.hardware.touchscreen` with `android:required="false"`, as **direct children of `<manifest>`**. The source comment records the measured aapt2 failure that forced this placement, which is the correct diagnosis: a `<uses-feature>` nested in `<application>` is rejected outright and never reaches the merged manifest.

**Launcher categories.** The TV `MainActivity` intent-filter carries both `android.intent.category.LAUNCHER` and `android.intent.category.LEANBACK_LAUNCHER`, so phone playability is preserved while the leanback launcher still lists the app. `android:banner="@drawable/banner"` is set on `<application>`. The two camouflage activity-aliases are removed with `tools:node="remove"`, which is right: a D-pad remote has no focus handling on the decoy calculator surface and the disguise would lock a TV user out permanently.

**VPN binding contract.** `android/app/src/main/AndroidManifest.xml:208-222` is exactly the shape the platform enforces: `android:permission="android.permission.BIND_VPN_SERVICE"` plus an `<action android:name="android.net.VpnService"/>` intent-filter, with `android:exported="false"` (correct, since the system is exempt from exported gating for this permissioned binding), `android:foregroundServiceType="specialUse"`, `android:stopWithTask="false"`, and the `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` property that API 34+ requires. The duplicate `org.amnezia.awg.backend.GoBackend$VpnService` from the bundled AAR is stripped with `tools:node="remove"`, and so is `androidx.profileinstaller`'s exported `ProfileInstallReceiver`, which closes a genuine gap where the merged release manifest exported a component neither source manifest declared.

**Socket protection.** `VpnTunnelService.kt:2987` and `:3473` route both call shapes through `protect()`. `AwgSocketProtection.kt` fails closed with an `IOException` when `protectedCount == 0`, so a protection pass that silently protected nothing cannot be mistaken for success. That is the correct guard against the routing loop.

**Network handoff.** `registerNetworkHandoffCallback` guards re-entry on `networkCallback != null`, builds a `NetworkRequest` with `NET_CAPABILITY_INTERNET` and `NET_CAPABILITY_NOT_VPN` (the `NOT_VPN` capability is essential, otherwise the tunnel's own interface would feed the callback and loop), implements all four of `onAvailable`, `onLost`, `onCapabilitiesChanged` and `onLinkPropertiesChanged`, and `unregisterNetworkHandoffCallback` nulls the field in a `finally`. `setUnderlyingNetworks` return values are checked at lines 3827 and 3837.

### 13.5 Browser extensions: one High finding (E-01), otherwise clean

**Service worker lifecycle.** `extension/src/background/background.js` is correct MV3. Every listener (`onInstalled`, `onStartup`, `onAlarm`, `onMessage`, `permissions.onRemoved`, `permissions.onAdded`, and `installProxyAuth`'s `onAuthRequired`) is registered synchronously at top level before any `await`. `ensureAlarm()` and `startReady()` also run on bare module evaluation, covering revival by an event that is neither install nor startup. `ALARM_PERIOD_MINUTES = 1.0` (`extension/src/core/constants.js:60`) is above the Chrome MV3 packed-extension minimum, so the alarm reliably revives a worker Chrome terminated after 30 s idle.

**Initialization retry.** `ready()` caches one promise, and on rejection nulls the cache before rethrowing, so the next caller retries instead of latching a permanent failure. `ensureAlarm()` wraps `alarms.create` in both a `try/catch` and a `.catch()` on the promise form, which is needed because the API is callback-based on some engines and promise-based on others.

**Message origin.** `if (!sender || sender.id !== api.runtime.id) return;` returns `undefined` rather than `true`, closing the channel on a foreign sender. There are no content scripts and no `externally_connectable`, so no web page has a channel at all.

**Permissions.** The shipped Chrome, Edge and Firefox manifests each declare `webRequest` and `webRequestAuthProvider`. I verified against current MDN that this is correct for Firefox MV3, not a Chromium-only artifact: Firefox continues to support `webRequestBlocking` in MV3 **and** provides `webRequestAuthProvider` for cross-browser compatibility. Both adapters genuinely use `webRequest.onAuthRequired` with `['asyncBlocking']` (`extension/src/adapters/firefox.js:165`, `extension/src/adapters/chromium.js:233`), so the permission is earned rather than speculative. `optional_host_permissions: ["<all_urls>"]` keeps `<all_urls>` out of the install-time prompt.

**Extension-pages CSP.** `script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'self'; style-src 'self'`. `connect-src 'none'` is a strong choice: the extension UI cannot originate network requests at all.

**Dash compliance.** Zero U+2014 and zero U+2013 across `extension/src`, `extension/manifest` and `extension/tools`.

**Gates 1 through 3.** Leakscan, copy-honesty and the bridge contract all pass their self-tests. The bridge contract runs 25 cases against two independent implementations and against each other. Gate 4 is finding E-01.

### 13.6 Servers: one Medium finding (S-01), otherwise clean

**SQLite.** `get_db()` at `server/wins_control_plane_setup_ONETOUCH.sh:6481-6486` sets `busy_timeout=10000`, then **reads back the row returned by `PRAGMA journal_mode=WAL`** and raises when it is not `wal`, then sets `synchronous=NORMAL` and `foreign_keys=ON`. Reading the returned row rather than trusting the statement is the correct check; a `PRAGMA journal_mode` that silently declines (a read-only volume, an active reader on a non-WAL file) returns the old mode without raising. The same verified pattern repeats at lines 7289-7302 (with a 30 s busy timeout), 31962-31967 and 32622-32627.

**Dedicated chains.** Every firewall rule I traced is staged into owned `WINVPN-*` chains (`WINVPN-MANGLE-FORWARD`, `WINVPN-HUB-INPUT`, `WINVPN-CORE-INPUT`, `WINVPN-CORE-FORWARD`, `WINVPN-CORE-EGRESS`, `WINVPN-CORE-AUTH`). `append_mangle` aborts and calls `cleanup_edge_firewall_transaction` on any staging failure. No host rule is flushed.

**MSS clamping.** `server/wins_data_plane_setup_ONETOUCH.sh:7213-7219` clamps to `--set-mss 1240` on both directions of `awg0`, `winn3gw0` and `amn0`, gated by `-m tcpmss --mss 1241:65535` so an already-smaller MSS is left alone, followed by a general `--clamp-mss-to-pmtu`. With the 1,280-byte tunnel MTU this is arithmetically exact for IPv4 (1280 minus 20 IP minus 20 TCP equals 1240). The core server carries the matching rule at line 7372, and its three `MTU = 1280` declarations are consistent. This is the right configuration for a 464XLAT or NAT64 carrier path: 1,280 is the IPv6 minimum link MTU, so the tunnel payload survives CLAT encapsulation without needing PMTUD to work, which is exactly what eliminates the black hole.

The IPv6 MSS question does not arise, because the tunnel is IPv4-only (`Address = 10.8.1.1/16`) and IPv6 is disabled on the node. I verified that before concluding it, since an MSS of 1,240 applied to IPv6 would be wrong by 20 bytes and would reintroduce the black hole this configuration exists to prevent.

**Double VPN core.** `server/wins_core_server_setup_ONETOUCH.sh:7319-7322` implements the egress boundary fail-closed:

```
-A WINVPN-CORE-FORWARD -i ${CORE_INGRESS_IFACE} -j WINVPN-CORE-EGRESS
-A WINVPN-CORE-EGRESS -s ${CORE_INGRESS_CIDR} -o ${CORE_EXIT_IFACE} -j RETURN
-A WINVPN-CORE-EGRESS -s ${CORE_INGRESS_CIDR} -o ${CORE_EXIT_IFACE_PREFIX}+ -j RETURN
-A WINVPN-CORE-EGRESS -j DROP
```

Traffic arriving on the ingress interface may leave only through an encrypted exit; everything else is dropped, and the `DROP` is the last rule rather than a policy default, so it cannot be bypassed by a later insertion. The underlay-bypass and unencrypted-leak cases are both closed.

**Double VPN enrollment leases.** `double_vpn_enrollment_leases` is created with an `expires_at` index, expired rows are deleted before insert (line 14132), and a concurrent preparation returns `409` with `X-Wins-Error-Code: double_vpn_enrollment_in_flight` and `Retry-After: 5` (lines 14156-14157). Lease cleanup at line 14171 runs inside the mutation path.

**shellcheck.** Zero errors at `-S error` on the control plane (1.89 MB), data plane (498 KB), winn3 gateway installer (250 KB), Linux release builder and router installer.

### 13.7 Protocols and core app: no defects found

**Go engine.** 107 packages pass under `-race`, exit 0, no data races and no failures. Includes `winn3/session`, `winn3/core`, `winn3/carrier`, `winn3/driver`, `winn3/tun`, `winn3/netlab` and `winn3/redteam`.

**Anti-downgrade.** `lib/winn_protocol_dispatch.dart` builds the enforcement out of generation-bound, single-use grants. A v1 compatibility authorization is scoped to the exact selection generation that produced it, is consumed on use, and is destroyed outright by a new or malformed generation (line 2067: "A new or malformed generation destroys every earlier grant"). Refusal paths explicitly stop the session rather than falling back: "connection was stopped rather than downgraded" (line 3197), "stopped rather than downgraded to AmneziaWG or Xray" (line 3053). The v1 ordering the target specifies, AmneziaWG attempted first with XRay/VLESS-WS only as a runtime fallback after AWG handshake failure, is preserved, and a standalone session taking the carrier path is identified as the silent downgrade to refuse (line 3549).

**Client MTU and keepalive.** `lib/main.dart:271-272` pins `_directAwgMtu = 1280` and `_stealthTransportMtu = 1280`, and line 5723 overwrites any inbound value with those constants rather than trusting the control plane. The generated peer stanza carries `PersistentKeepalive = 25` (line 5944). Client, Apple core and server agree.

**Static analysis.** `flutter analyze --no-pub` reports zero issues.

### 13.8 Smart Router on RTX 5060 Ti: one Medium finding (R-01), otherwise clean

**HMAC construction.** `router/security.py:387-405` signs `METHOD\nPATH[?QUERY]\nTIMESTAMP\nNONCE\nSHA256_HEX(BODY)`. The raw query-string bytes from the ASGI scope are carried verbatim into the signature, so a query-parameter rewrite in flight breaks the MAC.

**Admission order.** `RouterSecurityMiddleware.__call__` enforces, in this order: protected-path membership, configuration validity (503 on failure), declared `Content-Length` against the cap (413), actually-streamed bytes against the cap (413), header shape via `_NONCE_RE` and `_SIGNATURE_RE`, timestamp window, `hmac.compare_digest` against the expected signature (401), rate limit (429), and only then the durable replay journal. A replayed nonce yields 401; a journal that cannot answer yields **503, not 200**, which is the fail-closed behaviour the specification demands. The nonce is admitted before the downstream app runs, so a concurrent replay cannot slip through.

Placing the rate limiter after HMAC verification is deliberate and correct: an unauthenticated flood cannot consume a legitimate caller's quota. The service binds loopback only, so the absence of pre-auth rate limiting is not an exposure.

**Path encoding.** `path.encode("ascii")` in `signing_message` cannot raise, because the middleware engages only when `scope["path"]` is a member of the fixed ASCII `PROTECTED_PATHS` set. I checked this specifically, since a `UnicodeEncodeError` on that line would have been an unauthenticated 500.

**systemd hardening.** `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectSystem=strict`, `ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictSUIDSGID`, `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictRealtime`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service` with `~@privileged @resources @obsolete @debug @mount @swap @reboot @raw-io @cpu-emulation`, `SystemCallErrorNumber=EPERM`, `RemoveIPC`, empty `CapabilityBoundingSet` and empty `AmbientCapabilities`, `User=aicore`, `Group=aicore`, `UMask=0077`, `StateDirectoryMode=0700`. `ExecStart` binds `--host 127.0.0.1 --port 8090`. This is a well-constructed profile. `RestrictAddressFamilies` is finding R-01.

**Test suite.** 421 of 423 pass. The single failure is `test_aicore_deployment_source_and_its_tests_are_tracked`, which shells out to `git ls-files` and therefore fails in any non-git export:

```
AssertionError: Smart Router deployment source and its tests must be tracked before release:
fatal: not a git repository (or any of the parent directories): .git
```

That is a test environment coupling, not a product defect, but it does mean the assertion silently provides no coverage wherever it cannot run. Recommended hardening, in `router/tests/test_router_supply_chain.py`:

```python
    if result.returncode == 128 and "not a git repository" in result.stderr:
        pytest.skip("tracked-source custody is only assertable inside a git checkout")
    assert result.returncode == 0, (
        "Smart Router deployment source and its tests must be tracked before release: "
        + result.stderr.strip()
    )
```

An explicit skip is honest about the gap; a hard failure in every export trains people to ignore the result.

### 13.9 Website, DNS and edge: findings W-01 through W-05 and N-01

Verified clean beyond those findings:

- **Security headers**, all present on the live apex: `strict-transport-security: max-age=63072000; includeSubDomains`, `x-content-type-options: nosniff`, `x-frame-options: DENY`, `referrer-policy: strict-origin-when-cross-origin`, `cross-origin-opener-policy: same-origin`, `cross-origin-resource-policy: same-origin`, `origin-agent-cluster: ?1`, `x-permitted-cross-domain-policies: none`.
- **CSP** is hash-based with no `unsafe-inline` and no `unsafe-eval`, `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`, `upgrade-insecure-requests`. All three inline-resource hashes match the live bytes. Zero violations in Chrome 151.
- **Permissions-Policy** correctly scopes `payment=(self "https://www.paypal.com" "https://www.sandbox.paypal.com" "https://pay.google.com")` so the PaymentRequest API reaches the wallet buttons, with accelerometer, camera, geolocation, gyroscope, magnetometer, microphone and usb all empty.
- **Transport**: HTTP/2 with `alt-svc: h3=":443"; ma=86400`, plain HTTP 301s to HTTPS, certificate valid 2026-09-01 to 2026-11-30 from Google Trust Services.
- **CORS**: `allowedOrigins` is a closed set of seven origins. `publicConfigCacheKey` keys the edge cache per allowed origin, which correctly prevents one origin's `access-control-allow-origin` value being replayed to another from a shared cache entry. `Vary: Origin` is set explicitly. Verified live: a request to `www.winsvpn.org` with `Origin: https://www.winsvpn.org` echoes that exact origin.
- **Payment CSRF guard**: `paymentOriginGuard` requires `Content-Type: application/json` and rejects any present-but-unallowlisted `Origin`, which closes the CORS-safelisted simple-request bypass on the four state-changing payment POST routes.
- **Rate limiting** is isolate-local because Cloudflare Pages rejects Rate Limiting bindings; `web/wrangler.jsonc` is correctly documented as an inert migration target with placeholder namespace IDs, and `requireQuota` treats a bound limiter as optional while falling back to the isolate-local bucket. `connectingClientIp` reads only `cf-connecting-ip` and never a spoofable `X-Forwarded-For`.
- **DNS**: two Cloudflare nameservers, A and AAAA on Cloudflare anycast, SPF `v=spf1 include:_spf.protonmail.ch ~all`, MX to ProtonMail, ProtonMail and Google site verification TXT records. Well formed apart from the missing CAA.

`www.winsvpn.org` serves 200 rather than redirecting to the apex. That is not a defect: `www` is in `allowedOrigins`, the CORS echo is correct there, and `<link rel="canonical" href="https://winsvpn.org/">` handles search canonicalization. Noting it only so it is not mistaken for one later.

### 13.10 Mobile data and cellular resilience: no defects found

Every parameter the target specifies was checked against the code rather than assumed.

| Parameter | Required | Measured | Where |
|---|---|---|---|
| Tunnel MTU | 1280 | 1280 | `lib/main.dart:271-272`, `WinsTunnelConfig.swift:1027`, core server x3 |
| TCP MSS clamp | 1240 | 1240 | data plane `:7213-7218`, core `:7372` |
| MSS guard band | skip if already smaller | `-m tcpmss --mss 1241:65535` | data plane `:7213-7218` |
| PMTU fallback | present | `TCPMSS --clamp-mss-to-pmtu` | data plane `:7219` |
| Persistent keepalive | 20 to 25 s | 25 s, floor 15, ceiling 120 | `WinsTunnelConfig.swift:1042-1044`, `lib/main.dart:5944` |
| Underlying network hint | required | `setUnderlyingNetworks` with checked return | `VpnTunnelService.kt:3827,3837` |
| Handoff callbacks | 4 events | `onAvailable`, `onLost`, `onCapabilitiesChanged`, `onLinkPropertiesChanged` | `VpnTunnelService.kt:3881-3901` |
| Loop prevention on callback | `NOT_VPN` | `addCapability(NET_CAPABILITY_NOT_VPN)` | `VpnTunnelService.kt:3878` |
| Apple footprint ceiling | 15 MiB | `15 * 1024 * 1024` on `phys_footprint` | `PacketTunnelProvider.swift:1253` |
| Kernel PMTUD | RFC 1191/8201 | `winn3/carrier/pmtud*.go` | present |

The 1,280 and 1,240 pair is the right answer for the carrier cases named in the target. 1,280 is the IPv6 minimum link MTU, so it survives 464XLAT CLAT encapsulation and NAT64 translation across the `64:ff9b::/96` prefix without depending on PMTUD messages that many carriers filter, and it sits below every LTE and 5G MTU in the 1,360 to 1,420 range. The 25-second keepalive holds CGNAT UDP bindings whose carrier timeouts are 20 to 30 seconds while leaving the radio free to drop to RRC Idle between beats, which a 5-second keepalive would prevent entirely.

### 13.11 Performance: no defects found

`go test -race ./...` across 107 packages, exit 0. The parallel-crypto design in `winn3/session/batch.go` and `winn3/core/batch.go` is sound: monotonic nonce reservation, a circular ticket completion ring, a strict epoch rekey barrier, and `runLocked` executing small batches (`n <= 8`) inline to avoid worker channel dispatch and join overhead while preserving identical lock semantics. `EpochSentBytes()` resets the byte counter on epoch cutover so the 64 GiB rekey threshold cannot accumulate across epochs and silently degrade the batch path. `winn3/carrier/udp.go` arms the context write deadline once per batch rather than per datagram in `SendBatch`.

I did not re-run the throughput benchmarks; the race-clean result across every package is the correctness claim I am making here.

---

## 14. What I could not verify

Stated plainly, so nothing above is read as broader than it is.

1. **Runtime behaviour of the native platform code.** Windows, Linux, Android and Apple findings are static analysis plus test-suite results. I had no Windows host, no Linux host, no Android device and no iOS device. I did not build the Windows service, did not exercise the named pipe against a live client, and did not observe a real Wi-Fi to cellular handoff.
2. **Server deployment behaviour.** The ONETOUCH scripts were read and linted, never executed. Firewall chain ordering, `xt_time` authority expiry, dm-crypt tuning, LUKS enforcement and container health monitors were verified as written, not as running. No live server was touched, per the rules.
3. **The 20,794 ms figure is the worst case, not a field measurement.** It is what the code produces when the Worker's documented 6 s hub budget expires on all three attempts. Today the endpoint answers in 58 to 101 ms. I could not measure how often the slow path occurs in production, because that needs Cloudflare analytics I do not have. The defect is structural regardless of frequency.
4. **The originally reported click failure may also have had a transient component.** I could not reproduce a hard, permanent click failure against the live site in either jsdom or real Chrome; the settled page works on desktop and mobile. What I did reproduce is a long, silent, fully unclickable window that presents itself exactly as the user described. I cannot prove it is the only cause, and W-02 (a cached 503) is a plausible independent contributor I could not trigger without changing server state.
5. **Chrome and Edge extension packaging.** Blocked by E-01. I could not produce fresh archives because the owner-issued receipt is stale and minting one is an owner action, not an audit action. The `extension/dist/*.zip` artifacts dated Sep 14 were inspected but I cannot attest they match current source.
6. **One router test provides no coverage here.** `test_aicore_deployment_source_and_its_tests_are_tracked` needs a git checkout; this workspace is a plain copy. The tracked-source custody property is therefore unverified by me.
7. **Live server-side state machines.** Double VPN enrollment lease concurrency, the assignment state machine, activation-secret single-use semantics, the transactional email outbox and account provisioning were audited as source. Exercising them requires creating accounts and payment orders, which the rules forbid.
8. **tvOS D-pad navigation and background wakeup.** No Apple TV or simulator available. Verified only that the `enforceRoutes` and `excludeLocalNetworks` rulings hold for the shared iOS provider.
9. **Gemma and vLLM runtime.** The RTX 5060 Ti host was not reachable from this workspace. NVFP4 quantization, DFlash-16 speculation, KV FP8 cache and the closed-set JSON contract were verified as code and tests, not against a running model.

---

## 15. Recommended remediation order

1. **W-01** first. It is the reported bug, it is on the revenue path, and the fix is confined to one file.
2. **W-02** with it. Same file family, same deploy, and it removes an outage amplifier that could otherwise mask whether W-01's fix worked.
3. **E-01** next. Nothing else about the browser extensions can be shipped or reproduced until the release build runs again.
4. **R-01** and **S-01** together: both are one-line posture corrections with an accompanying verification step.
5. **W-03**, **W-04**, **W-05**, **C-01**, **N-01** in the following cycle.

After 1 and 2, re-run the full gate set:

```bash
python3 web/update_style_csp.py && python3 web/verify_inline_csp.py
python3 tools/website_security_audit.py            # 56 PASS, 0 FAIL
python3 tools/verify_live_deployment.py            # 9/9 PASS
flutter analyze --no-pub                           # No issues found!
bash tools/verify_rulings.sh                       # 59 invariants + 6 apple
cd winn_protocol_experimental && go test -race ./... # 107 ok, 0 FAIL
python3 -m pytest router/tests -q                   # 422 passed after the skip fix
python3 extension/build.py                          # exit 0 after E-01 is fixed
```

---

*End of report. Author: Opus 5 (Claude Code Extra High). All findings above were reproduced with the commands and outputs shown; nothing is asserted from inspection alone unless the section says so.*

