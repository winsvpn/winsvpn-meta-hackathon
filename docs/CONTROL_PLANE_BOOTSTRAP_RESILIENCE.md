# Control-plane bootstrap resilience

Status: design, plus an inert policy library landed behind a seam.
Date: 2026-08-03.
Scope: how a client reaches *any* control-plane gateway when the operator's own
domains are blocked. Not about the data plane, which is already in better shape.

---

## 0. The one-paragraph version

The data plane already gets this right: alternative Xray hosts are delivered in
runtime config and never appear in the binary, so decompiling the APK yields no
transport hosts to block. The control plane gets it exactly wrong: three
hostnames across two registrable domains, both unmistakably the operator's, are
compiled in as `String.fromEnvironment` defaults with no build-time override
anywhere. Blocking `winsvpn.org` and `winsvpn.com` therefore disables the
product — and because the good unlinked transport hosts arrive *inside* the
config the client can no longer fetch, the data plane's diversity is unreachable
at precisely the moment it is needed. **Every carrier, fingerprinting and
transport improvement in this tree is downstream of this gap.**

The fix is mostly not code. It is the owner acquiring unlinked domains, exactly
as the cover-certificate work concluded. What code can do is (a) make the set of
reachable endpoints rotatable without an app update, (b) authenticate that
rotation so it cannot be used to steer clients, and (c) tell the difference
between a censored path and a bad cell tower so the scarce endpoints are not
squandered on the latter.

---

## 1. Verified current state

Read directly, not inferred:

| Fact | Location |
|---|---|
| `https://sync.winsvpn.org` (`WINS_GATEWAY_BASE`) | `lib/gateway_failover.dart:69-72` |
| `https://sync.winsvpn.com` (`WINS_GATEWAY_BASES`) | `lib/gateway_failover.dart:77-80` |
| `hub.winsvpn.org` (`WINS_HUB_HOST`) | `lib/gateway_failover.dart:73-76`, joined at `:86` |
| The compiled set is pinned by test, including a negative assertion that `sync.app-cloud-sync.net` is *not* present | `test/gateway_failover_test.dart` |
| **No `--dart-define` sets any of the three, anywhere in the tree** | grep for `WINS_GATEWAY_BASE`/`WINS_HUB_HOST` outside `.artifacts/` returns nothing |
| Unlinked transport hosts come from runtime config, never constants | `lib/main.dart:2991-3003` (`_xrayHostCandidates`) |

Two registrable domains. Both attributable by WHOIS and CT. The defaults ship.

### What authenticates a gateway today

This turned out to be the load-bearing fact for the whole design, so it is
stated plainly:

- **There is no certificate pinning anywhere.** `badCertificateCallback`,
  `SecurityContext`, `setTrustedCertificates` and `HttpOverrides` have zero
  occurrences across `lib/` and every platform directory.
  `android/app/src/main/res/xml/network_security_config.xml` has no `<pin-set>`.
  No plist carries `NSAppTransportSecurity`.
- **There is no signature verification of any control-plane response.** Not on
  `/nodes`, `/verify`, `/account/status`, `/legal/current`, or the app-update
  URL. `package:cryptography` is present but used only for PBKDF2 and X25519.
- Therefore the client's entire control-plane trust model is **WebPKI against
  the system trust store, plus the three-entry compiled host allowlist**.

The allowlist is what stands in for authenticity. `recoveryGatewayFromRecord`
(`lib/gateway_failover.dart:130-137`) lets the unsigned GitHub-hosted recovery
record only *reorder* hosts already compiled in — never introduce one. That
invariant is why an unsigned record is safe today.

> **This is the crux of the design.** Discovery exists to introduce *new* hosts.
> Doing that breaks the allowlist invariant that makes the unsigned record safe.
> A signature on the discovery record is therefore not defence in depth and not
> a nice-to-have — **it is the direct replacement for the allowlist invariant**,
> and without it discovery is a remote-code-equivalent steering primitive
> against a client that pins nothing. Any implementation that ships discovery
> without signature verification is strictly worse than shipping nothing.

### Adjacent findings worth the owner's attention

1. `_freeAccessPreflightTerminalKind()` (`lib/main.dart:828-843`) builds its
   `/free/status` URL by hand from `defaultGatewayBase` and hits **only the
   primary**, with no failover. It gates free activation at `:7160` and `:7343`.
   Single point of censorship failure on the path most-used by new users.
2. **Dormant domain-fronting support.** `_jsonHeaders({includeHost: true})`
   (`lib/main.dart:516-517`) sets a literal `Host:` override from
   `defaultHubHost`. No caller passes `includeHost: true`. Fronting has been
   dead since 2018 (see §6). This should be deleted, not revived.
3. `_postAuthenticatedRace` (`lib/main.dart:564-659`) fires **all** URLs
   concurrently; `_postDoubleVpnAssignmentRace` (`:684-759`) uses `Future.wait`
   over all of them. Feeding discovered endpoints into either primitive would
   reveal the entire fallback reserve simultaneously on a single login. This is
   the concrete hazard behind "do not half-migrate the gateway layer".
4. No `http.Client` instance exists; every request builds and tears down its own
   TLS session. No resumption, no reuse. This triples the byte cost of the
   sequential strategy in §7 and is worth fixing independently.
5. `User-Agent: WinsVPN-App/1.0` (`lib/main.dart:510-520`) names the product to
   the origin and to any TLS-terminating middlebox.
6. The recovery record lives at `raw.githubusercontent.com`. GitHub is itself a
   commonly blocked host; this is a fourth attributable dependency, not a
   fourth independent path.

---

## 2. The layer model

Bootstrap should be four independently-blockable layers. Today only L1 exists.

| Layer | Mechanism | Cost when healthy | Survives |
|---|---|---|---|
| **L0** | Last-known-good endpoint, cached per network | 0 bytes | Everything except first run |
| **L1** | Compiled seed set | 0 extra | Nothing — 2 domains, both attributable |
| **L2** | DoH TXT discovery | 0 extra (only fires on failure) | Domain blocking; not resolver blocking |
| **L3** | Out-of-band pasted token | 0 | Everything network-based |

L0 does not exist today: there is no `shared_preferences` dependency and no
cached winning gateway, so every launch re-derives the order from scratch and
re-pays for any failure. L0 is the cheapest single improvement available and it
is pure local state.

L3 is the strongest and the cheapest. See §8.

---

## 3. Blocking-domain diversity — procurement, not code

The reasoning transfers verbatim from `winn_protocol_experimental/OPERATIONS.md`
§2.1, including its most important sentence: *"This is a procurement
requirement, not a validation one."* The code cannot check any of the
following, and a domain that fails every one is structurally identical to one
that passes.

The owner must acquire **N ≥ 4** registrable domains, and they must be unlinked
from each other and from Win's VPN along every axis a censor can query cheaply:

1. **Registrar** — different accounts, ideally different registrars. One
   registrar account holding all of them is one subpoena, one compromise, or one
   billing email away from linking the set.
2. **Registrant** — WHOIS privacy on all, and different underlying details. Do
   not reuse `admin@winsvpn.org` as the contact.
3. **Registration timing** — do not register the set in one sitting. Creation
   dates cluster and creation date survives WHOIS privacy.
4. **DNS provider** — *different providers*. This is the axis most often missed.
   If all N sit on one provider's nameservers, blocking or compelling that one
   provider takes the whole set down together. Correlated failure defeats the
   point of having a set.
5. **Hosting / CDN / ASN** — different origins. **Never point two unlinked
   domains at one origin IP.** A shared origin IP is the single strongest link
   available to an adversary and it is already sitting in Censys and Shodan scan
   data, free, retroactively, with no probing.
6. **Certificate Transparency** — one certificate per domain. **Never place two
   unlinked names as SANs on the same certificate**; that is an instant,
   permanent, publicly-logged link. Issue from separate ACME accounts.
7. **Naming** — anodyne and unthematic. `secure-tunnel-mm.net` self-identifies.
   The data-plane convention (`app-cloud-sync.net`) is the right register:
   plausible-boring infrastructure. Continue it.
8. **Put something real behind each name.** Same requirement as OPERATIONS.md
   §2.2 step 1 — a censor that fetches the name over the public internet and
   gets a real site is looking at a real site.

**Notation in this document:** real domains are written as
`<discovery-zone-1>`, `<gateway-alt-1>` and so on. Nothing is committed and
nothing has been registered.

### The burn problem, stated plainly

A fallback domain is consumed the moment it is used *while anyone is watching*.
If every blocked client reaches for `<gateway-alt-1>` on the same day, the
correlation is trivially observable and the domain is blocked within a cycle.
Sequential exhaustion of a static list under observation costs one domain per
round, and a national adversary can block faster than an operator can register.

This is why a bigger compiled list is not the answer, and why the design below
optimises for **rotation speed and burn containment** rather than for set size.

---

## 4. Discovery: DoH TXT lookup

### 4.1 Why DoH, precisely

The mechanism is a DNS-over-HTTPS query for a TXT record at a well-known name,
whose answer names current gateway endpoints. ProtonVPN's alternative routing
works this way. The property that makes it work is narrow and worth stating
exactly, because it is the only thing the scheme rests on:

> Inside a DoH session the censor sees TLS to a resolver and nothing else. It
> cannot see the query name, so it **cannot selectively block one name**. Its
> only lever is to block the entire resolver.

That converts "block a name" — cheap, targeted, no collateral — into "block
`dns.google`" — which breaks Android Private DNS and a long tail of unrelated
software for the whole country. The defence is **economic and political, not
cryptographic.** It should never be described as strong.

A second, cheaper property: because the discovery *name* cannot be selectively
filtered, putting it in the binary is far less dangerous than putting a gateway
hostname there. A gateway hostname in the binary is directly actionable at the
enforcement point. A discovery name in the binary is not.

### 4.2 Resolver assessment

| Resolver | Endpoint | For | Against |
|---|---|---|---|
| Google | `dns.google` / `8.8.8.8` | Largest collateral cost to block; cert carries IP SANs so IP-literal use validates under WebPKI | The obvious first target; a state that decides to pay the cost can |
| Cloudflare | `cloudflare-dns.com` / `1.1.1.1` | Widely deployed; cert carries IP SANs | `1.1.1.1` is the most commonly interfered-with of the three, including by consumer CPE, independent of state policy |
| Quad9 | `dns.quad9.net` / `9.9.9.9` | **Already in this app's traffic profile** — `_nativeTunnelDnsServers` (`lib/main.dart`) defaults Apple platforms to `9.9.9.9,149.112.112.112`, so a query here adds no new destination | Smaller; less collateral damage to block, therefore a cheaper target |

**Recommendation:** try all three, in a per-install randomised order, one at a
time. Randomising the order across the install base means no single resolver
carries the whole user population's discovery traffic, which both spreads the
blocking cost and avoids the app contributing a distinctive concentration to
any one resolver's logs.

**Use hostnames, not IP literals, as the primary form.** An IP-literal HTTPS
connection sends no SNI, which is itself an anomaly worth avoiding. Keep the IP
literals as a second attempt for the case where system DNS is itself poisoned —
all three resolvers carry their IPs as certificate SANs, so IP-literal use
validates correctly under WebPKI and **involves no authentication downgrade**.

**Verify before relying.** Whether these three are reachable from Myanmar
mobile networks today is a measurement question, not a design question. The
owner should check current OONI data for the target networks rather than trust
this table.

### 4.3 What the record carries, and the size problem

Wire format, designed to fit a **single 255-byte TXT character-string**:

```
v1|<sequence>|<expiry-unix-seconds>|<host>,<host>,...|<base64 signature>
```

Hosts appear bare and are promoted to `https://<host>` by the client, so a
record can never smuggle a scheme, port, path, query, fragment or userinfo past
the screen. A realistic record with three endpoints and an Ed25519 signature is
**~172 bytes** — verified by test.

**The signature does not fit if it is ML-DSA. This is the decisive constraint.**

| Scheme | Signature | Base64 | TXT strings | Verdict |
|---|---|---|---|---|
| Ed25519 | 64 B | 88 ch | fits in 1, with room | Usable |
| ML-DSA-44 | 2 420 B | 3 228 ch | 13 | Anomalous |
| ML-DSA-65 | 3 309 B | 4 412 ch | 18 | Anomalous |
| ML-DSA-87 | 4 627 B | 6 172 ch | 25 | Unusable |

A ~4.5 kB TXT response is not merely inconvenient; it is a distinguisher in its
own right and invites truncation problems at intermediate caches. So, answering
the question directly:

- **`internal/pqauth` (ML-DSA) does not apply to the TXT record.** The
  signature is an order of magnitude too large for the channel.
- **The `internal/gatewaymanifest` pattern does apply**, but to the *bundle*,
  not to the locator. Its genuinely valuable properties — monotonic `Sequence`,
  bounded `ExpiresAt` lifetime, format tag, fail-closed verification — are
  reproduced in the record format above and in the landed code. Those are
  design properties, and they cost no bytes.

### 4.4 Two stages, and why this is not a downgrade

```
1. DoH TXT  ->  locator: candidate hosts + sequence + expiry + Ed25519 sig
2. Verify signature, sequence monotonicity, expiry.  Fail -> discard entirely.
3. Connect to a candidate under the SAME authentication as the primary.
4. Over that channel, fetch the ML-DSA-signed manifest/config as today.
```

Step 3 is the authentication boundary and it is unchanged. A discovered
endpoint is authenticated **identically** to a compiled one — same WebPKI, same
validation, and the same future pinning when it is added. The landed code
enforces this structurally by re-exporting the existing screen
(`isSafeHttpsGatewayUri`) rather than writing a second, looser copy.

The large ML-DSA signature belongs in step 4, where an HTTPS response body has
room for it. The small Ed25519 signature belongs in step 1, where 255 bytes do
not.

**Is Ed25519 a weakening in a PQ-disciplined project?** Honest answer: it is a
classical primitive, and it is the weakest cryptographic element in the chain.
Three things make it defensible, and the owner should decide with them stated:

1. Signatures are not subject to harvest-now-decrypt-later. Forging one
   requires a cryptographically-relevant quantum computer *at the time of the
   attack*, not later.
2. Records are short-lived (recommended TTL 6 h, hard ceiling 7 d) and
   sequence-bound, so the value of a forgery decays.
3. It is strictly additive. Today the record it replaces — the GitHub recovery
   record — is **unsigned**. Ed25519 is not a downgrade from ML-DSA here; it is
   an upgrade from nothing.

If the owner wants PQ on the locator too, the route is a hybrid record served
over HTTPS from a discovery host (where size is free) with the TXT record used
only when that host is blocked. That is more moving parts for a benefit that
does not bind until a CRQC exists. Recommend Ed25519 now, revisit on a schedule.

### 4.5 Anti-rollback, and why sequence beats expiry

Both are enforced; they are not redundant.

- **Sequence** is the primary control. A record whose sequence is not strictly
  greater than the highest previously accepted one is refused. This stops an
  adversary replaying a captured older record to push clients back onto a
  retired or seized endpoint.
- **Expiry** is a coarse backstop with a 12-hour skew tolerance, because
  **mobile clocks are unreliable and a wrong device clock is not an edge case in
  this population**. A design that leans on expiry alone strands every user
  whose clock has drifted. Sequence works regardless of what time the device
  thinks it is.
- A hard lifetime ceiling (7 days) bounds the blast radius of a signing-key
  compromise.

### 4.6 The unavoidable bootstrap seed

Three constants are unavoidable, and each is justified against the "no new
domains in the binary" constraint:

| Constant | Why unavoidable | Why acceptable |
|---|---|---|
| DoH resolver hostnames/IPs | Must know where to ask | Not attributable to Win's VPN. `8.8.8.8` is the most famous IP on the internet; `9.9.9.9` is *already* in this binary |
| Ed25519 public key (32 B) | Must know whom to trust | A public key. `strings` yields 32 random bytes and no blocking target |
| Discovery zone name(s) | Must know what to ask for | The censor cannot act on it selectively inside DoH (§4.1); it is the minimum irreducible seed |

The discovery zone is the one genuine cost, and it should be **two or three
zones under different registrars and jurisdictions**, so that seizure of one
does not end discovery.

**Sign the discovery zones with DNSSEC.** All three recommended resolvers
validate. That closes upstream cache-poisoning and spoofing of the authoritative
answer, leaving seizure and removal as the remaining attacks — a materially
smaller set, for the cost of ticking a box at the DNS provider.

---

## 5. Blocked versus degraded

The hard part, as stated. A blocked path and a congested one both surface as a
timeout, and collapsing them is what makes naive failover flap and deliver
nothing.

### 5.1 Signal table

| Observation | Reading | Strength |
|---|---|---|
| DNS answer is loopback/RFC1918/bogon | Sinkhole | **Confirmed** |
| NXDOMAIN for a name known to exist | DNS-level block, or seizure/lapse | **Confirmed** |
| TCP RST materially faster than reference RTT | Path-injected reset | **Confirmed** |
| Reset/close after ClientHello, before ServerHello | SNI filter | **Confirmed** |
| Certificate rejected (wrong name/untrusted) | Interception | **Confirmed** |
| HTTP 200 with a portal or notice page | Interception | **Confirmed** |
| HTTP 403/451 from something that is not the origin | Explicit block | **Confirmed** |
| DNS SERVFAIL / no reply | Ambiguous | Suspected |
| TCP SYN unanswered | Ambiguous | Suspected |
| TLS handshake timeout | Ambiguous | Suspected |
| Request deadline exceeded | Ambiguous | Suspected |
| TCP RST at plausible origin RTT | Host refusing — server-side | **Not a block** |
| HTTP 5xx behind a valid certificate | Our own outage | **Not a block** |

Two rows deserve emphasis:

- **RST timing.** An injected reset arrives sooner than the true round trip to
  the origin permits. Using the measured RTT to the DoH resolver as the
  reference makes this a cheap and decisive discriminator, and it needs no extra
  request.
- **HTTP 5xx is not a block.** Getting this wrong is the most expensive false
  positive available: a routine backend incident would drive the entire user
  base to burn its entire fallback reserve simultaneously. This is tested
  explicitly.

### 5.2 The control probe

The ambiguity between "blocked", "no internet" and "congested" collapses given
one reference point. **The DoH query is that reference point, and it is free
because it is already being made.** If DoH succeeds, the device demonstrably has
working internet, so a concurrent gateway failure is *specific*. If DoH fails
too, nothing about the gateway can be concluded.

Consolidating the control probe and the discovery lookup into one request saves
a round trip and ~6 kB, and costs nothing: the query is opaque inside TLS, and
the plan admits at most one new endpoint regardless.

The probe is a **veto, never a promotion**. It can stop an ambiguous failure
being read as censorship; it can never make a benign observation hostile. And it
gates only the genuinely ambiguous observations — a forged certificate is not
more or less forged depending on whether some other host was reachable, so
self-evidencing signals bypass it. Both properties are tested.

### 5.3 Hysteresis

- Ambiguous signals need **3 corroborating observations**; self-evidencing
  signals act on **1**.
- Transient signals never accumulate toward a block.
- **Health is scoped per network attachment, not globally.** Blocking is a
  property of the path. A gateway censored on a hotel Wi-Fi is usually fine on
  the same user's mobile data, and global state would let one hostile network —
  or a captive portal doing it deliberately — permanently poison the primary
  gateway everywhere. Changing network discards the old verdict rather than
  merging it.
- **Blocked endpoints are rechecked** on exponential backoff from 15 min to a
  24 h cap. Blocks get lifted; and a false positive that is never rechecked is a
  permanent one.
- A success clears everything, so recovery needs no separate unblock path.
- The planner can never return an empty plan. Failing closed on one's own
  hysteresis would strand a client whose block was lifted.

### 5.4 False-positive cost, concretely

A client that wrongly concludes it is censored pays three costs, in increasing
order of seriousness:

1. **Data and latency.** ~11 kB and a few extra seconds. Negligible (§7).
2. **A slower path.** Recoverable.
3. **It burns a fallback endpoint** — reveals it to any observer, for the whole
   user base, permanently. This is the real cost, and the reason every threshold
   above is set conservatively.

Containment, in order of effectiveness:

- The control-probe veto removes the largest class of false positives (no
  connectivity read as censorship) for free.
- 5xx and slow-RTT RST are classified as non-blocks, removing the backend-outage
  mass false positive.
- Per-network scoping stops one bad network poisoning global state.
- **One new endpoint per launch** means a false positive costs exactly one
  endpoint, never the reserve.

---

## 6. Explicitly rejected

**Domain fronting is dead.** SNI naming a benign host while the HTTP `Host`
header names the real one, with the CDN routing on `Host`: Google and Amazon
CloudFront both disabled it in 2018, and Cloudflare enforces SNI/`Host`
agreement. It is not designed around here. The dormant `includeHost: true`
support at `lib/main.dart:516-517` should be **deleted**.

What is proposed that superficially resembles it, and is not:

- **Differential SNI probing** — two ordinary connections, each with matching
  SNI and `Host`, compared purely as a *measurement* to prove SNI filtering. No
  routing trickery, works everywhere, legitimate. Available as a high-confidence
  discriminator when the gateway sits behind a shared CDN.
- **CDN hosting under an unlinked name** — SNI and `Host` both name the unlinked
  domain. This still works and is worth doing: it forces the censor off cheap
  IP blocking (the IP is shared, so blocking it has collateral cost) and onto
  per-name SNI blocking, which requires knowing the name.

**ECH** is the real successor to fronting and would defeat SNI filtering
outright, but it is unavailable here for a decisive practical reason: Dart's
`dart:io` TLS stack does not support it. Deployment status among CDNs is also
unsettled. Not a near-term option for the Flutter control plane; revisit if the
control plane ever moves to the Go stack, which already models `ECHConfigList`.

**Encrypting the TXT payload to a key in the app** raises the adversary's cost
from "query the name" to "reverse-engineer the APK once, then query the name".
That is a one-time cost, after which it is free forever. Against a national
adversary it buys nothing. Not recommended as a defence; possibly worth it
purely as friction against commodity automated blocking, and only after
everything above is done.

**A larger compiled fallback list** recreates the current problem with more
entries. Anything in the binary is one `strings` run away.

---

## 7. Ordering and cost

Users are in Myanmar on expensive metered mobile data. Strategy: **cache-first,
strictly sequential, discovery only on exhaustion, one new endpoint per
launch.**

```
0. Last-known-good endpoint for this network        (0 extra bytes)
1. Compiled gateways, in order, skipping blocked    (as today)
2. -- only if 1 is exhausted AND control probe says the device has internet --
   DoH discovery lookup, doubling as the control probe
3. At most ONE discovered endpoint
4. Out-of-band token, if the user has one
```

**Never in parallel.** Three independent reasons, each sufficient:

1. **Data cost** on metered connections.
2. **Traffic signature** — a burst of TLS handshakes to several unrelated
   domains within a second is a fingerprint no ordinary app produces. Serial
   attempts with ordinary gaps look like retries.
3. **Burn containment** — parallel attempts reveal the whole reserve at once and
   lose it at once.

Note this directly contradicts the existing `_postAuthenticatedRace` and
`_postDoubleVpnAssignmentRace` primitives, which fan out to all URLs. Those must
not be handed discovered endpoints. See §8.

### Data cost per launch

Assuming no connection reuse, which is the current reality (finding 4, §1):

| Event | Bytes |
|---|---|
| Full TLS 1.3 handshake, typical DV chain | ~5 kB |
| DoH query on a fresh session (handshake + query + TXT answer) | ~6 kB |
| Failed TCP connect (SYN retries) | ~0.3 kB |
| Reset after ClientHello | ~0.8 kB |
| DNS NXDOMAIN | ~0.2 kB |

| Scenario | Added cost vs today |
|---|---|
| **Healthy launch (cache hit)** | **0 bytes** |
| Healthy launch, cold cache | 0 bytes |
| Blocked launch: 3 compiled attempts fail, DoH probe, 1 fallback succeeds | **~11 kB** |

The scheme is free when it is not needed, because discovery only fires once the
compiled set is exhausted. ~11 kB is a rounding error against any per-gigabyte
tariff — roughly one hundred-thousandth of a gigabyte.

**So bytes are not the binding constraint, and it would be misleading to present
them as the headline number.** The costs that actually bind are: *latency* on a
blocked launch (several sequential timeouts before recovery), *battery*, and
above all *domain burn rate*, which is denominated in the owner's procurement
budget and operational tempo rather than in the user's data plan.

The honest UX cost of "one new endpoint per launch" is that recovery from a
block can take a few launches in the worst case. That is a deliberate trade
against burning the reserve, and it is largely hidden by L0: once something
works it is cached per network and subsequent launches cost nothing.

---

## 8. What was implemented

`lib/bootstrap_resilience.dart` — **pure policy, no network I/O, no hostnames,
no keys.** 30 tests in `test/bootstrap_resilience_test.dart`. `flutter analyze`
clean; full suite 371 passing.

| Component | Function |
|---|---|
| Observation taxonomy | `BootstrapObservation` — 14 distinguishable outcomes |
| Classification | `classifyBootstrapAttempt`, `requiresControlProbe` |
| Hysteresis | `EndpointHealth`, `recordBootstrapAttempt` — strikes, per-network scoping, recheck backoff |
| Record format | `parseDiscoveryRecord`, `verifyDiscoveryRecord`, `splitDiscoveryRecord`, `discoverySigningBytes` |
| Ordering | `planBootstrapAttempts`, `BootstrapPlan` |

Plus one additive line in `lib/gateway_failover.dart`: `isSafeHttpsGatewayUri`,
re-exporting the existing screen so discovered endpoints are validated by the
*same code* as compiled ones rather than by a second, looser copy.

**Why it is inert.** `verifyDiscoveryRecord` requires an injected
`DiscoverySignatureVerifier` and there is no default. No key is compiled in, no
discovery zone is named, nothing calls into `lib/main.dart`. Until the owner
provisions a signing key and a zone there is nothing to pass, and the shipping
bootstrap path is byte-for-byte unchanged. This is the seam: the policy is
reviewable and tested now; the gateway layer is untouched.

Two properties are worth calling out because they are the ones an auditor will
check first:

- **Structural validation does not depend on the signature.** The hostile-record
  test deliberately passes an always-accept verifier, so a *compromised signing
  key still cannot inject* a scheme, port, path, userinfo, IP literal or
  oversized record.
- **Signed bytes are taken from the raw input**, never from a re-serialisation
  of parsed fields — re-serialising is the classic way a signature check ends up
  validating something other than what arrived. Tested.

### Not implemented, deliberately

DoH transport, TXT parsing off the wire, Ed25519 key material, persistence, and
any wiring into `main.dart`. Each needs a decision or an asset that does not
exist yet, and doing them now would half-migrate the gateway layer.

### Integration checklist, when the owner is ready

1. Provision the Ed25519 signing key offline; publish the public key **only** as
   a compiled constant. Never transmit it.
2. Acquire discovery zones (§3), enable DNSSEC, publish the first record.
3. Add L0 persistence. `_writeSensitiveText`/`_readSensitiveText`
   (`lib/main.dart:900-949`) already exist; add a name to
   `_validateSensitiveStateName` (`:893-898`). Persist last-known-good endpoint,
   per-network health, and the highest accepted sequence — **the sequence store
   is security-relevant**, since losing it re-opens replay.
4. Implement the DoH client. Sequential, randomised resolver order, hostname
   first with IP-literal fallback.
5. Wire `planBootstrapAttempts` into `_resolveDynamicEndpoints`
   (`lib/main.dart:4775`) — the single existing chokepoint, which is why this
   integration is small.
6. **Do not** route discovered endpoints through `_postAuthenticatedRace` or
   `_postDoubleVpnAssignmentRace`. Give them a sequential path.
7. Fix `_freeAccessPreflightTerminalKind` to use `freeStatusGateways`.
8. Add the L3 paste box (below).

### L3 costs almost nothing and should be done first

`verifyDiscoveryRecord` takes a raw string from **any** source, so the same
format and the same verification serve a token a user receives over Signal,
Telegram or on paper and pastes into the app. A record is ~172–240 characters —
comparable to a long URL, and pasteable.

This is the highest value-to-effort item in the whole design: a UI text field
and a call into code that already exists and is already tested. It requires no
DoH client, no discovery zone, and no resolver to be reachable — and it is the
**only** layer that survives all three of the failures in §9.

---

## 9. What this survives, and what it does not

### Survives

- Blocking `winsvpn.org` and `winsvpn.com` by DNS, SNI or IP — provided
  unblocked alternatives exist.
- DNS poisoning of the operator's domains: DoH bypasses the local resolver, and
  certificate validation catches the poison regardless.
- A spoofed or replayed discovery record: signature, sequence and expiry.
- Passive APK analysis: yields the discovery zone, which is not selectively
  actionable inside DoH, rather than a list of gateways that is.
- A backend outage being mistaken for censorship.

### Does not survive

- **Blocking all major DoH resolvers.** States do this. If Google, Cloudflare
  and Quad9 are all unreachable, L2 is dead and only L0 and L3 remain.
- **Enumerate-and-block.** The TXT record is public. A censor queries the
  well-known name themselves, reads today's endpoints, and blocks them —
  immediately, automatically, at zero cost, without observing a single client.
  **This is the design's weakest joint.** Per-client partitioning cannot fix it,
  because DoH means the authoritative server sees the resolver's address, not
  the client's. The only mitigation is rotation tempo: it converts a one-time
  permanent block into a recurring cost for both sides. The owner's registration
  budget is then in a direct race with the censor's automation, and that race is
  not obviously winnable.
- **Seizure or compulsion of a discovery zone's registrar.** Mitigated only by
  holding zones in multiple jurisdictions. DNSSEC makes tampering detectable but
  does not prevent removal.
- **Severing international transit, or a full shutdown.** Myanmar has done this.
  No software measure applies.
- **TLS fingerprint blocking of the app itself.** If the ClientHello is
  distinguishable, no amount of domain diversity helps — see
  `winn_protocol_experimental/docs/CLIENT_TLS_FINGERPRINT.md`. Control-plane
  resilience is downstream of that work too.
- **IP-level blocking of fallback hosts** not behind a shared CDN.

**This is a resistance measure, not a solution.** It raises the cost and the
tempo a censor must sustain. It does not defeat a determined national adversary,
and it should never be described to users as doing so.

---

## 10. What the owner must acquire

Ordered by how much of the load each item carries. **The first three are
procurement, and they are the ones that matter** — the same conclusion the
cover-certificate work reached.

| # | Item | Notes |
|---|---|---|
| 1 | **N ≥ 4 unlinked gateway domains** | Different registrars, DNS providers, ASNs, CT chains. §3. Carries most of the load. Nothing in code substitutes for it. |
| 2 | **2–3 discovery zones**, different registrars and jurisdictions, DNSSEC on | §4.6. Seizure resistance. |
| 3 | **Real content behind each name** | OPERATIONS.md §2.2 step 1. A name that serves nothing is a name that reads as infrastructure. |
| 4 | An **Ed25519 signing key**, generated and held offline | Public half compiled in; private half never on a server that terminates client traffic. |
| 5 | A **publishing procedure** | Increment sequence, set TTL ≈ 6 h, sign, publish to all zones. Must be routine — the whole scheme is worth exactly as much as the rotation tempo behind it. |
| 6 | A **measurement input** | OONI data for the target networks, to know which resolvers and endpoints are actually reachable before betting on them. |

Not acquired, not registered, not committed: no domain in this document is real,
and no domain was chosen on the owner's behalf.
