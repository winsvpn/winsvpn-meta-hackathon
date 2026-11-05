# Operations Runbook — Standalone Winn Protocol v3 (CORRECTED 2026-08-12)

> ## ⚠ SUPERSEDED IN ONE RESPECT — cover/ECH, 2026-08-13
>
> **Everything this file says about cover, decoy and ECH being ABSENT from
> `winn3-gateway` was true when written and is now FALSE.** The cover listener
> landed late on 2026-08-12 (`cmd/winn3-gateway/cover.go`, backup
> `cover.go.bak_20260812_v3_cover_listener_impl`).
>
> **MEASURED 2026-08-13:** `cmd/winn3-gateway/main.go:645` calls `startCover`
> **unconditionally** in the serve path, and `cover.go:63` begins with
> `requireCoverFlags(opts)` then loads `-ech-keys`, `-cert` and `-key`. A missing
> one is a returned error, so **the gateway exits at startup**.
>
> Specifically, do NOT act on these rows below — they will break a deploy:
> - the §2 row "No cover cert, no ECH"
> - the §2.1 row "`rg cover-cert cmd/winn3-gateway` → 0"
> - the §2.2 row "`rg decoy cmd/winn3-gateway` → 0"
> - "Do not install `/etc/winn/credentials/cover.pem`"
> - "There is **no** `-cover-cert`, `-decoy-origin`, `-ech-keys`"
> - the summary row "Cover / decoy / ECH on this binary | **absent**"
>
> **What is required now**, per the ruling in
> `docs/handoff/COVER_CERT_DECISION_20260812_fable.md`:
> 1. A **real DV certificate** for an innocuous domain unrelated to winsvpn.org.
>    `internal/coverlisten/covercert.go` refuses a self-signed leaf, a CA-as-leaf,
>    and validity over 398 days, so the lab PKI (`internal/pki.GenerateLab`,
>    `CN=Winn Protocol Experimental Lab CA`) is NOT usable — it only loads behind
>    an `-insecure-cover-*` downgrade, which puts the protocol's name in the clear
>    to every prober. Do not use those flags.
>    Obtain with `scripts/obtain_cover_cert.sh --unit winn3-gateway` — note it
>    **defaults to `--unit winn-carrier-server`** and predates this gateway.
> 2. **Production ECH keys** whose public name is that same cover domain. Use
>    `cmd/winn-ech-keygen -public-name <cover-fqdn> -out <dir>` (added 2026-08-13).
>    Do NOT use `winn-pki`: it hardcodes `public.winn.invalid`, a reserved TLD,
>    and the key file sets `SendAsRetry`, so that name can reach a prober in an
>    ECH retry_config.
> 3. The installer refuses without them: `WINN3_GATEWAY_COVER_CERT`,
>    `WINN3_GATEWAY_COVER_KEY`, `WINN3_GATEWAY_ECH_KEYS`.
>
> The rest of this file — MTU, promotion, DNS, resolver, unit layout — was not
> re-audited on 2026-08-13 and is believed to stand.

**This file was corrected on 2026-08-12 by lane `doc_operations`.** The previous
version was titled `# Winn Protocol v2 Operations Runbook` (865 lines, dated
2026-08-03, sha256 `844e8872302043c5c82ecfe9bfc798624d7a30b5421daf13dd5f654aab91b7d2`).
It described PostgreSQL, cover certificates, AmneziaWG peer updates, MASQUE
carriers, gateway manifests, anonymous tokens, and `winn-admin` revocation.
**That document is FALSE when read as operations for standalone Winn Protocol v3.**
A wrong ops doc is worse than none because it gets cited for v3 decisions
(path MTU, cover certs, promotion, DNS).

- **Backup of the previous file (byte-identical):** `OPERATIONS.md.bak_20260812_doc_operations`
- **Per-claim audit:** `docs/handoff/OPERATIONS_V3_AUDIT_20260812_doc_operations.md`
- **Deploy procedure (separate, dated):** `source/wins_vpn/docs/WINN3_GATEWAY_DEPLOYMENT_RUNBOOK_20260812.md`
- **This correction never softens a claim the code fails to meet.** Gaps stay FALSE.

Kansas `<KANSAS_IP>` and Spain `<NODE_ES_IP>` are frozen production. Nothing
in this file is a grant to contact them.

---

## 1. FALSE claims the previous document made about standalone v3 — read this first

Verdicts are against **current standalone v3** (`winn3/*`, `cmd/winn3-gateway`,
`datapath/`, signed descriptor + client derivation). A claim that is true of
the still-present v2 control-plane code is still **FALSE as v3 operations**.

| Previous § | Claim | Verdict for standalone v3 | Evidence |
|---|---|---|---|
| Title L1 | Current ops runbook for this tree | **FALSE** | Title was `Winn Protocol v2 Operations Runbook`. `rg` of the file: 0 hits for `winn3-gateway`, `resolver`, `inner_resolver`, `path-mtu`, `descriptor`, `winn3`. |
| §1 | Choose file-backend vs PostgreSQL for a controller | **FALSE** | `rg postgres winn3 --include='*.go'` → 0. `cmd/winn3-gateway` has no controller.state and no DSN. |
| §2 | Required creds: P-384 TLS, ECH keys, device CA, cover cert, PG URL, v3 PQ registry | **FALSE** | v3 gateway secrets are two files: 32-byte X25519 static + admission secret (`deploy/systemd/winn3-gateway.service` LoadCredential). No cover cert, no ECH, no Postgres. |
| §2.1 | `winn-server`, `winn-token-issuer`, `winn-carrier-server` refuse to start without `-cover-cert` / `-cover-key` | **FALSE as v3** (TRUE of those v2 binaries) | Flags exist in those three `cmd/winn-*` mains. `rg cover-cert cmd/winn3-gateway` → 0. Cover review lives in `internal/coverlisten`, which winn3-gateway does not import. |
| §2.2 | Every listener serves a cover website; `-decoy-origin` selects it | **FALSE** | `rg decoy cmd/winn3-gateway` → 0. The binary binds one unconnected UDP socket and does not speak HTTP to probers. |
| §3 | `psql … schema/postgres_v1.sql`; five Winn tables; `sslmode=verify-full`; `-postgres-auto-migrate -lab-mode` | **FALSE** | Schema files still exist for v2. winn3-gateway does not read them. |
| §4 | Install `winn` user, `/etc/winn/server.env`, file vs Postgres unit, AWG `set <iface> peer <key> preshared-key`, `CAP_NET_ADMIN`, `-ech-keys` | **FALSE** | Unit user is `winn3-gateway`. Env is `/etc/winn/winn3-gateway.env`. Default CapabilityBoundingSet is **empty**. No AWG binary is exec'd. Binary path `/usr/local/libexec/winn/winn3-gateway` happens to match §4 step 1's directory; that is the only overlap. |
| §4.1–4.3 | `winn-carrier-server` MASQUE, `winn-manifest`, transparency log, `winn-token-issuer`, blind RSA | **FALSE** | Owner rejected v3-as-AWG-relay (`_COMMON.md`). Standalone v3 owns handshake, crypto and datapath. Those binaries are v2. |
| §4.4 | `-privacy-profile high-risk` default, `DisableLengthPadding`, measured padding table (424,800 B, IMIX +35.3%), `-local-peer`, `-cover-cert` on the carrier | **FALSE / UNVERIFIABLE** | `DisableLengthPadding` exists in `internal/carrier` (v2 MASQUE), not in `cmd/winn3-gateway`. Padding table not re-derived here. No such flags on winn3-gateway. |
| §5 | `./scripts/build_release.sh /private/release/winn-v2`, CycloneDX, amneziawg-go/tools licences, SLH-DSA release signatures | **FALSE as v3 release** | Scripts exist. The directory name and AWG licence notes are v2. v3 artifacts are `winn3-gateway` / `winn-datapath` / platform engines. |
| §6 | HTTP 201/200 rotation, generation++, AWG PSK supersede, TTL 24h | **FALSE** | v3 session is X25519 handshake + optional in-band ML-KEM-768 ratchet (`winn3/core`), not HTTP PSK rotation. |
| §7 | ML-DSA registry/pin-set JSON, up to four keys, `winn-admin` ceremony | **FALSE** | Shipped descriptor signatures are **Ed25519** (`WINN3_DESCRIPTOR_SUPPORTED_ALGS`, `Ed25519().verify` in `lib/winn_protocol_dispatch.dart`). Go comments in `winn3/core` that say "ML-DSA-65-signed descriptor" are stale relative to the hub and client. Design wants ML-DSA-65; the wire does not. |
| §8 | Two-step revoke → `winn-admin -action revocation-list` → carrier flags | **FALSE** | `rg revocation winn3 --include='*.go'` → 0. No revocation list in the standalone datapath. |
| §9 | `/healthz` `/readyz` `/metrics`; alerts `carrier_dial_failed`, `carrier_revocation_*`, Postgres retries | **FALSE** | `rg healthz\|readyz\|/metrics cmd/winn3-gateway` → 0. The unit writes status to stdout/stderr; `journalctl -u winn3-gateway` is the only record. |
| §10–12 | Backup `controller.state`; `winn-audit`; incident step "reconcile AWG PSK" | **FALSE** | No durable controller state. Unit comment: no writable path, no on-disk artifact of a run. |
| §13 | Private Linux Auto gate as a v3 operations step | **FALSE as this runbook** | Auto/AWG impairment matrix is not how standalone v3 is stood up. |
| *(omission)* | Gateway datapath descriptor resolver | **FALSE by omission** | The previous file never named it. It is the load-bearing gap for shipping v3. See §5 below. |

**TRUE as threat-model prose, FALSE as a v3 required file:** the cover-certificate
argument (issuer DN in the clear, EV vs DV, 398-day CABF cap, reserved TLDs) is
cryptographically sound and is what `internal/coverlisten` enforces on v2 TLS
listeners. `cmd/winn3-gateway` is a UDP datagram responder. It does not present
a certificate to unauthenticated peers. Do not install `/etc/winn/credentials/cover.pem`
for this binary; it will not load it.

**TRUE of v2 code, not this runbook:** `schema/postgres_v1.sql`,
`scripts/verify.sh`, `deploy/systemd/winn-server-*.service`, `-cover-cert` on
`winn-server` / `winn-carrier-server` / `winn-token-issuer`. Those remain in
tree. They are not how you operate standalone v3. The previous file is in the
`.bak_20260812_doc_operations` backup if you need the v2 procedures.

---

## 2. What standalone v3 operations actually are

Standalone v3 means v3 owns its handshake, crypto and datapath. It does **not**
mean relaying AmneziaWG datagrams.

| Piece | Where | What an operator actually runs |
|---|---|---|
| Reachable gateway process | `cmd/winn3-gateway` | `winn3-gateway -mode serve …` |
| Handshake / crypto | `winn3/core` | X25519 static keys; optional in-band ML-KEM-768 ratchet. **Not** AWG PSK. |
| Session / driver | `winn3/session`, `winn3/driver` | `driver.NewGateway` per peer (this binary). Plan floor from `-path-mtu` + `-plan`. |
| Inner IP / tun rules | `winn3/tun` | src MUST be ours outbound; dst MUST be ours inbound. |
| Library front door (not this binary) | `winn3/gateway` | Dispatch library; "holds no socket and no timer". `cmd/winn3-gateway` does **not** use `gateway.Table`. |
| Inner DNS responder | `cmd/winn3-gateway/resolve.go` (+ `resolve_tcp.go`) | Off by default. Answers UDP/53 at `-inner-v4` only. Advertises **nothing**. |
| Signed descriptor | control plane + `lib/winn_protocol_dispatch.dart` | Hub format version **3** with required `inner_resolver_v4`. Client pin **2**. Signatures: **Ed25519**. |
| Client derivation | Apple `WinsWinn3Resolvers`, Android `WinnV3Resolvers`, desktop `BuildPromotedPosture` | Promotion **refuses** without a derivable inner resolver. |
| Staging interlock | `winn3/conform` `StandaloneResolverStagingGuards` | Pins client format at 2 until a live responder is verified. |
| Install generator | `server/wins_winn3_gateway_install.sh` `write_unit()` | The systemd file in `deploy/systemd/` is a **hand-kept reference, read by nobody at install time**. |

---

## 3. The reachable binary — what it is and is not

From `cmd/winn3-gateway/main.go` package doc (read, not paraphrased into a
stronger claim):

- One unconnected UDP socket, a demultiplexer, one `winn3/driver` responder
  loop per peer, joined by `carrier.Pipe`.
- Demultiplexes on **peer address**, not on the demux token. A session does not
  survive a peer rebinding to a new source port. `winn3/gateway.Table` is the
  address-independent index the protocol calls for and is **not used here**.
- Default inner side is an **in-process reflector** (`reflect.go`): it forwards
  nothing to the internet, resolves nothing, egresses nothing. A packet
  round-trip proves socket + handshake + session + frames + tun layer. It
  proves **nothing** about forwarding, NAT or egress.
- `-forward` (Linux only) is what creates a kernel TUN and lets the kernel
  forward. Default is off. Required: `-accept-transit=true` and `-forward-cidr`.
  Refuses `-inner-v6`/`-router-v6`. Refuses non-Linux.
- Setting `-forward` or `-resolver` **does not entitle the control plane to
  serve winn/3** to anyone. Advertising is a signed-descriptor change, not a
  flag.

Flags measured from `run()` in `cmd/winn3-gateway/main.go`:

| Flag | Default | Notes |
|---|---|---|
| `-mode` | `serve` | `keygen` or `serve` |
| `-listen` | empty (required) | UDP bind, e.g. `127.0.0.1:51833` |
| `-static` | empty (required) | 32-byte X25519 private key file |
| `-admission` | empty (required) | admission secret file |
| `-gateway-id` | empty (required) | authenticated gateway identifier |
| `-inner-v4` | `10.64.0.1` | this end's inner IPv4; the **only** address the resolver can answer at |
| `-router-v4` | empty | inner next hop, for PMTU signals only |
| `-inner-v6` / `-router-v6` | empty | optional; refused under `-forward` |
| `-plan` | `udp` | comma-separated migration plan |
| `-path-mtu` | `carrier.DefaultPathMTU` (**1450**) | planning path MTU; unit file passes it explicitly and must not omit it |
| `-accept-transit` | false | required by `-forward`; lab-only without `-forward` |
| `-max-sessions` | 64 | session ceiling |
| `-forward` | false | Linux TUN + kernel forward/NAT |
| `-forward-if` | `winn3gw0` | must not already exist (`IFF_TUN_EXCL`) |
| `-forward-cidr` | empty (required if `-forward`) | must contain `-inner-v4`; must be the subnet the control plane assigns from; must be disjoint from awg0's VPN_CIDR |
| `-resolver` | **false** | answer DNS at `-inner-v4`. **Advertises nothing.** |
| `-resolver-upstream` | empty (required if `-resolver`) | literal `address:port`; no hostname; no default |
| `-resolver-timeout` | 5s (`dnsDefaultTimeout`) | must be positive; inert without `-resolver` (refused) |

There is **no** `-cover-cert`, `-decoy-origin`, `-ech-keys`, `-postgres-dsn`,
`-healthz`, or AWG binary flag.

---

## 4. Path MTU — do not leave this to a silent default

`winn3/carrier/sizing.go`: `const DefaultPathMTU = 1450`.

`winn3/gateway/params.go` `checkPathMTU` (library `gateway.New`, not this
binary's constructor) refuses:

- `pathMTU <= 0` (no claim → silent-refusal #3 fail-open)
- `pathMTU < MinPathMTUForInnerIPv6` where `MinPathMTUForInnerIPv6 = 1421`
  (dead zone **1280–1420**: session resolves, bootstraps, carries, **never
  promotes**; `ipv6_add_dev()` returns `-EINVAL`)
- `pathMTU > 0xFFFF` (notice cannot state it)

`cmd/winn3-gateway` sizes via `driver.NewSizing(opts.pathMTU, classes...)`
(`buildServeSizing`). `-plan` defaults to `udp`. A client sized for
`udp,tcp,tls` at the same PathMTU computes a **wider** floor than a udp-only
gateway. Same PathMTU is not enough: the plan must match or the gateway must
emit `EncodePathMTUFloorNotice` (this binary's `driver.NewGateway` path does;
a regression onto `winn3/gateway.New`'s 7-byte PathMTU-only notice would
black-hole full-size packets while both ends report carrying). See
`cmd/winn3-gateway/pathmtu_planmismatch_test.go`.

The systemd unit comment that a "built-in 1280" is the trap is **stale**: the
binary default is 1450. The unit is still right that `-path-mtu` must be an
**explicit operator decision** in the env file. A mismatch looks like
censorship: the gateway never answers an unauthenticated-looking datagram.

Do not raise a fleet default against a gateway left at a different value.

---

## 5. Gateway datapath descriptor resolver — the blocking gap

This is the component the previous OPERATIONS.md omitted entirely. It is **not**
`datapath.adoptUDPDescriptor` (host UDP-socket adoption for the engine). It is
the inner DNS forwarder plus the signed field that would advertise it.

### 5.1 What exists in this process

`cmd/winn3-gateway/resolve.go` (1156 lines) + `resolve_tcp.go` (357 lines).

It is a **forwarder**, not a recursive resolver, not a cache, not a filter. It
relays a query's UDP payload to `-resolver-upstream` and relays the answer
back. It parses DNS only to refuse non-queries, to synthesise **TC=1** when the
answer will not fit the inner MTU, and to synthesise **SERVFAIL** on upstream
failure (not NXDOMAIN, not silence).

It answers **UDP/53 at this end's `-inner-v4` and at no other address**.
`winn3/tun` outbound: a DNS reply's source MUST equal this endpoint's
assignment or the tunnel drops it as `TxDroppedInvalid` / `ErrSourceNotOurs`.
A resolver at a second inner address (e.g. `10.64.0.53`) cannot answer through
the tun layer without `-forward` and a kernel path this file does not
implement. `-inner-v4` is already the client's `inner_router_v4`. The missing
piece on the wire is a **signed statement that this gateway answers there**.

`claim()` (measured, and the suite `TestResolverRefusesEverythingItMustNotClaim`
is green with `-count=1`) accepts only:

- IPv4, total-length field **equal** to bytes present, not fragmented, UDP/17,
  dest = ours, dest port 53, QR==0, src ≠ ours, source port ≠ 0.

Packets `claim()` refuses pass through to the wrapped device untouched. Under
`-forward` that is the kernel tun: a claimed-shape-but-malformed UDP/53 can
reach a host resolver (e.g. AdGuard) that **does** log. The no-per-query-log
guarantee covers queries this responder claims, not that fall-through.

Limits (constants in `resolve.go`):

| Constant | Value | Role |
|---|---|---|
| `dnsDefaultTimeout` | 5s | one upstream exchange |
| `dnsDefaultMaxInFlight` | 32 | process-wide |
| `dnsDefaultMaxInFlightPerClient` | 8 | per session |
| `resolverInboxDepth` | 256 | queued replies |
| `dnsUpstreamReadCap` | 4096 | read then measure; oversize → TC path |

Over the in-flight cap, queries are **dropped and counted**, not queued.

`validateResolverMode` refuses (suite green, `-count=1`): empty upstream;
hostname; missing port; port 0; IPv6; upstream == `-inner-v4`; upstream ==
`-router-v4`; upstream inside `-forward-cidr`; `-resolver-upstream` or
non-default `-resolver-timeout` without `-resolver`; non-positive timeout.

TCP/53 (`resolve_tcp.go`) starts **only when both `-forward` and `-resolver`
are on**. That bind needs `CAP_NET_BIND_SERVICE`. Resolver without forward
must not gain it: there is no tun address, and a successful bind would be on a
host address including the WAN. `TestResolverTCPNotStartedWithoutForward` PASS.

Privacy: this file logs **nothing** per query (no name, no client address, no
upstream address). Counters are aggregate. Every name still passes through this
process in the clear and is seen by `-resolver-upstream`. Choose that upstream
deliberately. The install script's recommended value on a data-plane node is
`127.0.0.1:53` (AdGuard on loopback, not `10.8.1.1` on awg0). This runbook does
not default it; the binary will not either.

### 5.2 What the signed descriptor would advertise

Hub (`server/wins_control_plane_setup_ONETOUCH.sh`):

```
WINN3_DESCRIPTOR_FORMAT_VERSION = 3
```

`inner_resolver_v4` is in the required field set, a dotted quad, validated
in-pool. Hub does **not** require `inner_resolver_v4 == inner_router_v4`.

Client (`lib/winn_protocol_dispatch.dart` and the copy under
`tools/native_messaging/host/lib/`):

```
const int kWinn3DescriptorFormatVersion = 2;
```

A v3 descriptor fails `descriptor-unsupported-format-version` and the node
serves winn/1 — unavailable, **never black-holed**. The field is read when
present, shape-checked when present, and emitted into `[winn]` only when
`descriptor.innerResolverV4.isNotEmpty`. Desktop parsers refuse unknown keys;
unconditional emission would take Linux/Windows down.

Signatures on the shipped client are **Ed25519**, not ML-DSA-65. Hub:
`WINN3_DESCRIPTOR_SUPPORTED_ALGS = (WINN3_DESCRIPTOR_ALG_ED25519,)`. The
comment in that file states the design wants ML-DSA-65 and the shipped
verifiers do not implement it. Do not write "ML-DSA-65-signed descriptor" as
an operational fact.

### 5.3 What clients do with it

Apple `WinsWinn3Resolvers` and Android `WinnV3Resolvers` derive "is this
resolver inside my tunnel". The next-hop (`inner_router_v4`) is accepted as a
resolver **only when the signed descriptor names a resolver at that same
address** (`if advertised.isEmpty || ipv4Value(advertised) != candidate`).
When named, the candidate list **replaces** rather than joins `[Interface] DNS`
(which on Apple is filled with public Quad9 literals). Needles pinned by
`StandaloneMobileResolverGuards`.

Desktop: `BuildPromotedPosture` refuses an empty `dns_servers` list
(`StandaloneResolverGuards`). Linux/Windows **store** `inner_resolver_v4` and
do **not** yet consume it into that derivation (`StandaloneResolverStagingGuards`).

Client derivation floor is a **/24 around the client's own `inner_v4`**. Hub
default pool is a **/16**. `resolverDerivationWarning` fires when `-forward-cidr`
is wider than /24 (`TestResolverDerivationWarningFiresOnAPoolWiderThanA24` PASS).
Keep the allocation pool inside one /24, or the descriptor field has to state
the address rather than leaving hosts to derive it.

### 5.4 Ordering — this is the safety property

`StandaloneResolverStagingGuards` Why, measured in `winn3/conform/conform.go`:

> If a descriptor advertises `inner_resolver_v4` before that responder is
> verified live, all four hosts stop refusing and promote GREEN: the route set
> moves, DNS points at an inner address, and nothing is listening. Names fail
> or — worse, in `-forward` mode with no forwarding verified — names resolve
> and every TCP connection black-holes while the UI reads Connected. That is
> strictly worse than today's refusal.

**Stand the resolver up and verify it answers through a real tunnel before
anything advertises it.** Bumping `kWinn3DescriptorFormatVersion` from 2 to 3
is the **last** step, owner-gated, and is a credential/descriptor re-sign this
lane must not perform.

`-resolver` on a running gateway **still advertises nothing**. Clients keep
refusing. That is correct.

### 5.5 systemd / install wiring

`WINN3_GATEWAY_RESOLVER` defaults to **0**. At 0, `write_unit()` appends no
`-resolver*` flags. Setting `WINN3_GATEWAY_RESOLVER_UPSTREAM` at 0 is refused
by `validate_config` (same bar as `validateResolverMode`).

At `RESOLVER=1`: three ExecStart flags (`-resolver`, `-resolver-upstream`,
`-resolver-timeout`). UDP needs no sandbox change.

At `FORWARD=1` **and** `RESOLVER=1`: `CAP_NET_BIND_SERVICE` on both
CapabilityBoundingSet and AmbientCapabilities for TCP/53. Resolver without
forward must not gain it.

Editing the env file and restarting does **not** add these flags. Re-run the
install script so `write_unit()` bakes them in.

Default unit shape (`WINN3_GATEWAY_FORWARD=0`, `WINN3_GATEWAY_RESOLVER=0`):
User=`winn3-gateway`, empty capabilities, `PrivateDevices=yes`, no writable
paths, `LimitNOFILE=8192`, `TasksMax=256`, session-derived `MemoryMax`
(default 64 sessions → `160M` / `MemoryHigh=120M` / `GOMEMLIMIT=96MiB`;
not a host-RAM percentage). Two credentials:
`static.key`, `admission.key`.

---

## 6. Install — do not follow the previous §4

Do **not** run `psql -f schema/postgres_v1.sql`. Do **not** select a
file-vs-Postgres unit. Do **not** confirm an AWG `preshared-key` contract for
this binary. Do **not** grant `CAP_NET_ADMIN` on the default (reflector) shape.

The generator is `server/wins_winn3_gateway_install.sh`. The checked-in
`deploy/systemd/winn3-gateway.service` is a reference for the default shape
only. There is **no** `winn3-gateway.env.example` in `deploy/systemd/`
(measured: `ls` → No such file). The install script writes
`/etc/winn/winn3-gateway.env`.

Step-by-step commands, host targeting, and the "resolver first, descriptor
last" deploy order: `source/wins_vpn/docs/WINN3_GATEWAY_DEPLOYMENT_RUNBOOK_20260812.md`.
That document is dated and scoped to a **fresh node**. It is not a grant to
touch Kansas or Spain.

This file does not duplicate that runbook. If the two disagree, prefer the
dated deploy runbook for commands and this file for "what the previous
OPERATIONS.md got wrong."

---

## 7. Monitoring

There is no `/healthz`, `/readyz`, or Prometheus endpoint on `winn3-gateway`.

```
journalctl -u winn3-gateway
```

is the only record. A node whose journal is volatile keeps no history across
reboot. Status documents go to stdout; refusals (including plan-floor
mismatches) go to rate-limited stderr.

Do not alert on `carrier_*` or `audit_*` names from the previous §9 for this
process; those metrics are not produced here.

---

## 8. What is not ready — do not ship around these

| Item | State (MEASURED) |
|---|---|
| `-resolver` default | **off** |
| Live query answered on a real node | **not claimed here** (no server contacted) |
| `-forward` default | **off**; reflector carries no user traffic |
| Client format version | **2** (hub is 3) |
| Desktop consumption of `inner_resolver_v4` | stored, **not** derived into DNS |
| Descriptor advertisement of `inner_resolver_v4` | **must not** happen before a live answer is verified |
| Demux-token / `gateway.Table` in this binary | **not used**; address demux only |
| ML-DSA-65 descriptor signatures | **not on the shipped client** (Ed25519) |
| Cover / decoy / ECH on this binary | **absent** (UDP, not TLS) |
| Revocation list | **absent** in winn3 |

A promotion that would install **no** resolver is refused on every client
platform. That refusal is the honest state. Turning it into a green tunnel
pointing at silence is a regression, not a ship.

---

## 9. Frozen hosts and credentials

- **Kansas `<KANSAS_IP>` and Spain `<NODE_ES_IP>`:** read-only, no
  `--deploy`, no `/api/v1/nodes/register` (it DELETEs colliding rows).
- **No credential operations:** no keystore, no certificate, no re-signing the
  descriptor, no bump of `kWinn3DescriptorFormatVersion` as a "fix".
- **Do not bring up a VPN tunnel on the operator's Mac.**
- Lab keys this process generates (`-mode keygen`) are 32-byte files; delete
  them after use; never print them.

---

## 10. How to read the previous file if you still need v2

The v2 control plane (TLS 1.3 + ECH + cover cert + Postgres + AWG PSK rotation)
is still in this module under `internal/*`, `cmd/winn-server`,
`cmd/winn-carrier-server`, `cmd/winn-token-issuer`. Its procedures are in
`OPERATIONS.md.bak_20260812_doc_operations`. They are **not** current
standalone-v3 operations. Do not cite that backup as authority for the
gateway datapath descriptor resolver.
