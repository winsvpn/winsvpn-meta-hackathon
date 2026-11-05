# Winn Protocol v3 — adversarial security review via Fugu Ultra

> ## STALE LINE CITATIONS — read the tree, not this document, before acting
>
> **Written 12:05 on 2026-08-03. The code moved the same afternoon.** Findings 1
> and 2 were substantially fixed within the hour, and **none of their line
> citations resolve against current source** — the burst at `envelope.go:218-228`
> and the `outerSize` at `388-391` no longer exist. Finding 3 was largely closed
> by the cover profile rather than by the curve list. Finding 4's line numbers
> have also moved (`tlsconfig.go` post-handshake re-verification is now near
> `401`, not `165`).
>
> A later lane was dispatched against these citations without checking the tree
> first and spent most of its run rediscovering that the work was already done.
> **Do not repeat that.** The *findings* remain accurate as descriptions of
> defect classes; the *locations and severities* are a snapshot of a tree that
> was being edited by several lanes at once.
>
> Current status of the four HIGH findings is tracked in section 10 of
> `docs/handoff/COMBINED_HANDOFF_ALL_FIVE_20260731.md`, which is maintained.


Reviewer: `fugu-ultra-20260615` (dated snapshot, every response payload echoes the
id; no fallback was used). Date 2026-08-03. Raw reviewer output and pinned file
snapshots with SHA-256 manifests are in the session scratchpad as `unit_*.md` and
`snapshots/<unit>/`.

## Verification tally

| Metric | Count |
|---|---|
| Findings claimed by Fugu | 10 |
| **Confirmed** | **9** |
| **Rejected** | **1** |
| Fabricated files, functions or organisations | **0** |
| Line-citation blocks checked against source | 34 |
| **Exact** | **34 / 34 (100%)** |
| Flagged but declined as findings | 5 (4 safe, 1 real) |

**Why 34/34 against the prior review's 1/17:** every file was sent with line
numbers already in the left margin, so the model transcribed rather than
estimated. That single change converts verification from judgement into string
comparison. Mandate it for all future automated review.

Fugu never manufactured a finding. In five places it explicitly refused to claim
a defect it could not substantiate, including one it correctly identified as
potentially CRITICAL.

## The tree moved mid-review

`internal/pqauth/pqauth.go` (688 to 704 lines, 11:13:10) and
`internal/carrierauth/auth.go` (702 to 739 lines, 11:16:13) changed **while units
were in flight**. `pqauth.go` changed after its unit had read it, which would have
made every line number in that unit appear wrong through no fault of the model.
Snapshot-pinning was added and the unit re-run; all line numbers below are
verified against the exact bytes the reviewer saw.

Confirmed unchanged throughout: `protocol.go`, `tlsconfig.go`, `envelope.go`,
`relay.go`, `relay_batch.go`, `carrier/authentication.go`, `replay.go`, `ech.go`.
Actively moving: `internal/carrier/h3.go`, `h2.go`, `supplied_socket.go`,
`h3_migration.go`, `datapath/`, `clientbinding/`, `cshared/`, `cdatapath/`.

---

## Findings, ranked as an external auditor would

The top four are one story: **the cryptography is conservative and well built; the
wire behaviour is conspicuous.** For a tool whose users face physical risk on
identification, that is the audit's centre of gravity.

### 1. HIGH — MTU probe emits a protocol-identifying burst on every connection
`internal/carrier/envelope.go:218-228` (burst), `235-253` (retry), constants
`19-22`. Three identical max-size datagrams back to back at setup, then
retransmits every **300 ms** up to 16 times over 2 s, requiring an ACK of
*exactly* the same size (`count != requiredOuterSize` rejected at 272).
Unconditional on both carriers (`h2.go:616`, `h3.go:701`); failure aborts the
connection. **The strongest fingerprint finding: no ClientHello mimicry hides it,
because it is a behavioural signature in packet sizes and timing.**

### 2. HIGH — Length padding is off by default and hard-disabled on the Linux auto path
`envelope.go:388-391`. `outerSize` returns `minimum` (16 + payload length) when
padding is off, leaking inner datagram lengths 1:1. `PrivacyPadding` is
`privacyProfile == PrivacyHighRisk` (`cmd/winn-carrier-client/main.go:339,355`)
and **hardcoded `false`** at `internal/linuxauto/h3_builder.go:269`. The bucket
list `{256,512,...,1516}` — the actual defence — is inert in the default config
and unreachable on one shipped path.

### 3. HIGH — Single-group `CurvePreferences` gives an active prober a clean oracle
`internal/tlsconfig/tlsconfig.go:83-88` (server), `132-137` (client). A prober
offering only X25519/secp256r1 gets `handshake_failure` where any real origin
negotiates. Mandatory ECH means the differential confirms rather than discovers.
**May be partly addressed by the probe-resistance work landed the same day; verify
against the current tree.**

### 4. HIGH (Fugu said CRITICAL, downgraded here) — Distinctive, stable ClientHello
Same lines. Claim verified exactly, severity reduced because the attribution is
incomplete: a Go `crypto/tls` ClientHello is already trivially distinguishable
from a browser's regardless of these settings. **The real finding is that there is
no ClientHello mimicry layer at all** (no uTLS equivalent). Fixing the curve list
alone would not change blockability.

### 5. MEDIUM — Identity-mode replay protection is process-local
`replay.go:14-18` is a bare in-process map, consumed at `auth.go:297`, window
plus or minus 2 minutes (`auth.go:262-267`). A captured valid request replays
**across a restart** and **across load-balanced instances**. Signature
verification precedes cache consumption, so nonces cannot be burned
unauthenticated.

**The asymmetry is the finding.** Anonymous-token redemption is required to be
durable (`carrier/authentication.go:88-93`) and is genuinely atomic:
`internal/state/redemption_postgres.go:134-147` uses `INSERT ... ON CONFLICT
(token_id) DO NOTHING` inside a `Serializable` transaction. Anonymous mode is safe
cross-instance; identity mode gets no equivalent backstop.

### 6. MEDIUM — Nil `ExpectedLocalPeer` lets any local process latch the relay peer
`relay.go:55-60, 85, 142-145, 275-281`. With no expected peer the **first** local
UDP sender is pinned for the connection lifetime. A co-resident process winning
the startup race causes tunnel denial of service and receives all carrier-to-local
packet cadence, a local oracle confirming the user runs the tool.

Two production paths do set it (`directawg/candidate.go:317`,
`h3candidate/linux_awg_adapter.go:216`) but **`cmd/winn-carrier-client/main.go:441`
calls `RelayLocalUDP` with `RelayConfig{MaxDatagram: maxDatagram}` and no
`ExpectedLocalPeer`. The vulnerable path is live in a shipped binary.**

### 7. MEDIUM — `ErrReplayAtLimit` lets one credentialed principal deny service
`replay.go:45-55`. At capacity only *expired* entries are evicted; if full of
unexpired ones, every subsequent request from **any** device or token is refused.
One valid credential can pack the single global map with entries living about
twice the skew window. The O(n) sweep under a single lock amplifies it.

### 8. LOW — Malformed carrier envelope tears down the relay
`envelope.go:118-131`. `ReadFrom` drops only `envelopeCover` and
`envelopeProbeAck`; everything else returns an error, including `envelopeProbe`
(=2), which **decodes cleanly** at `446` but has no case in the switch.
`relay.go:241-252` and `304-315` escalate that to teardown, and
`relay_batch.go:170-173` returns `(0, err)` which is exactly what the teardown
branches consume. Bounded to a malicious carrier (authenticated peer), so LOW, but
it is a stealthy intermittent-kill primitive and the fail-soft pattern already
exists two lines above.

### 9. LOW — `canonical()` is not byte-injective for non-UTF-8 header fields
`auth.go:494-500`. `json.Marshal` coerces invalid UTF-8 to U+FFFD while
`validateRequestClaims` (`629-631`) constrains `UDPTarget` only for emptiness and
length, and `245-247` compares raw bytes. Two raw targets differing only in
invalid UTF-8 collapse to one signing string. Requires invalid-UTF-8 identifiers
in config, unrealistic for `host:port`.

### 10. LOW — `ReadPublicIntegrity` provides no cryptographic integrity
`internal/securefile/securefile.go:339-351`. `readLimited` does Lstat, regular-file
check, group and other-writable rejection, TOCTOU-safe `os.SameFile` recheck and
size limiting — careful filesystem hygiene, but **no hash and no signature**. The
`sha256` in that file belongs to an unrelated helper. **The name invites false
reasoning and already misled the reviewer** into calling the registry
integrity-checked.

---

## Rejected: `winn/2` control-plane downgrade

`protocol.go:19-20, 152-153, 205-206, 270, 275, 322, 363` — all eight citations
exact. The exploit needed v2 and v3 coexistence. **The precondition is false.**
`RekeyPath = "/v2/rekeys"` is the only rekey path, one listener
(`bootstrap/server.go:77`), one client (`bootstrap/client.go:165`). There is no
`/v3/rekeys`.

**There is no version negotiation anywhere.** Every check is strict equality
against a single constant. `winn/2`, `winn/3` and carrierauth `"3"` are constants
of three *different* sub-protocols, not two versions of one.
`connectivity.Version` is telemetry only.

Retained as a naming observation: a v3 product whose control plane says v2 will
cost an external auditor time and invite this exact false positive again.

Fugu is not penalised: it set CONFIDENCE MEDIUM, called the exploit
deployment-conditional, and wrote that absent a v2 listener the effect degrades to
interop failure rather than a crypto downgrade.

---

## Examined and found sound

- **Hybrid KEM, the strongest part of the design. It is not hand-rolled**: Go's
  `crypto/tls` `X25519MLKEM768` / `SecP256r1MLKEM768` / `SecP384r1MLKEM1024`,
  selected via `CurvePreferences` and **re-verified post-handshake** at
  `tlsconfig.go:165` (`if state.CurveID != suite.Curve`). Neither component is
  load-bearing alone. **`internal/pqauth` is ML-DSA signatures, not ML-KEM** — it
  is the PQ authentication layer, not the KEM.
- **Transcript binding: the classic bug is absent.** `RekeyRequest` 12 fields to
  11 signed, `RekeyResponse` 16 to 15, only `auth_signature` omitted. Response
  bound to request across 6 fields including random `RequestID`/`Nonce`;
  generation must be exactly current+1; `key_id` recomputed and constant-time
  compared; all-zero PSK and pubkey rejected in constant time.
- **ML-DSA is actually verified**: `bootstrap/server.go:190`, `client.go:211`,
  unconditional, fails closed with 401 before any state transaction.
- **Cross-protocol signature replay closed safe.** Rekey messages are prefixed
  `Winn-Protocol-v2/request\x00`; none of the eight valid domains equals that
  string, so rekey bytes can never parse as `domain||0x00||message`.
- **ECH is genuinely enforced**: `ech.go:194-206`, `223-234` reject unless
  `state.ECHAccepted`; all 10 call sites pass `true`, verified individually.
- **Envelope parsing is memory-safe and not reachable by a network adversary** —
  envelope bytes arrive over authenticated TLS/QUIC, so only a malicious carrier
  reaches the parser. **The plaintext `"WCF2"` magic is encrypted on the wire and
  is not a DPI signature**, a natural false positive that was never claimed.
- Buffer-pool accounting traced exhaustively: no double-return, no starvation
  deadlock, every blocking point has a shutdown escape.
- Mode confusion closed (identity rejects tokens, anonymous rejects client
  certs); ordering correct (verify, replay, redeem); header duplication closed by
  `oneHeader` collapsing to `""`.

## Not covered

10 files across 6 packages, of 325 non-test files and 92 packages. **Not
reviewed:** `internal/masque`, `internal/directawg`, `privacytoken` internals (the
RSA blind-signature construction itself; token *use* was reviewed), `wcf3`, `pki`,
`identity`, `state`, `rotation`, `gatewaymanifest`, `transparency`, all of `cmd/`.

`h3.go` (1301 lines) and `h2.go` (811 lines) were read for context but **not
submitted as units** because they were being edited throughout. They hold the ECH
dial path, H3 migration and retry choreography, and are **the obvious next target
for fingerprint review**.

No key material was encountered in any file read.

## Operational note

Fugu Ultra is an orchestrator: 33k to 49k orchestration tokens and 345 to 1569
seconds per unit. **Three of eight dispatches timed out at 900 s returning zero
bytes** when run 3 to 4 concurrent; dropping to 2 or fewer concurrent with a 2400 s
timeout fixed it. Successful units consumed about 208k billed tokens plus about
460k orchestration tokens.
