# Winn v3 — Dual-Signature Session Authentication (spec)

Status: design approved (owner); core layer implemented; driver/hub provisioning integration staged.
Goal: peer authentication via **two mathematically independent signatures** over the session-binding
material, matching the patent claims, without changing what today's shipped apps and gateways do.

## Threat model framing
The property being added is AUTHENTICATION RESILIENCE (cryptographic agility): if either signature
family breaks (including a quantum break of a classical one), peer authentication still holds.
Confidentiality already has this shape (X25519 + ML-KEM-768). Detectability must not regress:
the new traffic is inside the AEAD (uniform-random), uses existing frame types, and is emitted
ONLY to clients that announced the capability.

## Chosen algorithms
- Ed25519 (classical, 64-byte signature). Std `crypto/ed25519`.
- ML-DSA-65 (post-quantum, 3309-byte signature). `internal/pqauth` (circl v1.6.3, already a dep).
Both sign the SAME message: `domain || 0x00 || transcriptHash`, with a NEW domain string
`"winn3-dual-auth-v1"` — the same `SignDomainMessage`/`VerifyDomainMessage` framing pqauth already
uses (internal/pqauth/pqauth.go:437, :461). Ed25519 uses the identical domain framing by hand.

Session-binding material = the handshake transcript hash `h` (core/transcript.go `chain.h`), which
already commits the protocol label, responder static, ephemeral, and the whole sealed init.
Transport frames (including the PQ ratchet) never fold into `h`, so both ends hold the same stable
`h` after the handshake — one value, two signatures over it.

## Where it goes on the wire (sizes)
Transport message ceiling on UDP ≈ 1402 bytes (VM-verified). Therefore:
- Ed25519 signature (64 B) → ONE new frame, `FrameDualAuthED`.
- ML-DSA-65 signature (3309 B) → ONE new frame type, `FrameDualAuthML`, carried through the EXISTING
  generic chunk machinery `chunkBlob`/`blobRx` (winn3/session/frames.go:85-160) — the same path the
  PQ ratchet blobs use. ~3 chunks on UDP; 1 on larger TCP carriers. Uniform-parseable, inside AEAD.

New frame types (core/frame.go, after FrameRekeyAck):
  FrameDualAuthED  — payload = 64-byte Ed25519 signature over the bound message.
  FrameDualAuthML  — payload = 3309-byte ML-DSA-65 signature, chunked like PQ blobs.

Emission point (gateway): immediately after the PQ ratchet completes (the same seam `MixPQ` uses,
doc.go's "post-handshake in-band" doctrine). Verify point (client): frames received and BOTH
signatures verified before the tun gate may reach Carrying, in strict mode only.

## Backward compatibility (non-negotiable)
Negotiation channel = the handshake payload flags byte, which is "reserved, must be zero, checked
on receipt" today (core/handshake.go:186). Define:
  handshakeFlagDualAuth = 0x01
- Shipped clients send flags=0 → new gateway treats as legacy → emits NO attestation frames.
  Shipped apps are bit-for-bit unaffected.
- New clients send flags=0x01 → gateway emits the two frames → client verifies both, fail-closed.
- Old gateway + new client: old code rejects nonzero flags (checked on receipt) → clean refusal,
  not a silent downgrade. Acceptable: post-fresh-deploy there are no old gateways.
- Receipt rule on new code: accept flags ∈ {0, 0x01}; reject any unknown bit (fail closed).

Client ATTESTATION-REQUIRED-ness additionally rides the hub descriptor (the same capabilities gate
that already serves winn/3 descriptors, `resolve_served_winn3_descriptor` emb. 4967): the hub includes
the gateway's two attestation public keys in the descriptor ONLY for clients advertising the new
capability, so a misprovisioned node is caught before the session, fail-closed.

## Key provisioning (gateway + hub)
- Gateway `keygen` (cmd/winn3-gateway/main.go:209): additionally write
  `auth_ed25519.seed` (32 B), `auth_ed25519.pub` (32 B), `auth_mldsa65.seed` (pqauth.GenerateSeed),
  `auth_mldsa65.pub` (pqauth signer PublicBytes).
- `serve`: `-dual-auth` flag (default OFF while a fleet is partially provisioned; ON in deploy
  for dual-provisioned nodes). Loads Ed25519 key + `pqauth.NewSigner("mldsa65", seed)`.
- Hub: descriptor gains OPTIONAL fields `auth_ed25519` (b64) and `auth_mldsa65` (b64), included only
  when the client capability demands dual-auth AND the node is dual-provisioned. Serve-path
  signature re-verification (P0-1 fix) already re-runs on every serve; the new fields ride inside
  the signed payload, so they inherit the same protection. Descriptor format stays v-current
  (optional fields) — no version bump, no old-client breakage (capability-gated).
- Client (Go host): derive DualAuthExpected from the descriptor: when the descriptor carries both
  auth keys, the client REQUIRES the attestation; otherwise behaves exactly as today.

## Client capability plumbing (how the gateway learns the client is dual-capable)
- Dart requests descriptor with capability `supports_winn3_dualauth` (new, sent by NEW app builds).
- New app config, minted by the hub, carries `dual_auth: true` → the Go client host sets
  DualAuthExpected=true and sets handshakeFlagDualAuth in its init.
- Gateway: if `-dual-auth` ON and init flags has 0x01 → emit attestation after PQ;
  if flags=0 → legacy (no frames). If ON but client sent no flag, session proceeds legacy —
  so partial fleets and mixed clients coexist.

## Gate integration (strict mode)
Client strict path (DualAuthExpected=true):
  Initiating (handshake+PQ) → DualAttesting (NEW internal state) → Established, where
  DualAttesting only exits when BOTH signatures verify against the descriptor keys. Any failure =
  session close `CloseDualAuthFailed` (fail-closed). Server side: nothing extra beyond emission;
  the server's own confidence is unchanged (it authenticated the client via SIGMA).
Client legacy path: exactly the current behavior — no new state, no new frames expected.

## Tests (each must be written before the integration lanes are called done)
- dualsign package: sign/verify round-trip (both algs); tamper → reject; wrong key → reject;
  domain confusion → reject; size assertions (64 / 2420).
- frames: FrameDualAuthML chunking round-trip via blobRx (idempotent retransmit).
- handshake flags: flags=0 legacy path byte-identical; flags=0x01 accepted; flags=0x80 rejected.
- driver integration: dual client+gateway reaches Carrying only after verify; garbage ML-DSA sig
  → session closed; legacy client against dual gateway → Carrying with NO extra frames (byte-level
  traffic check); legacy client against legacy gateway → unchanged vectors.
- interop/sim: gateway `-dual-auth` ON + probe `-dual-auth` → canary verdict still
  handshake=ok/replay-safe=ok/rekey=ok, plus `dual-auth=ok`; probe without flag → legacy ok.
- Hub: descriptor with dual keys served only to capable clients; serve-path re-verification still
  holds (P0-1 regression). Dart parser tolerates the new optional descriptor fields (new build only).

## Implementation anchors (for the lanes)
- core/frame.go:17-57 (FrameType enum) — add FrameDualAuthED, FrameDualAuthML.
- core/session.go:223-272 (accessors) — add `TranscriptHash() [HashSize]byte`.
- core/handshake.go:173-189 (encodeHandshakePayload) — flags bit + param; receipt check (~init
  decode site) — accept {0, 0x01}.
- session/frames.go:85-160 (chunkBlob/blobRx); driver.go:1780-1795 (frame dispatch — add the two
  cases mirroring PQEK/PQCT); driver.go:1063,1256,1892 (queuePQ emission seam — add attestation
  emission after completePQ).
- internal/pqauth/pqauth.go — no change (SignDomainMessage/VerifyDomainMessage exist).
- cmd/winn3-gateway/main.go:112 (keygen/serve flags) — keygen files + `-dual-auth`; emit hook.
- cmd/winn3-probe — `-dual-auth` flag + verdict line.
- server/wins_control_plane_setup_ONETOUCH.sh embedded hub — descriptor optional fields
  (validate/register/serve), capability constant `supports_winn3_dualauth`.
- lib/winn_protocol_dispatch.dart — descriptor parser tolerance for the two new optional fields;
  capability advertisement (new builds only).
- winn3/doc comments claiming ML-DSA-65 descriptor signing (E3/P1-2) — CORRECT them alongside.

## Lane plan (from the earlier estimate)
- L1 (this phase): core layer — frame types, transcript accessor, handshake flags, dualsign
  package, unit tests. DONE before driver work.
- L2: driver session integration (server emit + client verify + gate state) + frame re-assembly
  path + negative/fail-closed tests.
- L3: gateway keygen/serve flags + probe support + GCE end-to-end (legacy && dual matrices).
- L4: hub descriptor provisioning + Dart parser/capability (new builds) + doc-comment corrections.
- L5: security review pass (re-check: no new observable shape, no old-client regression,
  fail-closed ordering), then merge to winsvpnv3 and redeploy gate.
## STATUS (as of the last commit)
- L1 DONE: core layer — frame types, TranscriptHash, handshake capability flag (fail-closed), dualsign pkg (Ed25519 + ML-DSA-65 over the transcript, VerifyBoth), pqauth domain.
- L2 DONE: driver — gateway signs+emits post-PQ only to flag-bearing clients (chunked via chunkBlob/blobRx); client verifies both and only then opens the gate; deadline fail-closed (CloseDualAuthFailed appended, wire reasons never renumber); tests cover round-trip, legacy byte-compat, wrong-key fail-closed, unprovisioned wait. All session/core/carrier tests + race green.
- L3 DONE: gateway keygen (auth_ed25519.*, auth_mldsa65.*) + serve flags (both-or-neither, exact sizes); probe dual flags + verdict token; Runtime-proofed locally: DUAL client -> handshake=ok replay-safe=ok rekey=ok reflect=ok dual-auth=ok epoch=2 rekeys=1 (49/48); LEGACY client against the same gateway -> gate CARRYING + replay silent.
- L4 DONE (engine side): hub descriptor validator accepts the optional pair `auth_ed25519`/`auth_mldsa65` (exact 32/1952 bytes, both-or-neither, half-provisioned refused); they ride the signed payload so the serve-path signature re-verification (P0-1) covers them and legacy clients ignore them (read-key-based parsers). Go client host (cmd/winn-datapath) carries `dual_auth_ed25519_pub_path`/`dual_auth_mldsa65_pub_path` and, when both are set, builds the session with DualAuth Expected + both peer keys. System-side verification done via the runtime-proven gateway/probe pair.
- L4 GLUE DONE: Dart `Winn3Descriptor` parses the optional pair (both-or-neither, exact 32/1952 bytes, `hasDualAuth`), the INI writer emits `auth_ed25519`/`auth_mldsa65` only under the `WINS_WINN3_DUAL_AUTH` dart-define (default-off, so Linux/Windows parsers that refuse unknown keys are never handed them), and Android's `WinnV3Keys` decodes the pair and writes `auth_ed25519.pub`/`auth_mldsa65.pub` + the two document paths. Platform activation order: flip the define in a release build whose host parser accepts the names. Pending platform verification (repo rule): flutter analyze + connected-phone assembleDebug per AGENTS.md.
- L5 DONE (pass 1): no new observable wire shape (attestation frames are typed inside the AEAD, chunk sizes equal like PQ, only sent to flag-bearing clients); no old-client regression (L2 byte-compat test + L3 legacy runtime run); fail-closed ordering pinned by the wrong-key and unprovisioned tests. Full winn3+internal suites green.
