# Release security fail-closed ruling, 2026-08-23

## Authority and scope

The owner authorized the final ship-readiness implementation and verification
program on 2026-08-23. This ruling records three security decisions that
reverse earlier availability or compatibility choices embedded in comments and
tests. It covers control-plane HTTP pinning, Winn Protocol v3 replay durability,
and signed descriptor binding. It does not authorize an implicit protocol
downgrade.

## Evidence considered

- The immutable-tag audit at `494408f8cafbea1ebc6de9aea98796f78e9f3432`
  demonstrated that a request could reach a CA-valid unpinned peer before the
  client rejected the response, and that redirects could forward activation
  credentials across origins.
- The same audit demonstrated that a replay-journal write failure could be
  followed by a restart and acceptance of the same initiation.
- Repository review at `a293d6c644944e02b43da8e20186e79bad04cb77`
  found that a valid signed descriptor was not bound to the node selected by
  the served configuration, and that client validation accepted algorithm,
  lifetime, and tag geometry the hub rejects.
- Fable 5 Max independently reviewed the relevant sources and recommended an
  exact-connection pin gate, durable-write-before-accept replay semantics, and
  explicit descriptor-to-node binding. Its unverified suggestions are not part
  of this ruling unless independently proven against the hub emitter and tests.

## Ruled decisions

### 1. Exact-connection control-plane pinning

Every pinned control-plane TLS connection must verify the leaf SPKI before any
HTTP request header or body byte is written to that connection. A successful
probe or a time-limited origin ledger is not authorization for a later
connection. Automatic redirects are disabled in the inner client. Any manual
redirect handling must verify each hop and must not forward credentials across
an origin change without a separately ruled allowlist.

Post-response certificate checks may remain as defense in depth, but they are
not the primary gate. Unsupported proxy connection paths fail closed.

### 2. Durable replay admission

When a replay journal is configured, a new Winn Protocol v3 initiation is not
accepted and no responder handshake is returned until the replay record is
durably appended. Append or rewrite failure refuses new initiations and remains
operator-visible. Existing transport sessions may continue until their normal
rekey or drain boundary. The failure path must stay wire-silent and must not
truncate, repair in place, or weaken the journal's atomic replacement sequence.

### 3. Descriptor schema and selected-node binding

A signed descriptor is necessary but not sufficient. Before standalone v3
starts, the client must verify that the normalized signed `node` equals the
node selected by the served configuration. A missing selected-node identity or
a mismatch is a named refusal before tunnel traffic is sent.

At descriptor format version 3, the client also enforces the hub's supported
algorithm, descriptor lifetime bounds, tag-size bounds, closed required and
optional field sets, and the required equality of `inner_resolver_v4` and
`inner_router_v4`. These schema rules were checked directly against the current
hub validator and descriptor signer before being locked here. A persisted
sequence rollback floor remains a separate design decision because it requires
secure storage, recovery, reinstall, and multi-node semantics.

## Anti-downgrade boundary

Failure of any ruled v3 check is a connection refusal. It never starts Winn v1,
AmneziaWG, Xray, or another carrier as an implicit fallback. Winn v1 over
AmneziaWG/Xray remains a required release capability only when the trusted
served configuration explicitly selects the v1 path.

## Release consequences

These decisions are release gates. Tests must prove zero request bytes at an
unpinned redirect target, refusal on replay-journal persistence failure, and
refusal for a descriptor whose node differs from the selected node. Fresh GCP
deployment and live carriage testing occur only after the local gates pass.
