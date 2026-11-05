# aicore host-support snapshot

The router reconciliation is complete in repository source. `router/` is the
only AICORE Smart Router implementation and `router/install_aicore_router.sh`
is its only supported bare-host producer. This directory no longer contains a
router application, a `wins-edge-router.service` unit, a router environment
template, or router drop-ins. The retired bearer-authenticated `edge_router.py`
snapshot and its deployment path were deleted rather than retained as a second
security boundary.

The canonical service binds to loopback port 8090 and runs `router/main.py`
through the immutable release installed under `/opt/winsvpn-router`. Protected
requests use the contract in `router/README.md`: HMAC-SHA256 over the exact
method, path, timestamp, nonce, and body digest; a bounded timestamp window; a
durable SQLite nonce journal; and a per-source rate limit. An inbound
`Authorization: Bearer` header grants no access. `EDGE_ROUTER_SECRET` remains
only as a compatibility name for the HMAC key and is never a bearer token.

The old `/v1` Cursor proxy, `/api/chat` shim, `signals` plus `rt_ms` request
shape, and optional route protocol fields were not ported. Hoppy callers use
the HMAC-authenticated `/hoppy/escalate` endpoint. `/route` accepts only the
canonical closed-set request schema.

## Remaining host evidence

The files still present here record supporting AICORE host configuration:

- `systemd/vllm-gemma4.service` and its reviewed safety drop-in;
- `systemd/cloudflared-aicore.service`;
- `systemd/host-perf.service` and `usr-local-sbin/host-perf.sh`;
- `cloudflared/config.yml`, which records the single public hostname to
  loopback port 8090 and a final `http_status:404` fallback.

The Cloudflare token remains an owner-delivered secret at
`/home/aicore/.cloudflared/token.env`; it is not represented in this tree. The
router HMAC and optional provider credentials belong only in the root-owned
mode-0600 `/etc/winsvpn/router.env`, created from
`router/aicore.env.example` and parsed as data by the canonical installer.

## Deployment boundary

These host-support files remain evidence, not standalone deployment authority.
Do not copy a router unit or Python file from this directory. Run
`router/install_aicore_router.sh --preflight` and then the separately approved
`--deploy` mode at one exact audited revision. The installer's runtime verifier
rejects a noncanonical unit, a legacy environment path, or any
`wins-edge-router.service.d` drop-in before the service can start.
