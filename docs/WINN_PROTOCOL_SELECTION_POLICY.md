# Winn Protocol selection policy

Release contract for Win's VPN 1.0.15+30:

1. A valid served Winn Protocol v3 candidate is the primary route and is
   attempted first. The legacy `direct_awg_enabled` control-plane field applies
   only to the Winn v1 AWG leg and cannot suppress v3.
2. After an ordinary v3 liveness or connectivity failure, the app may select a
   different cover-bearing node only when the listing identifies it as Winn v1
   or leaves the version absent for legacy compatibility. A node labelled
   `protocol_version=winn/3` is never a v1 fallback, regardless of carrier.
3. A descriptor, signature, node-binding, authentication, replay, schema,
   platform, or native security refusal is terminal. It never authorizes v1.
4. Within Winn v1, AWG is always attempted before Xray. Learned UDP demotion,
   a TCP preference, and network history cannot reorder or remove the AWG
   attempt.
5. "Prefer TCP fallback" does not skip Winn v3 or the Winn v1 AWG lead. It
   pauses optional direct-address latency probes and applies only to the XRay
   fallback after a required direct attempt fails.
6. `WINS_FORCE_XRAY` is a compile-time diagnostic override for Winn v1 only.
   It cannot skip v3 and must be false in every release artifact.
7. Timeout, silence, packet loss, a running bridge, connection refused, DNS
   outcomes, stderr, exception text, process exit text, and free-form
   diagnostics never authorize v1 cover. Only structured OS errors
   ENETDOWN, ENETUNREACH, EHOSTDOWN, EHOSTUNREACH (Linux/Android 100/101/112/113;
   Darwin 50/51/64/65) and Windows WSAENETDOWN/WSAENETUNREACH/WSAEHOSTDOWN/
   WSAEHOSTUNREACH (10050/10051/10064/10065) may create `ordinary_connectivity`.
   Any security signal overrides ordinary. An Android proof timeout is
   `unknown_terminal` with no authorization token.
8. Each native backend holds one in-memory <=60s monotonic one-use grant bound
   to the start token, start generation, selection generation, failed v3 node,
   exact v1 target, and AWG-then-optional-Xray order. Direct user-selected
   primary v1 does not need that grant.

The behavioral policy lives in `lib/winn3_cover_fallback.dart`; the connect
orchestration in `lib/main.dart` consumes those decisions.
