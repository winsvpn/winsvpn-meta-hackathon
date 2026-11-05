# CONTINUE.md -- Lane A ops (AI Router), workdir /Users/owner/xprize/router

> Historical Gemini-only continuation note. It is superseded by `README.md` and the current
> fail-closed Smart Router implementation. Current ordering is deterministic Winn v3 for
> connection initiation, local aicore vLLM Gemma on distress, bounded Google Gemini API
> fallback, then the same deterministic scorer. Hoppy is `/hoppy/escalate`. The Cloud Run
> URL below is not the target aicore Smart Router and must not be treated as live proof.

State: see PROGRESS.json. Authoritative receipt: receipts/prod_sanity.txt.
Router live at https://AI_ROUTER_HOST
(supervisor deploys; this lane never runs gcloud).

## Status snapshot (2026-08-17 16:05 UTC)

- New endpoints /favicon.ico /stats /decisions.csv are LIVE and 200 (verified
  fresh this run). The earlier 404 blocker is cleared.
- NEW PROBLEM: every live /route now returns source=fallback (0 gemini out of
  15+ posts this run; earlier today was 8 gemini / 2 fallback). Returns are
  instant (~0.4s), not 12s timeouts, so Gemini is erroring immediately on the
  deployed revision, not just slow. This run could not see the reason (old
  image has no diagnostics). The old image was redeployed with unpinned pip
  deps, but ALL pinned local versions were verified equal to current latest
  PyPI, so dependency drift is unlikely. Suspects: GEMINI_API_KEY /
  GEMINI_MODEL env not propagated to the new revision, or Gemini API
  degradation. Supervisor must check revision env + Cloud Run logs.
- This run's code changes are in the working tree, NOT yet deployed.

## Completed this run (do not redo)

1. Pinned requirements.txt to the exact versions proven in .venv
   (fastapi==0.141.1, uvicorn==0.52.3, google-genai==2.18.1, pydantic==2.13.4,
   pytest==9.1.1, httpx2==2.10.0). Each verified as current latest on PyPI, so
   the live/unpinned build would have resolved the same versions; pinning makes
   the deploy reproducible and auditable.
2. Ops self-diagnosis in main.py: every gemini failure is sanitized
   (token/API-key redaction, 200-char cap) into gemini_error, appended to the
   decision record (ring + JSONL), and exposed as /health.gemini_last_error.
   /health now also reports version 1.1.0 + deps (google-genai, fastapi,
   uvicorn, pydantic, starlette, httpx2) so the supervisor can confirm the
   deployed artifact matches this lane. Dashboard Routing stats card now shows
   a Gemini status line (configured / error: <kind> / no key).
3. Docker artifact validated locally: `docker build` succeeds with pinned
   versions; container smoke-tested on :8080 - health, root dashboard,
   favicon, stats, /route (deterministic without key), /decisions,
   /decisions.csv, /hoppy/escalate all correct; gemini_error surfaced
   correctly (\"GEMINI_API_KEY not configured\"). Image removed after test.
4. Tests: tests/test_router.py now 26 tests, all green
   (`.venv/bin/python -m pytest -q` -> 26 passed). New coverage: health
   diagnostics, gemini_error recorded + sanitized (fake key redacted from
   JSONL too), error clears on success, /stats 1h window excludes old
   records, CSV quotes embedded commas, malformed JSON -> 422, JSONL parent
   dir auto-created.
5. receipts/prod_sanity.sh re-run against the live URL -> 10/10 POST /route
   200, all new endpoints 200; receipts/prod_sanity.txt refreshed. Note the
   source mix is now all-fallback (see Status snapshot).

## OWNER-REQUIRED (blocking 100%)

1. Redeploy this lane from the updated Dockerfile (pinned requirements +
   diagnostics). The live instance currently runs the pre-diagnostics image.
2. On the new revision, verify GEMINI_API_KEY and GEMINI_MODEL are set, and
   check Cloud Run logs for the Gemini API error. After redeploy, watch
   /health.gemini_last_error and the dashboard Gemini status line: they will
   name the exact failure (e.g. API key invalid, model not found) on the
   first fallback post.
3. Re-run `bash receipts/prod_sanity.sh` and confirm /favicon.ico, /stats,
   /decisions.csv return 200 AND that at least some /route posts come back
   source=gemini before recording the demo video (a mixed
   gemini/fallback /stats card is the intended evidence).
4. Point the evidence pack at GET /decisions.csv (one URL) once live.
5. Optional: seed a few demo /route posts before the video so the dashboard
   stats card and timeline have content on first load.

## Gotchas

- Cloud Run is stateless per instance; DECISIONS ring lives in memory and
  /decisions, /stats, /decisions.csv all read the ring. The JSONL audit log
  (DECISIONS_FILE, default /tmp/router_decisions.jsonl) is the durable trail.
- Budget: ROUTING_BUDGET_S=12.0 in main.py wraps the gemini call;
  DEADLINE_MS=10000 in gemini_client.py is the SDK HTTP deadline. The old
  \"2.0s deadline\" wording in README/LANE_REPORT was stale; corrected.
- Live model is gemini-3-flash-preview (set by GEMINI_MODEL at deploy); local
  default remains gemini-2.5-flash. /health reports the live value.
- No secrets in this lane's files. gemini_error is sanitized (API-key/token
  patterns redacted) before it lands in the ring or JSONL.

## Boundaries still in force

No git. No secrets (GEMINI_API_KEY is env-only at deploy). No gcloud from this
lane. Nothing written outside /Users/owner/xprize/router except the deployed
service itself.
