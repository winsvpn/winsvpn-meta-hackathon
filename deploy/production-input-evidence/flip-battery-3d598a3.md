# Flip verification battery — approved_sha 3d598a3 (transcribed 2026-09-04
from supervised session live-command outputs; provenance per line)

## Machine proofs (re-read 2026-09-04T01:11:06Z)
- HEAD: 3d598a37352e1edf87627ee45e96bd743f75e8c4, worktree clean
- git diff --stat d9d4fb6..HEAD: 4 files, +326/-23 (governance checklist,
  public fingerprint JSON, plan docs, website chat worker)
- git diff --quiet d9d4fb6 HEAD on apps/core/crates/go/xcode/linux/windows/android: exit 0
- git diff --stat a5d32a5..HEAD: 1 file, +53 (plan docs only)
- manifest committed blob = worktree blob: e75a3441708dc7d32937c9c5eb9fff78e5aa865f
- validator: STRUCTURALLY-VALID status=PENDING-OWNER-INPUT deployment_authorized=false no_authority_conferred=true

## Aicore trigger matrix 5/5 (2026-09-04, live edge-router :8090)
- ABSENT trigger: 200 source=fallback, trigger_absent_total +1, zero inference
- INITIATION: 200 source=fallback, zero inference
- EXPLICIT under initiation: 200 source=explicit selected exit-b
- MALFORMED trigger: 422
- DISTRESS: 200 source=local_gemma selected exit-a
- llm_calls_total delta across matrix: exactly 1 (distress only)

## Engine concurrency sweep, unique prompts (2026-09-04, RTX 5060 Ti)
- n=1: 5318.7 agg tok/s, p50 0.12s p95 0.12s, ok 1/1
- n=8: 32693.2 agg tok/s, p50 0.15s p95 0.15s, ok 8/8
- n=16: 47701.7 agg tok/s, p50 0.19s p95 0.21s, ok 16/16
- n=32: 64999.8 agg tok/s, p50 0.30s p95 0.31s, ok 32/32

## Mixed-load preemption, 12 chat + 8 distress (2026-09-04)
- route: ok 8/8, p50 1.61s p95 1.62s, sources all local_gemma
- chat: ok 12/12, p50 1.90s p95 1.97s, none spilled
- wall 2.0s

## Website live proofs, production (2026-09-03/04)
- mode:gemini model:gemini-3.8-flash, real AI answers (multiple probes)
- mode:meta model:muse-spark-1.3-contributor, real Muse answers (multiple probes incl. owner-failing question)

## Target health (2026-09-04)
- Kansas HUB_IP, Spain NODE_IP_ES1, Germany NODE_IP_DE1: up 4+ days, reachable, no /etc/winsvpn/role markers
- aicore edge: /health ok, vllm-gemma4 + wins-edge-router active
