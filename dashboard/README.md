# Local release-readiness dashboard

This dashboard is a local evidence viewer. It never discovers readiness from Git,
network services, cloud APIs, stores, credentials, handoffs, plans, or manually
entered percentages. A target starts at zero and only a current schema-4 receipt in
`.artifacts/dashboard/evidence/<target-id>.json` can add technical evidence credit.
Every card with `upload_targets` also requires every mapped canonical schema-v2
receipt in `.artifacts/upload-receipts/<upload-target-id>.json`, verified against
`.artifacts/release-inputs/RELEASE_INPUT_INDEX.json`, before any store-ready credit
or `ready` status is possible. The dashboard has 16 required upload targets for
release `1.0.16+33`. `macos-developer-id-app` is a seventeenth, optional
distribution receipt that is displayed separately and never affects App Store
percentage or status. Apple scope is iOS with embedded watchOS plus macOS, with no
tvOS target.

## Scoring contract

Each of the 20 targets has five 20-point dimensions:

| Dimension | Required evidence type | Required producer ID |
| --- | --- | --- |
| Engineering verification | `engineering_verification` | `engineering_gate` |
| Release artifact | `release_artifact_verification` | `artifact_gate` |
| Signing verification | `signature_verification` | `signature_gate` |
| Store metadata | `store_metadata_verification` | `store_metadata_gate` |
| Runtime proof | `runtime_verification` | `runtime_gate` |

The technical percentage is the sum of dimensions whose status is `pass` and whose
receipt timestamp, observation timestamp, artifact timestamps, artifact hashes,
ownership, permissions, and evidence contract all validate. Missing, failed, stale,
or invalid dimensions add zero. Missing receipts are pending, not PASS. Failed
producer checks are failed, not pending. Plans, handoffs, and unit-test files cannot
supply either engineering or store-upload credit.

The dashboard reports two independent evidence scores plus a gated store-ready score:

- Engineering/test evidence: percent of the 40 engineering dimensions
  (`engineering` and `runtime_proof` across 20 scored targets) that currently verify.
  A card's `engineering_readiness` is at most 40, never 100. Missing evidence is
  `0 / 40` and `0%`.
- Store-upload evidence: percent of the 16 required upload-target receipts that
  currently verify. Exact coverage is also shown as `verified / 16`, with pending
  (missing) and failed (invalid) counted separately from stale. Missing receipts
  are `0 / 16` and `0%`.
- Store-ready progress can equal technical progress only when a fresh
`release_blocker_audit` from `blocker_gate` is verified and the receipt declares no
owner or external blockers. For mapped cards, every cross-store schema-v2 receipt
must also pass the authoritative artifact, build receipt, producer, release freeze,
signing, obfuscation, privacy, freshness, and custody checks. Any declared blocker,
or a missing, failed, stale, invalid, substituted, or partial mapped receipt set,
forces store-ready progress to zero. Owner credentials are never dashboard evidence.
A blocker producer records their absence as owner blockers and stores only non-secret
audit output.

The snapshot also carries a named `current_posture` that cannot be inferred from
source files, worker pid files, `PROGRESS.json`, `LANE_REPORT.md`, or a proof-client
binary. Publication remains `DO-NOT-UPLOAD` even when card scores are complete.
Missing upload receipts are shown as `0 / 16`. A generic GCP card receipt is not a
valid fresh GCP proof. AGP stays `in progress` until dedicated Android and Wear
completion evidence exists. macOS release Python stays `owner prompt pending` until
dedicated owner-runtime evidence exists. Those named holds are listed as active
blocker categories.

Producer IDs are schema identities used to prevent a generic test receipt from being
relabelled as signing or store evidence. They are not cryptographic identities. The
authoritative producer for each ID must create the receipt and its evidence in one
local transaction.

## Freshness and file rules

- The current evidence window is 24 hours.
- Pending means required evidence is absent. Failed means a producer reported
  failure or the receipt is invalid. Stale means evidence is older than the window.
  Those three states are displayed separately and none of them is PASS.
- A referenced artifact older than the window is stale even if its receipt is new.
- An artifact changed after its observation is invalid.
- Receipt file time must match `generated_at` within five minutes.
- Receipts, artifacts, directories, and the evidence root must be owned by the local
  dashboard user and must not be group- or other-writable.
- Symlinks, hard-linked evidence files, missing files, hash mismatches, sensitive
  paths, handoffs, and blueprints are rejected.
- Generated snapshots have a short `snapshot_expires_at`. Consumers must not display
  expired snapshots.

## Local operation

Custody and signing gates run only during an explicit local sync. That phase writes
one bounded immutable cache file, `.artifacts/dashboard/cross-store-cache.json`.
HTTP GET and snapshot rendering are read-only: they consume that cache fail-closed
and never execute gates or create verification directories. A missing, stale, or
invalid cache cannot mint store-upload credit.

Generate one private atomic snapshot without starting a server:

```sh
./tools/sync_progress.sh
```

Continuously refresh the local snapshot every five seconds:

```sh
./tools/sync_progress.sh --watch 5
```

The watcher is opt-in and remains local. If evaluation fails, it writes an explicit
zero-evidence failure snapshot. Failure snapshot `status_counts` match the receipt
object statuses, including `unavailable`. If even the failure writer cannot run, it
removes the active snapshot so an earlier percentage cannot remain current.

The optional viewer binds only to `127.0.0.1`, allows only exact local Host values
and GET paths (`/`, `/index.html`, `/api/state`, `/app.js`), and serves no-store
responses. Query strings, absolute-form targets, and non-GET methods fail closed.
The HTML shell loads one validated script contract from `/app.js`. Edge inherits
Chrome engineering evidence while keeping its own upload receipt.

```sh
python3 dashboard/server.py --port 4210
```

The viewer is not required for snapshot generation.
