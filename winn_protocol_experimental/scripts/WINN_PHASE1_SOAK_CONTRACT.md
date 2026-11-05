# Winn Phase 1 soak controller — contract

## What this is, and what it is not

This is a **harness**. It is **not** the production Phase 1 Auto soak, and no
artifact it produces is promotable.

The production soak requires three things that do not exist yet:

1. the real multi-gateway topology,
2. a real seven-day execution on that topology,
3. a controller-side finalization performed **off** the producing host, over
   retrieved evidence.

This controller performs none of them. It signs nothing, seals no terminal
audit checkpoint, and creates no anchor artifact. Every summary it writes
carries `"promotable": false` and a non-promotion notice as a field, so a file
found on its own months from now still says so. Nothing in the program can
suppress or parameterise that notice.

Until an actual seven-day run completes on the real topology and is finalized
off-host, **no result here may be cited as a passed gate**.

## Components

| Path | Role |
| --- | --- |
| `cmd/winn-phase1-soak-controller/` | The controller. |
| `cmd/winn-phase1-soak-success-fixture/` | Strict synthetic repeated-success runner for bounded non-promotable controller micro-soaks. It is not the Auto runner. |
| `scripts/aicore_phase1_continuous_soak.sh` | Operator front end: computes pins, asserts custody separation, invokes the controller. Starts nothing by default. |
| `scripts/test_aicore_phase1_continuous_soak.sh` | Tests for the front end, driven against a fake controller. |

The accepted Phase 1 runner (`scripts/aicore_phase1_auto_matrix.sh`) and its
harness (`scripts/aicore_auto_e2e.sh`) are **not modified**. The controller
invokes the runner through an injected command contract and configures it
exactly the way the runner already expects: entirely through its environment.

## The injected command contract

```go
type CycleRunner interface {
        RunCycle(ctx context.Context, request CycleRequest) (CycleResult, error)
}
```

One cycle is one invocation of the accepted runner. The controller owns
scheduling, provenance, resumption, resource bounds and evidence; it owns no
measurement semantics at all and cannot inspect or reinterpret them.

The injection is not a testing convenience. A hang, a mid-cycle crash, a clock
rollback, a source drift between cycles, a duplicate controller and an
exact-nanosecond duration boundary cannot be provoked against the real runner
without a lab and a seven-day feedback loop. Every one of those is covered
against a fake runner.

A returned `error` means no result could be obtained (missing binary, failed
fork). A cycle that ran and exited non-zero returns `OutcomeFailed` with a nil
error. The two are counted separately and never merged.

## Guarantees, and their limits

### Duration

- Default exactly `168h`. Measured **monotonically**; the wall clock is used
  only for timestamps and for rollback detection, never to decide whether the
  soak is over.
- A resumed run **adds** to the elapsed time it had already served. It never
  restarts the clock. `Checkpoint.AccumulatedElapsedNanos` is the single field
  that carries this, and a resume that declared a different total duration is
  refused.
- **Limit:** the monotonic clock has no meaning across a reboot, so a resumed
  run cannot measure the gap it was down. Downtime is not counted as soak time.
  This is the conservative direction — a resumed run serves at least its full
  duration of actual running, never less — but it means a soak interrupted for
  a day finishes a day later in wall-clock terms.

### Crash safety

Resume is permitted **only** from a checkpoint that is both content-addressed
and authenticated. There is no repair path, no fallback to an older copy, and
no "resume anyway" flag. Fail-closed on: clock rollback, source drift (snapshot
tree, runner binary, verifier binary, source manifest, source digest, or any
pinned path), runner replacement, changed total duration, foreign run ID, and
disagreement between the checkpoint's cycle count and the receipt log's.

**What the checkpoint MAC establishes:** that the file was written by something
holding the run-local resume key, which lives 0600 in the controller's own
state directory. It stops an unprivileged local process handing the controller
a forged resume state.

**What it does not establish:** anything against the identity that runs the
controller. Where the runner executes as root, root reads the key. It is not an
evidence-signing key and not a finalizer seed.

### Custody separation

No finalizer seed and no evidence-signing key may exist on the producing host.
Both the wrapper and the controller refuse to start if known finalizer or
signing material is found in the environment or in the directories they are
given.

**This is not proof of absence.** The separation comes from never provisioning
the seed to the producing host at all. The scan catches the known ways that
discipline gets broken. `cmd/winn-audit` makes the same statement about its own
`-detect-finalizer-leaks`, and this is deliberately the weaker, controller-local
echo of it rather than a replacement.

### Snapshot integrity

Refused outright: union and interposing filesystems (`overlay`, `overlay2`,
`aufs`, `ecryptfs`, `fuse`, `fuseblk`), quarantined trees (an `INVALID`,
`QUARANTINE`, `.quarantine` or `.winn-quarantine` marker at the root or one
level below it, or a `com.apple.quarantine`/`user.winn.quarantine` extended
attribute on the root or any traversed entry), symlinked path components,
non-regular files anywhere in the tree, and empty trees.

The snapshot root is opened once with `O_DIRECTORY|O_NOFOLLOW`. The filesystem
decision uses `fstatfs` on that held descriptor; traversal uses
`openat`/`fstatat` relative to it and verifies device/inode continuity. Extended
attributes are listed and quarantine attributes verified with
`flistxattr`/`fgetxattr` on the held root, directory, or file descriptor, with
the attribute-name set compared before and after each inspection. A platform
or filesystem that cannot provide these descriptor-bound checks is refused
rather than downgraded to a pathname check. The original root pathname is
device/inode-verified again after traversal, so a same-UID rename-and-replace
cannot cause the mount policy, quarantine policy, and digest to describe
different trees.

A writable snapshot mount is refused unless `-allow-writable-snapshot` is
passed. The opt-out relaxes **immutability**, not attributability: a union
mount is still refused with the opt-out set, because a merged view's bytes are
not attributable to fixed storage however the mount is flagged.

The snapshot digest is recomputed and compared **before every cycle**, and the
digest each cycle ran against is recorded on that cycle's receipt.

**Limit:** immutability is enforced by re-verification (detection), not by the
kernel, unless the mount really is read-only.

### Concurrency

Two mechanisms, answering different questions:

- **The lock** (`flock` on the opened state-directory inode) *prevents* a
  second controller from starting. Locking the stable directory rather than
  the replaceable `soak.lock` child means replacing that marker does not create
  a new lock domain. The lock is released by the kernel however the process
  dies. It is advisory, and weak-to-absent on some network filesystems.
- **The instance nonce** *detects*, after the fact, that two controllers wrote
  to the same evidence. Every receipt and checkpoint carries it, and a resume
  chains the new nonce to its predecessor. **It prevents nothing.**

### Cleanup

The single most destructive thing this program could do on a shared host is
signal the wrong process. `killplan.go` is the only place a signal target is
computed, and it refuses three specific catastrophes by construction:

- `kill(-1, …)` — signals every process the caller may signal; as root, the
  machine.
- `kill(0, …)` — signals the controller's own process group, its parent shell
  and its siblings.
- `kill(-N, …)` where the child is not the group leader — signals whatever
  unrelated services share that group.

A group-scoped signal is used **only** when the child is confirmed to be the
leader of its own group, which means the group was created by `Setpgid` for
this child and contains nothing the controller did not cause to exist. If
`Getpgid` fails, nothing is signalled at all: not knowing which group a process
is in is the state in which guessing is unaffordable.

**No pid is ever read from a file or adopted from a previous process.** The
signal is sent *before* `Wait` reaps the child, so the pid is still reserved by
the kernel and cannot have been recycled by an unrelated service.

### Resource bounds

Bounded disk (log rotation with a hard `bytes × files` ceiling), a minimum-free-
space gate evaluated *before* each cycle, and per-cycle memory, CPU, thread and
descriptor metrics. On Linux, `/proc` sampling sums RSS, threads, and
descriptors across every live member of the controller-owned process group;
an unavailable procfs is reported as unsupported, not as a measured zero.
Configuration is refused if the log budget is not smaller than the free-space
floor — the two would otherwise contradict each other.

Process-group accounting is not a substitute for cgroup containment. Formal
Linux cycles create a dedicated cgroup-v2 child below the controller's
delegated systemd unit, place the runner atomically with clone-into-cgroup (not
a post-fork `cgroup.procs` race), account `memory.peak`/`pids.peak` and
all-member descriptors/threads, signal every member through pidfds for the TERM
grace, use `cgroup.kill` for KILL containment, require `populated=0`, and remove
only the empty child. The generated systemd command carries `Delegate=yes`.
It also carries `DelegateSubgroup=controller`: systemd places the controller
process in that exact subgroup while leaving the delegated unit root empty.
The controller verifies its live cgroup path ends in that exact subgroup,
opens the parent descriptor without symlink traversal, requires the parent's
`cgroup.procs` to be empty, enables `memory` and `pids` there, and creates each
cycle as a sibling of the controller subgroup. This is required by cgroup v2's
no-internal-process rule; attempting to enable domain controllers on the
controller's populated subgroup fails with `EBUSY`. The generated unit uses
`ProtectHome=read-only`, not `ProtectHome=yes`, because the accepted AICORE
snapshot and binaries may be rooted below `/root`; explicit `ReadOnlyPaths`
and `ReadWritePaths` still constrain the frozen and evidence namespaces.
After descriptor-relative removal, the held cgroupfs directory FD may retain
the kernfs synthetic link count of 2 (regular filesystems report 0). Cleanup
therefore accepts only 0 or 2 while still requiring the held device/inode/type
to remain exact, a bounded descriptor-relative parent census to contain no
sibling with that device/inode, and the old name to return `ENOENT` through the
retained parent descriptor. This rejects a final-window rename-and-replacement
that would otherwise delete the replacement while leaving the original cgroup
alive under a new sibling name.
Failure of any one of these steps refuses the cycle. This implementation still
requires its native AICORE integration gate before deployment.

There is **no unbounded stdout**. The child's output is bounded per cycle, the
final-N tail is retained in a bounded ring while the true byte count survives, the cycle log
rotates, and the controller's own output is bounded too.

A measurement that could not be taken never reports a violation.

### Evidence

Append-only JSONL receipts, one per cycle, with mandatory LF termination,
strictly increasing sequence numbers, a hash chain over the raw lines, running
totals on every line, and a validated instance/predecessor/resume nonce
lineage. Receipt and checkpoint decoding rejects duplicate, missing, and
unknown members. **The first failure is preserved** in a separate record
written with `O_EXCL`; later failures cannot overwrite it, and all of them
remain in the receipt log. File writes are write-all operations, and file plus
containing-directory durability failures stop the controller.

**Not detectable from the receipt log alone:** truncation of its tail. A
truncated prefix is a valid shorter log. It is caught by the checkpoint's cycle
count and the comparison in `planResume`, and this is stated in the test that
covers it rather than papered over.

**Load-bearing versus guard rail:** `Checkpoint.conservationError` inspects
counters read back from disk that can be edited, so it detects something real.
`receiptTotals.conservationError` inspects counts this program recomputes from
a closed outcome set, so within this program they cannot fail to balance — it is
a structural assertion against a future edit that adds an outcome and forgets to
count it. Mutation testing established the difference, and the comments now say
which is which.

### systemd

`-print-systemd-command` prints a `systemd-run` invocation. **It does not
execute one.** `systemdunit.go` imports nothing that can start a process, and a
test parses its own import list and fails if that changes. Neither the wrapper
nor the controller invokes `systemctl` or `systemd-run`.

## Verification performed

| Check | Result |
| --- | --- |
| `gofmt -l` | clean |
| `go vet` (darwin/arm64) | exit 0 |
| `go build` (linux/amd64, static) | exit 0 |
| `go test -race` (darwin/arm64, native) | exit 0 |
| `go test` (darwin/arm64, native) | exit 0 |
| Focused Linux descriptor/cgroup/remediation test execution (linux/amd64 container, snapshot fixtures on tmpfs) | exit 0 |
| `shellcheck` on both scripts | exit 0 |
| `test_aicore_phase1_continuous_soak.sh` | 54 checks, 0 failures |
| Synthetic success-fixture normal/race/vet and exact-environment smoke | exit 0 |
| Hardened self-exec fixture normal/race/vet plus actual Linux `/proc/self/exe --child` empty-environment smoke | exit 0 |
| Full Winn Go suite and full `go vet ./...` after adding the success fixture | exit 0 |
| Native AICORE `go test`, `go test -race`, and `go vet` after delegated-cgroup correction | exit 0 |
| One supervised AICORE receipt-v2 delegated-cgroup timeout canary | bounded PASS; non-promotable |
| Independent strict receipt-v2 replay and post-run cgroup/process census | PASS; zero survivors |
| Thirty-minute AICORE repeated-success micro-soak, 59 alternating warm/cold cycles | bounded PASS; non-promotable; zero survivors |

The earlier focused Linux execution used a cross-compiled static test binary
in a local container. It covers cgroup-v2 fake-kernel contracts, exact
runner-descriptor execution, lock/receipt/checkpoint/durability/hardlink/
directory-replacement/tail/process-accounting remediations, fd-bound
filesystem/xattr provenance, and same-UID snapshot-path replacement. After
the delegated-subgroup correction, the full normal and race suites plus vet
also ran natively on AICORE.

The supervised AICORE canary used `DelegateSubgroup=controller`, a fresh
read-only source snapshot, fresh state/evidence directories, and exactly one
synthetic cycle deliberately configured to time out. Receipt-v2 recorded
terminal `populated 0`/`frozen 0`, successful child removal, and the
descriptor-relative final-window checks; independent replay found no surviving
cycle cgroup, canary unit cgroup, removed inode, controller, runner, or
verifier. This closes the bounded native containment integration gate only.
It does not exercise the real runner or make the harness promotable.

The subsequent repeated-success micro-soak served 30 minutes and
1.390472821 seconds under the same explicit non-promotion boundary. All 59
alternating warm/cold cycles succeeded, strict receipt-v2 replay and the final
checkpoint/HMAC passed, and all 59 distinct child-cgroup inodes were absent
from cgroupfs and every live descriptor after exit. It still used only the
synthetic fixture. The fixture used root-owned `/usr/bin/true` in this completed
run; independent review accepted that as a limitation of this lifecycle-only
result because `/usr` was read-only and the host package verified clean. The
next-run fixture no longer depends on that unpinned child: it uses the same
pinned executable through `/proc/self/exe --child`, with an empty environment
and exact Linux smoke coverage. The hardening does not retroactively change the
completed evidence.

**Incidental finding:** the union-mount refusal fired against a real overlayfs
the first time the test binary ran inside a container, because a container's
own filesystem *is* overlay. That is production-condition evidence the gate
works, obtained by accident. Container runs now stage their trees on tmpfs.

## Residual deployment gates

None of the following has been done, and every one must be before this can run
for seven days:

1. **The real runner has not been driven.** One supervised synthetic timeout
   canary and one 30-minute repeated-success synthetic micro-soak ran on AICORE
   and proved bounded delegated-cgroup/receipt-v2 lifecycle paths. Neither used
   the real multi-gateway runner, carrier, anchor, or VPS topology.
2. **The `execRunner` fork/exec/signal/reap path has synthetic coverage, not
   real-runner evidence.** The controller copies the exact verified runner
   descriptor into a private sealed custody directory and executes that copy;
   a path-swap regression proves replacement of the original pathname does not
   change executed bytes. It still needs a supervised single-cycle run against
   the real runner before any long run.
3. **A real read-only snapshot must be created.** The `-allow-writable-snapshot`
   opt-out must not be used for a real run.
4. **The topology does not exist.** Gateways, carrier, anchors: the accepted
   runner's own prerequisites are unchanged and unmet.
5. **`ANCHOR_MODE` interaction is untested.** The controller passes the child
   environment through unexamined; whether a seven-day sequence of matrix
   invocations composes correctly with the runner's resume and anchor state has
   not been exercised.
6. **Controller finalization is deliberately absent.** It happens later, off the
   producing host, and is not implemented here.
7. **Only bounded synthetic units have been accepted.** The 30-minute
   repeated-success run is not the production sustained soak. No real-runner
   sustained-soak unit has been started, resumed, or accepted.
8. **Cadence, cycle timeout and cold schedule are unvalidated against reality.**
   The defaults are plausible, not measured.
9. **Native Linux containment is verified only for bounded synthetic paths.**
   Native normal/race/vet, clone-into-cgroup, terminal `populated=0`,
   held-descriptor identity/census, and empty-child removal pass on the real
   cgroup-v2 filesystem for both timeout and repeated-success fixtures. The
   real runner still needs a supervised single-cycle matrix covering natural
   success, explicit failure, TERM-grace completion, and forced `cgroup.kill`
   before any long run.
10. **No capacity planning has been done** for seven days of evidence at the
    configured cadence.

## Single-cycle real-runner handoff

The controller must not invoke the full matrix script directly. It invokes
`aicore_phase1_single_cycle_adapter.sh` with exactly these eight environment
names:

```text
READINESS
WINN_SOAK_ADAPTER_MODE
WINN_SOAK_CYCLE_SEQUENCE
WINN_SOAK_INSTANCE_NONCE
WINN_SOAK_MATRIX_RELATIVE_PATH
WINN_SOAK_MATRIX_SHA256
WINN_SOAK_PROFILE
WINN_SOAK_RUN_ID
```

The adapter validates the complete environment, binds the controller cycle to
one profile, one warm-or-cold readiness class, one attempt, and a unique matrix
ID, then selects `MATRIX_MODE=preflight` or `MATRIX_MODE=run`. The matrix path
is the exact relative path `scripts/aicore_phase1_auto_matrix.sh` inside the
controller's immutable working snapshot, and its SHA-256 is part of the
controller's pinned child environment. This is required because the controller
executes the adapter from a sealed descriptor copy with no sibling files. Any
extra name, noncanonical sequence, invalid nonce, missing/symbolic/mismatched
matrix script, or readiness/profile mismatch is terminal.

`MATRIX_MODE=preflight` is zero-write. It performs the input, digest, source,
profile, dependency, and custody checks before matrix-root creation and emits a
single `winn-phase1-auto-matrix-preflight/v1` ready line. It is not a topology
probe and does not authorize a run.

This adapter closes the controller-to-matrix cardinality mismatch only. The
current matrix harness still creates local namespaces and a local carrier. It
must not be described as the real four-node gateway/carrier/anchor topology.
Before a real controller cycle, the exact rebuilt Linux bundle and source
manifest, frozen profile, controller, external topology manifests, and
cloud-start authority must all be separately accepted.

## External-topology E0 boundary

`winn-real-topology-verify` is the only accepted E0 reader for a proposed
external topology bundle. It supports `-mode preflight` only and must reject
execution mode before accessing the bundle.

The bundle contains exactly `external-topology.json` plus these six public
files in the descriptor's fixed order:

```text
accepted-trust-state-v2.json
carrier-root-ca.pem
controller-pq-pins.json
gateway-manifest-v2.json
linux-profile.json
transparency.jsonl
```

The verifier retains the directory root, validates each file from that root,
repeats the exact directory census, parses the actual typed formats, and
cross-binds descriptor roles to the manifest and primary-entry profile.
Success means only `structurally-valid-nonauthorizing`; it explicitly leaves
live readiness, complete signature/trust freshness, runtime validation, and
authority false. It cannot start providers, acquire credentials, create
interfaces, contact nodes, or run a matrix.
