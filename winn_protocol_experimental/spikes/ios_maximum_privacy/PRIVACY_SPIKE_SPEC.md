# WCF3 iOS Maximum Privacy Spike Specification

Status: a signed Stage A harness was installed on the physical iPhone and has
never been launched; the one-time user-approved VPN configuration is still
outstanding.

The installed build has source digest
`d81e656de925bd0dcd097decb8065ee92d2aa7b10288d778bafc4908db262d5b`. **That
build predates the start-latency evidence work and no longer corresponds to
this source tree.** A new signed build is required before any physical run,
and its digest must be recomputed by `Scripts/build_device.sh`; the value
above must not be reused as if it described the current source. Build,
installation, and source-only tests are not physical feasibility evidence.

## Purpose and boundary

This spike answers one narrow question early: can a real iPhone Packet Tunnel
extension sustain WCF3 fixed cells, bounded shuffling, cover traffic, a
30-second tail, and make-before-break allocation without unbounded memory,
termination, or unacceptable incremental energy?

It is not the production Winn client, a network anonymity claim, a throughput
claim, or proof that AWG and hybrid post-quantum cryptography fit. Their measured
peak resource reserve must be added before Phase 1 can close.

## Memory design

Each `FixedCellRing` owns one 64-byte-aligned allocation of:

```text
512 slots × 1,024 bytes = 524,288 bytes
```

Two directions and two overlapping circuits therefore own exactly 2,097,152
cell bytes. Metadata arrays are allocated at initialization. Reset clears their
elements in place; rotation never creates a third pool. A full ring rejects the
next cell and increments a stable counter before invoking the encoder.

The shaper assigns each accepted cell a release deadline in the inclusive range
`now ... now+20ms`. Due-cell selection begins at a randomized slot offset and
does not allocate a shuffle list. The scheduler owns batching; there must never
be a timer or Swift task per cell.

## Cover semantics

The current plan contains two statements that are not equivalent:

1. send one cover cell per second in each direction while connected;
2. continue a 30-second cover tail after user traffic stops.

Both interpretations are implemented and evidence records which one ran:

- `continuousWhileConnected` is the conservative, normative spike condition.
  It emits one coalesced inbound/outbound pair every second until explicit Stop.
  A user-traffic-ended signal has no effect.
- `activityWithThirtySecondTail` is an experimental interpretation. It begins
  after user traffic, moves the tail deadline on activity, and stops 30 seconds
  after the most recent activity.

Late polling emits at most one pair, advances from the original phase, and
skips every already-missed interval. It never sends a catch-up burst and small
timer delays therefore cannot accumulate schedule drift. The real inbound cell
in Stage B must originate at the remote reflector; a locally fabricated inbound
cell is valid only for Stage A resource measurement.

Explicit Stop clears every cover deadline immediately. The device gate requires
the provider to acknowledge Stop within 250 ms and emit no later cover cell.

## Rotation semantics

The protocol rotation interval is 15 minutes. The spike preallocates exactly
two bidirectional circuit buffer sets. The five-second overlap limit exercises
allocation ownership and cleanup only; it is not a protocol commitment.

The normal matrix uses real 15-minute rotations. A separate accelerated
allocation test performs 500 rotations without claiming realistic network
behavior.

## Synthetic profiles

| Profile | Target fixed-cell rate per direction | Purpose |
|---|---:|---|
| idle | cover only | wakeup and tail baseline |
| low | 50 cells/s | interactive/low-rate |
| medium | 1,250 cells/s | approximately 10.24 Mbit/s |
| saturated | producer faster than drain | cap, backpressure, drop behavior |

The saturated producer must not change ring capacity or allocate overflow
storage.

## Measurement records

The extension samples at 1 Hz and writes bounded aggregates every 30 seconds:

- resident memory and physical footprint;
- current process-available memory as advisory data;
- user/system CPU time, interrupt/package-idle wakeups, and energy where
  available;
- thermal and Low Power Mode state;
- queue depth/high-watermark, accepts, emits, and drops;
- maximum observed queue delay;
- cover pairs, missed deadlines, and rotations.

Every schema `/3` JSONL line binds the protocol/frame versions, run ID, source
and artifact SHA-256, mode, profile, declared test-condition selector, matched
A/B pair UUID,
cover interpretation, frozen constants, device/OS, and success/failure event.
It also binds the selected duration, traffic-active duration, rotation cadence,
bounded p99 occupancy/delay aggregates, exact directional accepted/emitted/
pending/retired cover accounting, scheduling underdrive, active/standby
rotation state, maximum overlap, and accelerated-rotation memory extrema.
Failures and acknowledged Stops are retained. Raw JSONL is not authenticated;
the current collector hashes it. Authenticated import into Winn's HMAC-chained
measurement store remains a required later gate before these results can feed
a production score.

No record may contain a packet, address, reflector token, Apple identifier,
account, or secret.

## Start-latency evidence

Two separately named intervals are bound to one attempt nonce, run ID, source
digest, request time, and first-record digest:

- **A, diagnostic.** Provider request receipt to provider ready. Its start
  endpoint is in the first `started` record; its end endpoint can only be in
  the receipt, because `providerReady` is captured after that record has been
  written and hashed.
- **B, the acceptance metric.** Host request to the host's first observed
  `NEVPNStatus.connected`, delivered by notification rather than polling. The
  hard bound is 3,000,000,000 ns: exactly that value passes, one nanosecond
  more fails.

Missing, malformed, non-canonical, duplicated, late, mismatched, overflowing,
clock-order-violating, or over-bound evidence is rejected, and a provider
file/directory synchronization failure fails startup rather than producing a
receipt without the recorded barriers. `fsync-only` means bytes left the
kernel but may remain in a volatile device cache; it carries no power-loss
claim. Provider attestation schema
`winn-ios-privacy-spike-start-attestation/2` records the actual combined
provider evidence barrier.

The host receipt is schema `winn-ios-privacy-spike-start-receipt/2` and adds
required exact keys `evidenceDurabilityBarrier` (`f-fullfsync` or `fsync-only`),
`artifactScope` (exactly `activation-observation-not-attempt-success-or-persistence-timing`),
and `hostReceiptDurabilityScope` (exactly
`host-receipt-barrier-not-encoded-no-power-loss-claim`). A `/2` receipt must
never be interpreted as proof that host receipt persistence met the <=3 s
activation deadline, as overall attempt success, or as a power-loss guarantee.
Activation <=3 s and asynchronous evidence persistence are deliberately separate
claims. At runtime the host validates the receipt
`evidenceDurabilityBarrier` against the provider attestation before publishing
the receipt. The offline verifiers validate the recorded barrier and its
first-record binding; they do not receive a separate raw attestation and must
not claim to have independently reconstructed the provider's system call.

Every JSON trust boundary is checked for exact-case unique keys and required
presence recursively before typed decoding. Each wall-clock value must use the
bounded UTC RFC 3339 nanosecond grammar; values must be nondecreasing and
internally consistent with monotonic deltas. This is a consistency check
between clocks sampled by the same process, not proof that physical UTC was
correct. Verifiers copy caller-owned inputs into private `O_EXCL`/fsync
snapshots before validation so later pathname replacement cannot change the
bytes under review.

**What B proves, precisely.** Stage A installs only the synthetic RFC 2544
route, completes no remote handshake, and forwards no packet. Passing the
3.000-second bound proves that a physical iOS Packet Tunnel extension was
activated and observed connected in that time. It is **not** evidence of a
usable VPN connection and **not** a measurement of
time-to-first-protected-packet. The later real-network gate must measure the
first protected flow; that result cannot be derived from this one.

The Stage A provider can machine-observe its thermal and Low Power Mode state,
but the Wi-Fi/cellular, locked-screen, and unplugged labels are operator
declarations. `evidenceverify` and `matrixverify` validate their internal
consistency and coverage; they do not turn those labels into machine-observed
physical facts. A physical score additionally requires separately retained,
timestamp-bound device/host observations for radio interface, external-power
state, and lock interval. Until that evidence exists, a matrix PASS is only a
declared-condition Stage A result.

## Required physical matrix

1. Core and Maximum Privacy A/B, low/medium/saturated, foreground Wi-Fi.
2. Core and Maximum Privacy A/B, low/medium, screen locked on Wi-Fi.
3. Core and Maximum Privacy A/B, low/medium, unplugged cellular.
4. Low Power Mode low-profile run.
5. Twenty sleep/wake cycles.
6. Twenty Wi-Fi/cellular path changes.
7. Five hundred accelerated allocation rotations.
8. Eight-hour locked low-profile run.

Do not externally heat the phone. Saturated load may induce thermal pressure;
stop at critical thermal state and retain the failure.

## Early feasibility gates

- No crash, Jetsam, unexplained extension restart, or termination.
- No structure exceeds its compile-time capacity.
- After 15-minute warmup, resident-memory trend below 1 MiB/hour.
- Rotation returns to the single-active ownership state within 10 seconds.
- After 500 accelerated rotations, peak memory is no more than 1 MiB above the
  maximum observed in the first ten.
- Low/medium profiles have zero drops and p99 occupancy below 50%.
- Saturated mode remains bounded and reports controlled drops.
- No deliberate release deadline exceeds 20 ms; nominal low/medium internal
  p99 queue delay is at most 25 ms.
- Continuous cover schedules exactly one inbound/outbound pair each second
  without catch-up bursts.
- Explicit Stop completes within 250 ms with no later cover.
- Idle continuous-cover incremental wakeups are at most approximately 1.5/s
  after coalescing.
- Three matched energy runs show median Maximum Privacy overhead no greater
  than 20% over Core on Wi-Fi and 25% on cellular.
- Privacy policy constants are not weakened under thermal or Low Power Mode;
  user traffic is backpressured instead.

Battery A/B runs must be unplugged. Install and start the autonomous run,
disconnect USB, lock the phone, reconnect afterward, and collect the App Group
evidence.

For Core/Maximum Privacy energy A/B, use identical profile, duration, radio,
screen, thermal, and Low Power Mode state. Both modes execute the same
deterministic common-path workload; Maximum Privacy adds fixed cells, shaping,
cover, and rotation. Treat the kernel task-energy counter as comparative
evidence only and corroborate it with matched whole-device battery runs.

For energy and whole-device battery, run at least three matched repetitions of
each foreground-Wi-Fi and unplugged-cellular low/medium pair. The strict
cross-run matrix verifier requires those repetitions, exact common-path
unit/checksum equality, per-profile task-energy median overhead no greater than
the applicable limit, positive matched unplugged battery observations, and a
separate five-minute-or-longer idle A/B wakeup pair. Whole-device battery
percent is too coarse for a defensible exact 20%/25% ratio, so its median is
reported as corroboration rather than used as a false-precision gate.

The Stage A matrix does not satisfy items 5 or 6: sleep/wake and real radio-path
changes require Stage B's remote reflector. These are feasibility gates, not
published Efficiency or anonymity scores.
