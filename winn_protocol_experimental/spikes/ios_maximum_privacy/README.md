# Isolated iOS Maximum Privacy Feasibility Spike

This folder is a disposable, non-production iOS feasibility experiment for the
frozen Winn Protocol v3 Maximum Privacy data-path constants. It is deliberately
separate from the production Flutter application, `ios/`, `apple/`, CocoaPods,
and `.dart_tool`.

The buildable component today is `PrivacyCore`, a native Swift package that
contains:

- the byte-exact 64-byte WCF3 header and 1,024-byte privacy cell;
- a fixed-capacity, preallocated cell ring;
- a deterministic release-time shaper bounded to 20 milliseconds;
- continuous and activity-tail cover scheduling without catch-up bursts;
- two preallocated bidirectional circuit pools for bounded rotation overlap;
- a versioned JSONL measurement record and append-only writer;
- unit tests and a deterministic Go-generated cross-language WCF3 fixture.

`Host/` and `PacketTunnel/` now form a signed Stage A physical-device harness.
It exposes Core/Maximum Privacy, idle/low/medium/saturated, one-minute through
eight-hour duration, continuous/activity-tail, and protocol/accelerated
rotation selectors. It polls the extension's source-bound run status, performs
an acknowledged and measured Stop, and copies synchronized JSONL for
collection. The collector also reads the experimental App Group directly so
stop/failure evidence remains recoverable when provider messaging is gone.
`Scripts/generate_project.rb` remains the reproducible generator for the
minimal, isolated Xcode project.

As verified on 2026-07-24, the physical iPhone, Apple Development identity, and
isolated iOS host/provider profiles are available. A hardened schema `/3`,
source-bound Release build with source digest
`d81e656de925bd0dcd097decb8065ee92d2aa7b10288d778bafc4908db262d5b`
was installed on the physical device without launch. **That build predates the
start-latency evidence work and no longer matches this source tree**, so it
must be rebuilt and reinstalled before any physical run, with a freshly
computed digest. The user must still approve Apple's one-time
VPN-configuration prompt before the first run; no physical feasibility result
is claimed until collected device evidence passes the gates below.

Pre-approval hardening now includes:

- cover-aware drain credits, preventing the prior one-cell/second queue leak;
- exact enqueue timestamps, bounded p99 occupancy/delay evidence, and retained
  scheduling-underdrive time;
- distinct accepted and actually dequeued cover-cell counters;
- deadline-driven idle cover instead of a permanent 10 ms timer;
- a matched deterministic common-path workload in Core and Maximum Privacy;
- task-energy, process-available-memory, and 30-second delta aggregation;
- a physical traffic-stop phase for the 30-second activity-tail experiment;
- active/standby and maximum-overlap rotation evidence plus per-rotation memory
  extrema for the first ten and post-ten accelerated rotations; and
- an acknowledged Stop record whose separately fsynced host receipt binds the
  collected JSONL hash and checks the full host/provider round trip against
  250 ms; and
- a start-latency receipt, described below.

## Start-latency evidence, and exactly what it proves

Each start attempt carries a lowercase UUID nonce and the host's monotonic
request time as canonical decimal text. The host registers the
`NEVPNStatusDidChange` observer on the main queue **before** calling
`startVPNTunnel(options:)`, timestamps immediately before that call, permits
one active attempt, and captures the first `.connected` exactly once. The
provider timestamps its own receipt of the request as the first statement of
`startTunnel`, and after `setTunnelNetworkSettings` succeeds it records the
first `started` record, completes the recorded file and containing
directory synchronization barriers, hashes those exact bytes **including the
trailing line feed**,
captures `providerReady`, and only then completes startup. Attestation schema
`winn-ios-privacy-spike-start-attestation/2` records whether the combined
barrier was `f-fullfsync` or the explicitly weaker `fsync-only`. A
synchronize failure fails startup rather than being swallowed.

Host receipt and provider attestation are bound to the same nonce, run ID,
source digest, request time, and first-record digest, and the host compares
the provider's `WinnSpikeSourceDigest` with its own. Receipt schema
`winn-ios-privacy-spike-start-receipt/2` carries the provider evidence barrier
after the host validates it against the attestation. The receipt is published
off the main actor once as `<runID>.start-receipt.json` through a retained
directory descriptor with exclusive creation and file/directory
synchronization; a byte-identical republish re-establishes both barriers and
anything different fails closed. `evidenceverify` and `matrixverify` require
the exact `/2` fields and recompute the first-line digest, line feed included.

Receipt persistence may finish after its caller's completion deadline because
an in-flight kernel write or sync cannot be cancelled honestly. Every receipt
therefore carries
`activation-observation-not-attempt-success-or-persistence-timing`. Because
the host cannot encode its own publication outcome into the immutable bytes
whose publication produces that outcome, it also carries
`host-receipt-barrier-not-encoded-no-power-loss-claim`. Receipt existence
proves neither persistence-before-deadline, attempt success, nor that the
tunnel remained connected.

**Scope, and it is narrow.** Stage A installs only the synthetic RFC 2544
route, performs no remote handshake, and forwards no packet. A host-observed
`NEVPNStatus.connected` within 3.000 s therefore proves **physical iOS Packet
Tunnel activation and nothing else**. It does **not** prove a usable VPN
connection and it does **not** measure time-to-first-protected-packet. That
measurement belongs to the later real-network gate, which must measure the
first protected flow, and cannot be inferred from any value in this spike.

Stage B remains separately required for real remote inbound cover, radio/path
changes, and Wi-Fi/cellular forwarding behavior.

## Frozen values

| Property | Value |
|---|---:|
| WCF3 header | 64 bytes |
| Privacy cell | 1,024 bytes |
| Privacy payload | 960 bytes |
| Per-direction ring | 512 cells |
| Maximum circuits during overlap | 2 |
| Preallocated cell storage | 2 MiB |
| Shuffle window | 0–20 ms |
| Cover | 1 cell/s in each direction |
| Cover tail | 30 seconds |
| Circuit rotation | 15 minutes |
| Spike-only maximum overlap | 5 seconds |

The five-second overlap is an experimental memory-stress setting, not a frozen
wire-protocol value.

## Local verification

```zsh
cd /Users/winsvpn/Downloads/wins_vpn/winn_protocol_experimental/spikes/ios_maximum_privacy
./Scripts/verify.sh
./Scripts/preflight.sh
```

`verify.sh` and `preflight.sh` must both pass. A Simulator build is available
as a compile/link plumbing check only — it runs nothing and satisfies no gate:

```zsh
./Scripts/build_simulator.sh
```

It builds arm64 only, because the x86_64 Simulator SDK's
`task_power_info_v2` has no `task_energy` member that the Stage A resource
sampler reads. Build the signed device artifact with a reproducible source
digest:

```zsh
./Scripts/build_device.sh
```

After an on-device run completes, collect its immutable JSONL copy and
SHA-256 manifest. Raw imports are accepted only under the ignored
`.runtime/device-evidence/` tree; collection requires JSONL plus its matching
activation receipt and refuses conflicting host/provider copies:

```zsh
./Scripts/collect_device_evidence.sh
```

Independently verify each collected JSONL before using it in a physical gate:

```zsh
cd /Users/winsvpn/Downloads/wins_vpn/winn_protocol_experimental
go run ./spikes/ios_maximum_privacy/evidenceverify \
  -evidence /absolute/path/to/RUN_ID.jsonl \
  -start-receipt /absolute/path/to/RUN_ID.start-receipt.json \
  -expected-source-digest 64_LOWERCASE_HEX \
  -expected-artifact-digest PROVIDER_EXECUTABLE_SHA256 \
  -expected-mode maximum-privacy \
  -expected-profile low \
  -expected-cover continuousWhileConnected \
  -expected-rotation protocol-15m \
  -expected-condition foreground-wifi \
  -expected-pair-id LOWERCASE_PAIR_UUID \
  -expected-os-version INDEPENDENTLY_OBSERVED_IOS_VERSION \
  -expected-hardware-model INDEPENDENTLY_OBSERVED_HW_MACHINE \
  -expected-low-power-mode off \
  -expected-start-thermal nominal \
  -expected-duration-seconds 1800 \
  -require-energy \
  -require-wakeups
```

The verifier requires both the frozen source digest and the independently
recorded Packet Tunnel provider executable SHA-256. It first copies evidence
and receipts into private `O_EXCL`/fsync snapshots, then performs every read
from that sealed set. Its JSON parser rejects duplicate, case-variant,
unknown, null, and missing required members recursively before typed decode.
It rejects changed
provenance/constants, retained failure records, missing terminal/resource
evidence, incomplete whole-run sampling, incorrect condition/pair/device state,
unaccounted or inexact matched work, capacity/drop/p99 delay violations,
incomplete directional cover accounting, schedule drift, incomplete rotations,
rotation-memory growth above 1 MiB, Stop above 250 ms, and resident-memory
growth above 1 MiB/hour after warmup. It also requires the activation receipt
for every run and rejects a receipt that is malformed, unbound, reversed,
overflowing, not pinned to the first JSONL line including its line feed, or
above 3,000,000,000 ns. The collected JSONL must be named `<runID>.jsonl`,
which is how the host writes it. For a Stop run, also pass
`-expected-terminal stop-acknowledged -stop-receipt /path/to/receipt.json`.

Create the strict manifest described in `Evidence/MATRIX_MANIFEST.md`. The
cross-run gate requires a pinned `evidenceverify` executable and invokes it
against every JSONL itself. It then rechecks its private sealed evidence copy
and the sealed verifier; caller-owned paths may change after sealing without
changing the bytes under review:

```zsh
/ABSOLUTE/FRESH_DERIVED_DATA/WinnEvidenceTools/matrixverify \
  -manifest /absolute/path/to/matrix.json \
  -evidence-verifier \
    /ABSOLUTE/FRESH_DERIVED_DATA/WinnEvidenceTools/evidenceverify \
  -expected-evidence-verifier-sha256 \
    PINNED_EVIDENCEVERIFY_SHA256
```

`build_device.sh` creates that fresh `-trimpath` verifier pair, publishes it
atomically with SHA-256 pins, and emits `WINN_SPIKE_BUILD_RECEIPT.json` binding
both verifier hashes to the host/provider executable hashes. Do not use a
cached `.derived/tools` binary. `matrixverify` seals the manifest-referenced
JSONL and receipt bytes before invoking the sealed verifier copy, requires
exactly one canonical PASS line on stdout and empty stderr, and refuses
verifier drift.

The cross-run verifier requires 16 matched A/B pairs: foreground Wi-Fi idle
(one), low/medium (three each), and saturated (one); locked Wi-Fi low/medium
(one each); and unplugged cellular low/medium (three each). It also requires
Maximum Privacy Low Power Mode, 500-rotation, eight-hour locked, and measured
Stop records. It proves exact common-path equality, the 20% Wi-Fi and 25%
cellular per-profile median task-energy limits, and no more than 1.5
incremental idle wakeups/second. It requires and reports matched unplugged
whole-device battery observations as coarse corroboration without claiming a
false-precision ratio gate. Stage B remains separately required for the 20
sleep/wake and 20 real Wi-Fi/cellular path-change tests.

Wi-Fi/cellular, external-power, and locked-screen condition labels are
operator declarations in Stage A; the verifier checks selector consistency,
not the physical truth of those labels. Retain timestamp-bound device/host
observations for those states. Without that external evidence, report a matrix
PASS only as declared-condition evidence, not a physical-condition proof.

Normal matrix pairs are canonical: completed, continuous cover,
`protocol-15m`, Low Power Mode off, nominal starting thermal state, five
minutes for idle, and thirty minutes for every busy profile. Exploratory
activity-tail, accelerated, Stop, short, or Low Power Mode runs cannot satisfy
those slots.

Generate the disposable Xcode project only on an Apple development machine:

```zsh
./Scripts/generate_project.rb
```

`verify.sh` regenerates the project in scratch space and compares an
UUID-independent canonical project graph plus the normalized shared scheme
against the checked-in artifacts.

The fixture can be inspected without creating a file:

```zsh
cd /Users/winsvpn/Downloads/wins_vpn/winn_protocol_experimental
go run ./spikes/ios_maximum_privacy/fixturegen
```

Its fixed SHA-256 is:

```text
d1dd7981e67dbcf896b5fbccc44b8d440f6685e62120dd96a8d5c61467ce7f80
```

## Physical-device prerequisites

Use only these experimental identities:

```text
Host:      org.winsvpn.experimental.wcf3privacyspike
Provider:  org.winsvpn.experimental.wcf3privacyspike.PacketTunnel
App Group: group.org.winsvpn.experimental.wcf3privacyspike
```

Required before building or running the Xcode project:

1. A valid Apple Development identity in the login Keychain. This is currently
   present, but must remain valid.
2. A development App ID/profile for the host with Packet Tunnel and the
   experimental App Group.
3. A development App ID/profile for the extension with the same capabilities.
4. The attached physical iPhone registered to those profiles.
5. `preflight.sh` passing.

Do not substitute `org.winsvpn.app`, its Packet Tunnel identifier, its App
Group, or a production provisioning profile.

## Physical test architecture

The provider must route only `198.18.0.0/15`, with no default route and no DNS
override. Stage A runs synthetic cells entirely inside the extension to measure
memory, allocation, CPU, wakeups, queue behavior, cover, and rotation. Stage B
adds a disposable authenticated UDP reflector to measure actual Wi-Fi/cellular
energy, path changes, and inbound cover. The reflector must not forward user
traffic or retain client identifiers.

The physical tunnel must never be reported as working based on a build,
installation, source-only test, or simulator. Collected physical-device
evidence and the gates in `PRIVACY_SPIKE_SPEC.md` are required.
