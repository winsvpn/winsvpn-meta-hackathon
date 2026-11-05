# Stage A physical matrix manifest

`matrixverify` pins and executes the strict single-run `evidenceverify`
executable against every collected JSONL before applying cross-run gates.
Running the same single-run commands manually first is useful diagnosis, but
is not the trust boundary.

The manifest and all referenced JSONL files must share one directory tree.
Evidence paths are relative, cannot escape the manifest directory, and bind to
their independently computed lowercase SHA-256. The top level is:

```json
{
  "schema": "winn-ios-privacy-matrix/1",
  "protocolVersion": "winn/3",
  "sourceDigest": "64_lowercase_hex",
  "artifactDigest": "provider_executable_sha256",
  "osVersion": "independently observed iOS version",
  "hardwareModel": "independently observed hw.machine",
  "runs": []
}
```

Each `runs` entry has this exact shape:

```json
{
  "evidence": "relative/path/to/RUN_ID.jsonl",
  "evidenceSHA256": "64_lowercase_hex",
  "startReceipt": "relative/path/to/RUN_ID.start-receipt.json",
  "startReceiptSHA256": "64_lowercase_hex",
  "mode": "core-baseline",
  "trafficProfile": "low",
  "coverSemantics": "continuousWhileConnected",
  "rotationCadence": "protocol-15m",
  "testCondition": "foreground-wifi",
  "pairID": "lowercase-uuid-shared-only-by-the-matched-a-b-pair",
  "repeat": 1,
  "durationSeconds": 1800,
  "expectedTerminal": "completed",
  "lowPowerMode": "off",
  "startThermal": "nominal",
  "unplugged": true,
  "batteryStartBasisPoints": 10000,
  "batteryEndBasisPoints": 9900
}
```

`startReceipt` and `startReceiptSHA256` are mandatory on **every** run, not
only the Stop run. The evidence file must be named `<runID>.jsonl` and its
receipt `<runID>.start-receipt.json`, which is how the host writes them.
`matrixverify` pins the receipt by digest, passes it to the single-run
verifier, and independently rechecks it: schema
(`winn-ios-privacy-spike-start-receipt/2`) and measurement scope, run ID and
source digest, **evidence durability barrier** (`f-fullfsync` or `fsync-only`
exactly), artifact scope
(`activation-observation-not-attempt-success-or-persistence-timing`),
host-receipt durability scope
(`host-receipt-barrier-not-encoded-no-power-loss-claim`), first-record attempt
nonce and request/provider timestamps, the SHA-256 of the first JSONL line
**including its trailing line feed**, that line's byte count, clock ordering,
and the 3,000,000,000 ns host activation bound.

A `/2` receipt must never be interpreted as proof that host receipt persistence
met the <=3 s activation deadline, as overall attempt success, or as a
power-loss guarantee. Activation <=3 s and asynchronous evidence persistence
are deliberately separate claims. The `artifactScope` and
`hostReceiptDurabilityScope` fields carry those limitations inside every
encoded artifact so they travel with the evidence rather than living only in
documentation.

The barrier field describes the provider JSONL file/directory barrier. The
runtime host validates it against attestation schema
`winn-ios-privacy-spike-start-attestation/2` before publishing the receipt.
The offline matrix does not contain that raw attestation, so its verifiers
validate the receipt value and first-record binding but do not claim to
reconstruct the provider's system call independently.

That bound covers **iOS Packet Tunnel activation observed by the host** and
nothing more. Stage A performs no remote handshake and forwards no packet, so
a passing matrix says nothing about a usable VPN connection or about
time-to-first-protected-packet; the later real-network gate must measure the
first protected flow separately.

A Stop entry additionally includes:

```json
{
  "stopReceipt": "relative/path/to/run.stop-receipt.json",
  "stopReceiptSHA256": "64_lowercase_hex"
}
```

Battery basis points range from 0 to 10,000, so a directly observed 100% is
10,000 and 99% is 9,900. Record only observed values; do not invent extra
precision. Battery fields are mandatory for the three low and three medium
energy pairs on both foreground Wi-Fi and cellular. Those runs must be
unplugged. The verifier compares each Maximum Privacy run only with the Core
run that has the same pair UUID, selectors, repeat, duration, and starting
thermal/Low Power Mode state.

`testCondition`, `unplugged`, and battery basis points are operator-attested
manifest inputs. The provider machine-observes thermal and Low Power Mode, but
Stage A does not machine-observe the active radio, cable state, or lock
interval. Therefore a matrix PASS proves selector consistency and numerical
gates, not those physical facts. Retain timestamp-bound device/host
observations for radio, external power, and screen lock alongside the matrix;
without them, report the result as declared-condition evidence only.

Because iOS exposes whole-device battery level at coarse resolution, the
verifier reports its per-profile median as corroborating evidence but does not
pretend it can enforce a precise 20%/25% ratio from those values. The numeric
20% Wi-Fi and 25% cellular gates apply to the provider's matched task-energy
counter. Battery observations must still be present, positive, unplugged, and
paired; retain the raw start/end values for human review.

Required matched pairs:

| Condition | Profile | Repetitions |
|---|---|---:|
| foreground-wifi | idle | 1 |
| foreground-wifi | low | 3 |
| foreground-wifi | medium | 3 |
| foreground-wifi | saturated | 1 |
| locked-wifi | low | 1 |
| locked-wifi | medium | 1 |
| unplugged-cellular | low | 3 |
| unplugged-cellular | medium | 3 |

Each required pair must be a canonical completed run with continuous cover,
real `protocol-15m` rotation cadence, Low Power Mode off, nominal starting
thermal state, and a duration of 300 seconds for idle or 1,800 seconds for
busy profiles. Short, activity-tail, accelerated, Stop-terminal, or Low Power
Mode pairs do not count toward these slots.

Also include one Maximum Privacy record for each of
`low-power-mode`, `accelerated-allocation`, `eight-hour-locked`, and
`stop-latency`. The stop entry uses `expectedTerminal: stop-acknowledged`; its
JSONL and receipt must already have passed `evidenceverify`. The accelerated
entry must use `accelerated-allocation` cadence and contain at least 500
rotations. The eight-hour entry uses 28,800 seconds.

Run the cross-run gate from the experimental Go module:

```zsh
/ABSOLUTE/FRESH_DERIVED_DATA/WinnEvidenceTools/matrixverify \
  -manifest /absolute/path/to/matrix.json \
  -evidence-verifier \
    /ABSOLUTE/FRESH_DERIVED_DATA/WinnEvidenceTools/evidenceverify \
  -expected-evidence-verifier-sha256 \
    PINNED_EVIDENCEVERIFY_SHA256
```

Use only the fresh `-trimpath` verifier pair and hashes emitted by
`build_device.sh` in `WINN_SPIKE_BUILD_RECEIPT.json`; stale
`.derived/tools` programs are not admissible. The matrix command snapshots
the exact manifest-referenced JSONL/start/stop bytes with `O_EXCL` and fsync,
executes a sealed copy of the pinned verifier, accepts exactly one canonical
PASS line with empty stderr, and rechecks the verifier digest.

The manifest proves Stage A cross-run gates and declared-condition coverage
only. It cannot prove physical radio/power/lock state, remote inbound cover,
radio forwarding, sleep/wake survival, or Wi-Fi/cellular path changes; those
require the external observations above or remain Stage B.
