# Evidence

Keep small reviewed summaries here. Raw JSONL, `.trace`, `.xcresult`,
sysdiagnose, app containers, and other runtime evidence belong under
`.runtime/device-evidence/<collection-id>/`, which is intentionally ignored.
The collector inventories the origin, basename, and SHA-256 of each file,
requires every JSONL to have its matching activation receipt, and fails closed
if host/provider copies with the same basename disagree.

Current start artifacts use attestation schema
`winn-ios-privacy-spike-start-attestation/2` and receipt schema
`winn-ios-privacy-spike-start-receipt/2`. The receipt records the provider
JSONL barrier as `f-fullfsync` or `fsync-only` and carries the exact
activation-observation and host-receipt durability scope declarations. That
barrier does not describe publication of the receipt file itself. Receipt
existence also does not prove persistence finished before a deadline, that the
host accepted the start attempt, or that the tunnel remained connected.
`evidenceverify` prints the accepted barrier in every PASS line;
`matrixverify` prints separate `f-fullfsync` and `fsync-only` run counts so a
formally passing matrix cannot hide use of the weaker barrier.

Each summary must identify:

- source-tree and installed-artifact SHA-256;
- device/OS and separately observed physical power/radio/lock state;
- mode, profile, cover semantics, and frozen constants;
- raw-evidence hashes;
- pass/fail per gate, including retained failures;
- whether the run was attached to power.

Use `MATRIX_MANIFEST.md` for the required cross-run manifest. Every raw JSONL
must first pass the single-run `evidenceverify` command. Only then run
`matrixverify`; it checks A/B identity, required coverage, median kernel-energy
and whole-device battery overhead, and incremental idle wakeups. Neither tool
turns Stage A synthetic inbound cover into Stage B network evidence.
The physical-condition labels and battery fields are operator-attested
manifest inputs; retain timestamp-bound external observations because a
matrix PASS alone does not authenticate radio, cable, or lock state.

Do not commit reflector tokens, device identifiers, packet contents, addresses,
provisioning profiles, or signing information.
