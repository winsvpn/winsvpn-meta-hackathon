# Winn iOS Stage B physical evidence contract

Status: schema/conformance design; no physical result
Protocol: `winn/3`
Attempt schema: `winn-stageb-physical-attempt/2`
Topology schema: `winn-stageb-physical-topology/1`

Attempt schema `/1` is retired and remains sealed as historical schema
conformance only. Its bytes must not be rewritten, migrated in place, or
claimed as `/2` evidence. No physical Stage B result was accepted under `/1`.
Manifest schema: `winn-stageb-physical-manifest/1`
Measurement scope: `physical-first-protected-flow`

This contract defines the evidence that a later physical-iPhone integration
must produce. Passing the local verifier means only that fixture bytes conform
to this schema. It does not prove that an iPhone, Network Extension, AWG peer,
DNS resolver, or remote reflector was used. The verifier must therefore print
`STAGE_B_PHYSICAL_SCHEMA_CONFORMANCE_PASS`, never `PHYSICAL_PASS`.

The existing `winn-stageb-local-receipt/1` receipt remains
`local-conformance-only` and is not admissible under this contract.

## 1. Exact timing boundary

`connectButtonT0MonotonicNanoseconds` is sampled as the first operation of the
on-device Connect-button handler. It is sampled before manager loading,
preparation, option creation, `startVPNTunnel`, Network Extension activation,
AWG setup, protected DNS, or reflector work. That exact unsigned value is
copied unchanged into the attempt binding and is covered by `bindingSHA256`.

Installing, signing, launching, saving a VPN configuration, receiving Apple's
one-time consent, applying tunnel settings, invoking the provider completion
handler, and observing `NEVPNStatus.connected` are setup or diagnostic events.
None is a protected-flow predicate or success endpoint.

One absolute deadline is:

```text
connectButtonT0MonotonicNanoseconds + 3_000_000_000
```

Overflow rejects the attempt. `tDataMonotonicNanoseconds` is captured by the
provider's serialized attempt owner immediately after all four authenticated
predicates have been committed. `tUIMonotonicNanoseconds` is the host's first
display of the provider-bound Online or clean terminal-failure result. On a
success, the four predicates, `tData`, terminal decision, and UI result must
all be at or before the one deadline. Exactly 3,000,000,000 nanoseconds passes;
3,000,000,001 cannot succeed. No activation,
preparation, retry, fallback, path change, or clock source may reset the
deadline.

Receipt persistence is outside the latency interval. A persistence failure
still makes evidence inadmissible.

## 2. One attempt and four predicates

Every event binds one run, attempt nonce, path, WCF3 session and binding, PSK
generation, sequence epoch, canary sequence, unchanged T0, AWG configuration,
precommitted expected peer, AWG engine instance and generation, winning path
generation, and an opaque winning-interface token. The verifier recomputes:

```text
SHA-256(
  "winn-stageb-physical-binding/v1\0" ||
  runID || "\0" ||
  attemptNonce || "\0" ||
  pathID || "\0" ||
  wcf3SessionID || "\0" ||
  wcf3BindingID || "\0" ||
  decimal(pskGeneration) || "\0" ||
  decimal(sequenceEpoch) || "\0" ||
  decimal(canarySequence) || "\0" ||
  decimal(requestedAtMonotonicNanoseconds) || "\0" ||
  awgConfigSHA256 || "\0" ||
  expectedAWGPeerSHA256 || "\0" ||
  awgEngineInstanceNonce || "\0" ||
  decimal(awgEngineGeneration) || "\0" ||
  decimal(winningPathGeneration) || "\0" ||
  winningInterfaceTokenSHA256
)
```

All identifier strings are independently CSPRNG-generated canonical lowercase
UUIDv4 values with an RFC 4122 variant, and are pairwise distinct within one
binding. All decimal inputs use their ordinary unsigned base-10 representation.
The interface token is a per-attempt opaque digest, never an interface name,
address, or endpoint.

A successful attempt has exactly these four observed predicates:

1. `freshAWGHandshake`;
2. `authenticatedBidirectionalBytes`;
3. `protectedDNS`;
4. `authenticatedReflector`.

Each predicate carries its trusted monotonic observation time and the exact
binding digest. Every time is within `[T0, deadline]`. `tData` is not earlier
than any predicate.

## 3. AWG proof

Before connection work, the manifest precommits the AWG artifact and
configuration digests, expected peer-key digest, engine-instance nonce and
generation, winning path generation, and opaque winning-interface token. The
adapter samples the expected peer after T0 and then records separate handshake
and counter post-sample monotonic times so neither predicate can borrow the
later time of a different poll. Baseline, handshake-post, and counter-post each
repeat the exact precommitted peer/configuration/engine/path identity. Any
change rejects the attempt. For a fresh handshake, the post latest-handshake
Unix-millisecond value is strictly greater than the baseline value, and the
fresh-handshake predicate time must equal the handshake post-sample time.

Authenticated transmit and receive counters are sampled from that peer.
Neither may decrease. The stored deltas must equal exact checked subtraction,
and both must be greater than zero before the bidirectional predicate is
recorded. The bidirectional predicate time must equal the counter post-sample
time. Generic Packet Tunnel, packet-flow, DNS-library, or socket byte counters
do not satisfy this proof.

## 4. Protected DNS proof

The attempt precommits a per-attempt query-nonce digest and expected response
payload digest. A successful DNS proof is attempted, cache-bypassed, bound to
the winning tunnel, and uses the pinned private resolver configuration and
topology proof. Its request/response order is monotonic and its response time
is the protected-DNS predicate time.

A cached answer, public/system resolver, wrong response, stale nonce, or
non-tunnel path is not admissible. An unattempted proof has both times and both
path booleans cleared. An attempted but unobserved proof has one in-deadline
request time after authenticated tunnel bytes, no response time, and the
cache-bypassed/tunnel-only booleans set. No other state is canonical.

## 5. Reflector proof

The physical reflector is a separate deployment from the loopback-only Go
reference server. The loopback server's allowlist must not be weakened.

The attempt emits the exact domain-owned request datagram through the winning
tunnel and accepts its authenticated response through the same bound path. The
evidence records only the canary sequence, times, artifact/config/topology
digests, and binding digest. It must not record a key, request tag, challenge,
packet body, endpoint, or client address.

An unattempted reflector has zero request/response times and cleared
authentication/tunnel booleans. An attempted but unobserved reflector has one
in-deadline request after protected DNS, zero response time, `tunnelOnly=true`,
and `authenticated=false`. No other attempted/unobserved state is canonical.

## 6. Topology proof

The topology record is a root-relative, digest-pinned companion file. It must
state that:

- private DNS and the reflector were blocked before the tunnel;
- both were blocked again after teardown;
- the reflector accepted ingress only from the AWG-inner policy;
- no plaintext DNS or reflector packet was observed on the outer path; and
- firewall, route, outer-capture, and independent-observer receipts were
  retained by SHA-256.

These fields are operator/collector attestations until a later physical run
binds them to independently retained observations. Schema conformance alone
does not authenticate the physical facts.

## 7. Terminal and cleanup evidence

Terminal states are `succeeded`, `failed`, `cancelled`, or `superseded`.
Success requires failure code `none`, all predicates, nonzero `tData`, and
cleanup state `not-required`.

A non-success normally has no `tData`, has a state-appropriate non-`none`
failure code, and requires cleanup state `complete`. Except for
`deadline-exceeded`, its terminal decision and UI result must still be at or
before the original three-second deadline, and its
`deadlineFailureReportingBudgetNanoseconds` is zero.

`deadline-exceeded` is decided only after the inclusive success deadline. A
checked-add overflow rejects the attempt. Its observed terminal decision must
be strictly later than the deadline and at or before:

```text
deadline + 50_000_000
```

For that failure only,
`deadlineFailureReportingBudgetNanoseconds` must equal the separately frozen
50,000,000-nanosecond reporting budget. Its UI result is at or after the
observed terminal decision and at or before the same reporting deadline. This
records real scheduler delay instead of substituting the timer's requested
wake instant. Thus both terminal and UI evidence are strictly after the
success deadline without extending the success interval.
All protected-flow events retained by a deadline failure remain at or before
the immutable terminal decision, and all observed predicates remain within the
original inclusive success deadline.

Cleanup is independent of the failure-reporting window. It completes no
earlier than the terminal decision and within its declared budget, whose frozen
maximum is 250,000,000 nanoseconds. It need not precede the UI result. Later
callbacks cannot revive the attempt.

Raw failures remain retained even when the verifier rejects them from an
acceptance set.

The exception is `evidence-persistence-failed`: all four predicates and a
bounded nonzero `tData` must already exist, because persistence follows the
protected-flow endpoint. Failure codes otherwise match the exact completed
predicate prefix: AWG handshake, bidirectional bytes, protected DNS, then
reflector. Cancelled, superseded, and deadline failures may retain only a
consistent prefix. Every predicate, AWG sample, DNS request/response, and
reflector request/response is at or before the immutable terminal decision;
late callbacks are inadmissible.

## 8. Provenance and relocation

The manifest and referenced attempt/topology files form one relocatable
directory with exactly these names: `manifest.json`,
`evidence/attempt.json`, and `proof/topology.json`. No caller-selected
component, hostname-shaped name, IP-shaped name, endpoint, alternative
filename, absolute path, or traversal is accepted.

On Darwin and Linux, the verifier opens the root and every component through
directory descriptors with no-follow semantics. It rejects a symlink root or
component, records device/inode identity before and after opening, compares the
opened descriptor and path identity again after the bounded read, and requires
the size to remain unchanged and equal the bytes read. Other platforms apply
the same identity/size checks through the strongest available rooted APIs.
Non-regular files and files above the verifier's limits are rejected.

The manifest pins:

- this contract;
- source tree;
- host executable;
- Packet Tunnel provider executable;
- AWG engine/library;
- AWG configuration and precommitted peer;
- AWG engine instance/generation and winning path/interface token;
- reflector executable and configuration;
- protected-DNS configuration;
- physical verifier executable;
- attempt bytes; and
- topology bytes.

The attempt repeats every build/configuration and AWG engine/path pin, and the
topology record repeats the AWG/reflector/DNS and engine/path pins. All copies
must agree.

The CLI requires four independently supplied digests: manifest bytes, this
contract, source tree, and the verifier executable. It validates all four as
canonical nonzero SHA-256 values. It hashes and compares the raw manifest bytes
before parsing or trusting any manifest member, then requires the manifest's
contract/source/verifier members to match the external pins.

Every JSON file is one canonical compact JSON object followed by exactly one
line feed. Member spelling, presence, and order are exact. Duplicate,
case-variant, unknown, null, missing, noncanonical, trailing, overflowing, or
inconsistent input is rejected before it can be reported as conforming.

## 9. Privacy boundary

The manifest and every referenced file forbid:

- shared keys, PSK values, request/response tags, and challenges;
- packet bodies and query plaintext;
- IP addresses, ports, endpoints, and client addresses;
- Apple account, device, advertising, vendor, or other persistent IDs; and
- provisioning/signing secrets.

Only random run/attempt/path/session UUIDs, public artifact/configuration
digests, counter values, timestamps, enums, and evidence digests are admitted.

## 10. Local deterministic gate

The local gate must cover:

- a canonical success fixture at the exact Tdata/Tui boundary;
- Tdata and Tui at boundary plus one;
- unchanged-T0 and binding-digest mutations;
- stale AWG handshake, counter rollback, and delta mismatch;
- AWG configuration, peer, engine-instance/generation, winning-path generation,
  interface-token, and baseline/post identity drift;
- DNS cache/public-path/topology mutations;
- reflector direct-path/topology mutations;
- attempted/unobserved DNS and reflector chronology/boolean mutations;
- success/failure-code/late-callback/cleanup state mutations;
- deadline failure at the deadline, at deadline plus two, UI at the deadline,
  UI beyond the 50-millisecond reporting window, reporting-budget drift, and
  cleanup/reporting-window conflation;
- ordinary failures attempting to borrow the deadline-failure reporting window;
- external manifest/contract/source/verifier and internal artifact,
  configuration, evidence, and topology pin drift;
- alternate/hostname/IP/escaping/symlink paths, symlink roots, and
  deterministic opened-file replacement;
- local-receipt substitution;
- duplicate, case-variant, missing, unknown, null, trailing, and overflow JSON;
- non-v4, wrong-variant, or duplicate binding UUIDs;
- forbidden secret/tag/challenge/address/Apple-ID members; and
- relocation of an unchanged root.

Passing that gate is only physical-evidence **schema conformance**.
