# NON-AUTHORITATIVE — OpenCode / DeepSeek V4 Pro — Stage B Codec Test-Gap Audit

**Date:** 2026-07-27
**Auditor:** OpenCode (DeepSeek V4 Pro), bounded, non-authoritative
**Environment:** macOS arm64e, Xcode 26.0, Swift 5.9 / SPM
**Scope:** `spikes/ios_maximum_privacy/PrivacyCore/` — codec source + tests only
**Production edits:** None. No production code or existing tests were modified.

---

## Source & Test File Identities (SHA-256)

| File | SHA-256 |
|------|---------|
| `PrivacyCore/Sources/WinnStageBProviderCore/StageBMessageCodec.swift` | `ed7bc9863606a41af417956f76b04e2a4f6c253ccd6a915e5fb828a724f4ef57` |
| `PrivacyCore/Tests/WinnStageBProviderCoreTests/StageBMessageCodecTests.swift` | `53a1bb21a5e41112e401a64955fbcd263bd7150b183e0410a43086fc99e566e1` |

---

## Test Execution Summary

```
Command: swift test --package-path PrivacyCore --filter StageBMessageCodecTests
Result:  62 tests executed, 0 failures, 0 unexpected
Duration: ~4 seconds (build + test)
Exit:    0
```

The full filter `StageBMessageCodecTests` was used, which isolated the codec test suite from other targets (`WinnPrivacyCoreTests`, `StageBProviderCoordinatorTests`, `StageBProviderLifecycleTests`, `StageBAWGUAPIParserTests`). No build scripts, Apple devices, cloud services, or shared verify lanes were involved.

---

## Prioritized Findings

### 1. [HIGH] No concurrent encode/decode tests — `NSLock` unverified under contention

**Source:** `StageBMessageCodec.swift:535-536`
```swift
final class StageBMessageTranscriptEngine: @unchecked Sendable {
  private let lock = NSLock()
```

The engine is annotated `@unchecked Sendable`, relying solely on `NSLock` to serialize `encode(_:body:)` and `decode(_:)`. There are **zero** tests that dispatch concurrent encode/decode operations on the same transcript from multiple threads. A lock-coverage gap means no empirical evidence that:

- The lock prevents two threads from simultaneously incrementing `nextSequence` (producing duplicate sequence numbers).
- The lock prevents a decode from reading `phase` while an encode is mid-`advanceLocked`, which could yield a transient inconsistent state.
- `poison()` (line 558-562) is safe when called during a concurrent decode on `Data` variants (lines 1110-1116, 1180-1186).

**Missing test:** A dispatch-group test that fires N concurrent encodes and M concurrent decodes at the same transcript and asserts that exactly one succeeds per expected phase, all others get `terminated` or ordering errors, and no sequences are duplicated or skipped.

---

### 2. [MEDIUM] Binding deadline boundary at `UInt64.max` not tested at exact edge

**Source:** `StageBMessageCodec.swift:262-270`
```swift
let (deadline, overflow) =
  requestedAtMonotonicNanoseconds.addingReportingOverflow(
    StageBProtectedFlow.deadlineNanoseconds
  )
guard !overflow,
  deadline <= UInt64.max - StageBMessageCodec.terminalSlackNanoseconds
```

The test `testAttemptBindingRejectsZeroDigestsAndOverflowingT0` (line 1431) uses `UInt64.max - 1_000`, which overflows in the addition and is correctly rejected. However, the exact boundary where `deadline == UInt64.max - terminalSlackNanoseconds` is valid, while `deadline == UInt64.max - terminalSlackNanoseconds + 1` should be rejected, is **not tested**.

Specifically:
- `requestedAt = UInt64.max - deadlineNanoseconds - terminalSlackNanoseconds` → deadline = `UInt64.max - terminalSlackNanoseconds` → **should be accepted** (not tested).
- `requestedAt = UInt64.max - deadlineNanoseconds - terminalSlackNanoseconds + 1` → deadline = `UInt64.max - terminalSlackNanoseconds + 1` → **should be rejected** (not tested).

**Missing test:** Construct two `StageBMessageAttemptBinding` instances at these two exact boundary values and assert accept/reject respectively.

---

### 3. [MEDIUM] `constantTimeEquals` length guard is not constant-time — information leak via early return

**Source:** `StageBMessageCodec.swift:480-487`
```swift
static func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
  guard lhs.count == rhs.count else { return false }  // <-- NOT constant-time
  var difference: UInt8 = 0
  for index in 0 ..< lhs.count {
    difference |= lhs[index] ^ rhs[index]
  }
  return difference == 0
}
```

The `guard` on line 481 returns `false` immediately if lengths differ, creating a timing differential between same-length and different-length inputs. An attacker that can measure response timing of chain/binding/digest verification could distinguish a length mismatch from a content mismatch.

This is a **defense-in-depth** concern: the length of these fields is fixed at 16 (UUID), 32 (digest), and 64 bits (UInt64). If calling code always passes fixed-length slices, the guard is harmless. But if any code path passes a variable-length slice (e.g., a parse-damaged `encoded[...]` range), the length check leaks one bit.

**Missing test:** Assert that `constantTimeEquals` returns the same result regardless of input length mismatches — and that the function is used only with fixed-width slices (static analysis via a test that extracts all call sites).

---

### 4. [LOW] `isNonzeroDigest` / `isCanonicalUUIDv4` boundary inputs untested

**Source:** `StageBMessageCodec.swift:448-457`
```swift
static func isCanonicalUUIDv4(_ bytes: [UInt8]) -> Bool {
  bytes.count == 16 && bytes[6] & 0xF0 == 0x40 && bytes[8] & 0xC0 == 0x80
    && !bytes.allSatisfy { $0 == 0 }
}

static func isNonzeroDigest(_ bytes: [UInt8]) -> Bool {
  bytes.count == digestBytes && !bytes.allSatisfy { $0 == 0 }
}
```

Edge cases not tested at the pure-function level:
- `isNonzeroDigest([])` → `false` (count != 32, short-circuits before `allSatisfy`; safe only because `[]` has count 0 and `allSatisfy` on empty → `true`, but `false && true = false` — actually `bytes.count == digestBytes` is `0 == 32 = false`, so the `&&` short-circuits at `false`. No issue here.)
- `isNonzeroDigest([UInt8](repeating: 0xFF, count: 32))` → `true` (all-FF digest is accepted). This is correct behavior and is used nowhere outside test validation — but the codec **does** accept all-FF digests on the wire. Not a vulnerability; a gap in "surprise input" coverage.
- `isCanonicalUUIDv4([UInt8](repeating: 0, count: 15))` → `false` (count mismatch).
- `isCanonicalUUIDv4` where `bytes[6] == 0x40` but `bytes[8] & 0xC0 != 0x80` — only one half of the v4 constraint checked in isolation. The existing binding tests exercise both validators indirectly but never as isolated pure-function assertions.

**Missing test:** Standalone `XCTAssertTrue`/`XCTAssertFalse` assertions for each pure function with edge inputs (empty, all-FF, all-zero, wrong-length-1, wrong-length+1).

---

### 5. [LOW] `StageBMessageTranscriptEngine` state after `poison()` — encode not tested

**Source:** `StageBMessageCodec.swift:558-562`, lines 1110-1116, 1180-1186

`poison()` is only called from the `Data` overloads of `decode` in `StageBHostMessageTranscript` and `StageBProviderMessageTranscript` (lines 1112, 1183). After poison, the next `encode(_:body:)` call should throw `.terminated`. The current tests only verify that `decode` throws `.terminated` after poison (via `testDataDecodeBoundsInputBeforeCopying`). There is no test that:

1. Calls `decode(Data)` with an oversized `Data` to trigger `poison()`.
2. Then calls `encode` (e.g., `encodePrepareDNSRequest()`) and asserts `.terminated`.

**Missing test:** A 3-step test: `decode(oversizedData)` → `messageTooLarge`, then `encode...()` → `terminated`.

---

### 6. [LOW] Payload-length field set to `UInt16.max` (65535) not tested

**Source:** `StageBMessageCodec.swift:698-703`

When the 2-byte payload-length field is `0xFFFF`, `readUInt16` returns `65535`, and `Int(65535)` is `65535`. This value exceeds `maximumPayload(for: kind)` for every kind (max is 1024), so it is rejected as `payloadTooLarge`. However, no test explicitly sets the payload-length field to `0xFFFF` and asserts the correct rejection. The existing `testEmptyKindRejectsAnyDeclaredPayload` tests length=1 but not `0xFFFF`.

**Missing test:** A mutation test that sets the payload-length field to `0xFFFF` and asserts `.payloadTooLarge` (not a crash, integer overflow, or incorrect error reason).

---

### 7. [LOW] Provider `decode` after `poison()` by oversized `Data` — encode path untested

**Source:** `StageBMessageCodec.swift:1180-1186`

The `StageBProviderMessageTranscript.decode(Data)` path calls `engine.poison()` then throws. The test `testDataDecodeBoundsInputBeforeCopying` only exercises the host-side `pair.provider.decode(huge)` path. The symmetric provider-side `pair.host.decode(hugeData)` path is not tested.

---

### 8. [LOW] Noncanonical endpoint encoding: IPv4-mapped-IPv6 addresses not explicitly rejected

**Source:** `StageBMessageCodec.swift:112-146`

`StageBPrivateEndpoint` rejects `::/128`, `::1/128`, and `ff00::/8` for IPv6. However, IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) and other transition addresses (e.g., `64:ff9b::/96`) are **not** explicitly rejected and would be accepted as valid unicast IPv6 addresses. If the adapter routes these through the host's native stack instead of the AWG tunnel, they could bypass tunneling. The codec comment on line 103-104 explicitly notes this is an adapter responsibility, not a codec one — which is correct from a separation-of-concerns standpoint. No codec-level test gap.

---

## Rejected False Positives

The following concerns were investigated and determined to be **already adequately covered** by existing tests:

| Concern | Existing test | Line |
|---------|--------------|------|
| Integer overflow in `readUInt64` shift loop | `testSequenceOutsideTheFixedTranscriptRangeIsRejected` (exercises max UInt64) | 663 |
| Integer overflow in `addingReportingOverflow` deadline | `testAttemptBindingRejectsZeroDigestsAndOverflowingT0` | 1431 |
| Body-kind mismatch (e.g., dns-response body with prepareDNS kind) | `testMismatchedBodyForAKindFailsClosedInTheEngine` | 1482 |
| Sequence rollover/rewind | `testStaleSequenceIsRejectedForItsOwnReason` | 641 |
| Sequence gap skipping | `testForwardSequenceGapIsRejected` | 653 |
| Chain poisoning via foreign challenge | `testChainOfADifferentAttemptChallengeIsRejected` | 626 |
| Self-role confusion (host decoding host message) | `testASideNeverDecodesItsOwnRolesMessage` | 1293 |
| Terminal at wrong time (success past deadline) | `testTerminalTimeBoundariesAreExact` | 1110 |
| Terminal failure window bounding | `testFailureReportMayUseTheBoundedReportingWindowOnly` | 1143 |
| Endpoint port=0, unspecified, loopback, multicast | `testStructurallyImpossibleEndpointAddressesAreRejected`, `testIPv6EndpointRoundTripsAndRejectsMulticastAndLoopback`, `testEndpointPortZeroIsRejected` | 878, 905, 870 |
| All-zero digest in send-ack | `testAllZeroSendAcknowledgementDigestIsRejected` | 955 |
| Empty datagram bodies | `testEmptyDatagramBodiesAreRejected` | 829 |
| Maximum-length bodies accepted | `testMaximumSizedBodiesAtTheExactBoundAreAccepted` | 820 |
| Trailing bytes rejected | `testTrailingBytesAreRejectedRatherThanIgnored` | 688 |
| Truncated message rejected | `testTruncatedInputIsRejectedBeforeAnyFieldIsRead` | 675 |
| Oversized message rejected (prefix not accepted) | `testOversizedInputIsRejectedInsteadOfAcceptingItsValidPrefix` | 723 |
| Per-kind maximum below global | `testPerKindMaximumIsEnforcedBelowTheGlobalMaximum` | 757 |
| Encoder rejects oversized bodies | `testEncoderRefusesOversizedBodies` | 780 |
| Duplicate message refused | `testDuplicateOfTheJustAcceptedMessageIsRefused` | 1309 |
| Failed encode poisons transcript | `testARejectedEncodeAlsoPoisonsTheTranscript` | 1358 |
| Post-terminal encode rejected | `testEncodingAfterTheTerminalResponseIsRefused` | 1343 |
| Early terminal at any provider turn | `testTerminalResponseMayArriveAtAnyProviderTurnAndClosesTheChannel` | 1322 |
| Every phase ordering (12 × 12 kind matrix) | `testEveryPhaseAdmitsExactlyTheKindsItsDirectionAllows` | 1195 |
| Predicate bytes strictly 0 or 1 | `testTerminalPredicateBytesAreStrictlyZeroOrOne` | 1024 |
| Non-Boolean predicate in failure report | `testNonBooleanPredicateByteIsRejectedEvenInAFailureReport` | 1045 |
| Cross-attempt message identity mismatch | `testCrossAttemptMessageIsRejectedAsAnIdentityMismatch` | 1369 |
| Noncanonical/duplicate UUIDs in binding | `testAttemptBindingRejectsNonCanonicalOrDuplicateIdentifiers` | 1392 |
| Zero digests in binding | `testAttemptBindingRejectsZeroDigestsAndOverflowingT0` | 1431 |
| Constant-time equals correctness | `testConstantTimeEqualityAgreesWithOrdinaryEquality` | 1496 |
| Schema/framing constant pinning | `testSchemaAndFramingConstantsArePinned` | 1512 |
| Golden transcript SHA-256 pinning | `testConcatenatedTranscriptMatchesThePinnedDigest` | 332 |
| Independent chain recomputation | `testChainFieldIsTheIndependentlyRecomputedPredecessorDigest` | 387 |
| Binding digest helper pinning | `testBindingDigestHelperMatchesThePinnedVector` | 402 |
| All header field mutations (magic, version, kind, reserved, protocol, nonce, path, binding, deadline, chain) | Individual mutation tests | 526-637 |

---

## Summary

| Category | Count |
|----------|-------|
| Tests executed | 62 |
| Tests passed | 62 |
| HIGH findings | 1 (no concurrency test) |
| MEDIUM findings | 2 (deadline boundary, constantTimeEquals guard) |
| LOW findings | 5 (pure-function edges, poison+encode, UInt16.max, symmetric poison, IPv4-mapped-IPv6 noted) |
| False positives rejected | 30+ |

The existing test suite is thorough for single-threaded correctness across the full framing, ordering, mutation, endpoint, and terminal-report surface. The primary gap is the absence of concurrent-access tests for the `NSLock`-guarded transcript engine.

---

*End of report. This document is NON-AUTHORITATIVE; all claims should be independently verified by Codex or equivalent.*
