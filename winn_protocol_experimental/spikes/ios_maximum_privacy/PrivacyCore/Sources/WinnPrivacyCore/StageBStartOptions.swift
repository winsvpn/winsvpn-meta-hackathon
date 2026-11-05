import Foundation
import WinnPrivacyStageACore

/// Separate Stage B start-option namespace.
///
/// Stage A owns exactly two `WinnSpike...` keys and its parser intentionally
/// refuses a third. These keys therefore use `WinnStageB...` and cannot weaken
/// or silently mutate the accepted Stage A activation receipt.
public enum StageBStartOptions {
  public static let optionNamespace = "WinnStageB"
  public static let attemptNonceKey = "WinnStageBAttemptNonce"
  public static let connectButtonT0Key =
    "WinnStageBConnectButtonT0MonotonicNanoseconds"
  public static let attemptSchemaKey = "WinnStageBAttemptSchema"
  public static let attemptSchema = "winn-stageb-physical-attempt/2"

  public static func encode(
    attemptNonce: String,
    connectButtonT0MonotonicNanoseconds: UInt64
  ) throws -> [String: String] {
    guard isLowercaseVersion4UUID(attemptNonce) else {
      throw StartLatencyError.invalidField("stageBAttemptNonce")
    }
    guard connectButtonT0MonotonicNanoseconds > 0 else {
      throw StartLatencyError.invalidField("stageBConnectButtonT0")
    }
    return [
      attemptNonceKey: attemptNonce,
      connectButtonT0Key:
        CanonicalDecimal.encode(
          connectButtonT0MonotonicNanoseconds
        ),
      attemptSchemaKey: attemptSchema,
    ]
  }

  /// Parses only entries collected from the exact `WinnStageB` namespace.
  public static func parse(
    namespacedOptions: [String: String]
  ) throws -> (
    attemptNonce: String,
    connectButtonT0MonotonicNanoseconds: UInt64
  ) {
    guard namespacedOptions.count == 3 else {
      throw StartLatencyError.malformedStartOptions(
        "stageB key set"
      )
    }
    guard
      let nonce = namespacedOptions[attemptNonceKey],
      isLowercaseVersion4UUID(nonce)
    else {
      throw StartLatencyError.malformedStartOptions(
        "stageB nonce"
      )
    }
    guard
      let t0Text = namespacedOptions[connectButtonT0Key],
      let t0 = CanonicalDecimal.decode(t0Text),
      t0 > 0
    else {
      throw StartLatencyError.malformedStartOptions(
        "stageB T0"
      )
    }
    guard namespacedOptions[attemptSchemaKey] == attemptSchema else {
      throw StartLatencyError.malformedStartOptions(
        "stageB schema"
      )
    }
    return (nonce, t0)
  }

  private static func isLowercaseVersion4UUID(
    _ value: String
  ) -> Bool {
    guard StartLatencyValidation.isLowercaseUUID(value) else {
      return false
    }
    let bytes = Array(value.utf8)
    return bytes[14] == 0x34
      && [UInt8(0x38), 0x39, 0x61, 0x62].contains(bytes[19])
  }
}

/// Fully bound provider-side view of the Stage A and Stage B start options.
///
/// Keeping namespace collection, nonce binding, and chronology in this pure
/// parser makes the security-relevant acceptance rule directly testable
/// without loading NetworkExtension.
public struct StageBProviderStartOptions: Equatable, Sendable {
  public let attemptNonce: String
  public let requestedAtMonotonicNanoseconds: UInt64
  public let connectButtonT0MonotonicNanoseconds: UInt64

  public static func parse(
    entries: [(key: String, value: Any)],
    providerReceivedAtMonotonicNanoseconds: UInt64
  ) throws -> Self {
    var stageA: [String: String] = [:]
    var stageB: [String: String] = [:]
    var ownedKeys = Set<String>()
    for entry in entries {
      let isStageA =
        entry.key.hasPrefix(StartLatencyConstants.optionNamespace)
      let isStageB =
        entry.key.hasPrefix(StageBStartOptions.optionNamespace)
      guard isStageA || isStageB else { continue }
      guard ownedKeys.insert(entry.key).inserted else {
        throw StartLatencyError.malformedStartOptions(entry.key)
      }
      guard let text = entry.value as? String else {
        throw StartLatencyError.malformedStartOptions(entry.key)
      }
      if isStageA {
        stageA[entry.key] = text
      } else {
        stageB[entry.key] = text
      }
    }

    let parsedStageA = try StartLatencyStartOptions.parse(
      namespacedOptions: stageA
    )
    let parsedStageB = try StageBStartOptions.parse(
      namespacedOptions: stageB
    )
    guard parsedStageA.attemptNonce == parsedStageB.attemptNonce else {
      throw StartLatencyError.bindingMismatch("stageB attemptNonce")
    }
    guard
      parsedStageB.connectButtonT0MonotonicNanoseconds
        <= parsedStageA.requestedAtMonotonicNanoseconds,
      parsedStageA.requestedAtMonotonicNanoseconds
        <= providerReceivedAtMonotonicNanoseconds
    else {
      throw StartLatencyError.bindingMismatch(
        "stageB start chronology"
      )
    }

    return Self(
      attemptNonce: parsedStageA.attemptNonce,
      requestedAtMonotonicNanoseconds:
        parsedStageA.requestedAtMonotonicNanoseconds,
      connectButtonT0MonotonicNanoseconds:
        parsedStageB.connectButtonT0MonotonicNanoseconds
    )
  }
}
