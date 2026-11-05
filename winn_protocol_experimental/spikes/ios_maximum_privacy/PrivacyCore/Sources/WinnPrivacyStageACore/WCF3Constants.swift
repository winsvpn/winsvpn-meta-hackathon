import Foundation

public enum WCF3Constants {
    public static let magic: [UInt8] = Array("WCF3".utf8)
    public static let headerSize = 64
    public static let maximumFrameSize = 1_500
    public static let maximumPayloadSize = maximumFrameSize - headerSize
    public static let privacyCellSize = 1_024
    public static let privacyPayloadSize = privacyCellSize - headerSize
    public static let probePayloadSize = 32

    public static let kindData: UInt8 = 1
    public static let kindProbe: UInt8 = 2
    public static let kindProbeAck: UInt8 = 3
    public static let kindCover: UInt8 = 4

    public static let flagPadded: UInt8 = 1 << 0
    public static let flagFragment: UInt8 = 1 << 1
    public static let flagFinal: UInt8 = 1 << 2
    public static let allowedFlags =
        flagPadded | flagFragment | flagFinal

    public static let maximumShuffleNanoseconds: UInt64 = 20_000_000
    public static let coverIntervalNanoseconds: UInt64 = 1_000_000_000
    public static let coverTailNanoseconds: UInt64 = 30_000_000_000
    public static let circuitRotationNanoseconds: UInt64 = 900_000_000_000

    public static let defaultRingCapacity = 512
    public static let maximumConcurrentCircuits = 2
    public static let spikeRotationOverlapNanoseconds: UInt64 = 5_000_000_000

    public static let schemaVersion = "winn-ios-privacy-spike/3"
    public static let protocolVersion = "winn/3"
    public static let frameVersion = "WCF3"
}

public enum WCF3Kind: UInt8, Codable, CaseIterable, Sendable {
    case data = 1
    case probe = 2
    case probeAck = 3
    case cover = 4
}

public struct WCF3ConnectionContext: Equatable, Sendable {
    public let sessionID: [UInt8]
    public let bindingID: [UInt8]
    public let pskGeneration: UInt64
    public let sequenceEpoch: UInt64

    public init(
        sessionID: [UInt8],
        bindingID: [UInt8],
        pskGeneration: UInt64,
        sequenceEpoch: UInt64
    ) throws {
        guard sessionID.count == 16, bindingID.count == 16 else {
            throw WCF3Error.invalidConnectionContext
        }
        guard !sessionID.allSatisfy({ $0 == 0 }),
              !bindingID.allSatisfy({ $0 == 0 }),
              pskGeneration > 0,
              sequenceEpoch > 0
        else {
            throw WCF3Error.invalidConnectionContext
        }
        self.sessionID = sessionID
        self.bindingID = bindingID
        self.pskGeneration = pskGeneration
        self.sequenceEpoch = sequenceEpoch
    }
}

public struct WCF3FrameHeader: Equatable, Sendable {
    public let kind: WCF3Kind
    public let flags: UInt8
    public let context: WCF3ConnectionContext
    public let sequence: UInt64

    public init(
        kind: WCF3Kind,
        flags: UInt8 = 0,
        context: WCF3ConnectionContext,
        sequence: UInt64
    ) {
        self.kind = kind
        self.flags = flags
        self.context = context
        self.sequence = sequence
    }
}

public enum WCF3Error: Error, Equatable {
    case destinationTooSmall
    case frameSizeOutOfRange
    case payloadTooLarge
    case invalidMagic
    case invalidKind
    case invalidFlags
    case invalidFragmentFlags
    case invalidConnectionContext
    case invalidSequence
    case invalidPayloadLength
    case invalidPaddingState
    case connectionBindingMismatch
}
