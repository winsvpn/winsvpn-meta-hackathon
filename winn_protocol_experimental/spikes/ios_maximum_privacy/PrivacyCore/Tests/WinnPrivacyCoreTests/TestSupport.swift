import Foundation
@testable import WinnPrivacyCore

func testContext(seed: UInt8 = 1) throws -> WCF3ConnectionContext {
    try WCF3ConnectionContext(
        sessionID: (0 ..< 16).map { seed &+ UInt8($0) },
        bindingID: (0 ..< 16).map { seed &+ 16 &+ UInt8($0) },
        pskGeneration: 7,
        sequenceEpoch: 9
    )
}

func deterministicPadding(
    _ bytes: UnsafeMutableRawBufferPointer
) {
    for index in 0 ..< bytes.count {
        bytes[index] = UInt8(truncatingIfNeeded: index &* 31 &+ 17)
    }
}

