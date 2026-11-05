import CryptoKit
import Foundation
import XCTest
@testable import WinnPrivacyCore

final class WCF3CodecTests: XCTestCase {
    func testFrozenConstantsMatchGoWCF3() {
        XCTAssertEqual(WCF3Constants.headerSize, 64)
        XCTAssertEqual(WCF3Constants.privacyCellSize, 1_024)
        XCTAssertEqual(WCF3Constants.privacyPayloadSize, 960)
        XCTAssertEqual(WCF3Constants.maximumShuffleNanoseconds, 20_000_000)
        XCTAssertEqual(WCF3Constants.coverIntervalNanoseconds, 1_000_000_000)
        XCTAssertEqual(WCF3Constants.coverTailNanoseconds, 30_000_000_000)
        XCTAssertEqual(WCF3Constants.circuitRotationNanoseconds, 900_000_000_000)
    }

    func testPrivacyCellRoundTripWithoutPayloadAllocation() throws {
        let context = try testContext()
        let header = WCF3FrameHeader(
            kind: .data,
            context: context,
            sequence: 42
        )
        let payload = Array("hello-winn-v3".utf8)
        var encoded = [UInt8](
            repeating: 0,
            count: WCF3Constants.privacyCellSize
        )
        _ = try payload.withUnsafeBytes { payloadBytes in
            try encoded.withUnsafeMutableBytes { destination in
                try WCF3Codec.encode(
                    header: header,
                    payload: payloadBytes,
                    totalSize: WCF3Constants.privacyCellSize,
                    into: destination,
                    paddingFiller: deterministicPadding
                )
            }
        }
        let decoded = try encoded.withUnsafeBytes {
            try WCF3Codec.decode($0, expectedContext: context)
        }
        XCTAssertEqual(decoded.header.kind, .data)
        XCTAssertEqual(decoded.header.sequence, 42)
        XCTAssertEqual(decoded.totalSize, 1_024)
        XCTAssertEqual(
            Array(encoded[decoded.payloadRange]),
            payload
        )
        XCTAssertNotEqual(
            decoded.header.flags & WCF3Constants.flagPadded,
            0
        )
        let digest = SHA256.hash(data: Data(encoded))
            .map { String(format: "%02x", $0) }
            .joined()
        XCTAssertEqual(
            digest,
            "d1dd7981e67dbcf896b5fbccc44b8d440f6685e62120dd96a8d5c61467ce7f80"
        )
    }

    func testWrongBindingFailsClosed() throws {
        let context = try testContext()
        let other = try testContext(seed: 2)
        let header = WCF3FrameHeader(
            kind: .cover,
            context: context,
            sequence: 1
        )
        var encoded = [UInt8](repeating: 0, count: 1_024)
        _ = try encoded.withUnsafeMutableBytes { destination in
            try WCF3Codec.encode(
                header: header,
                payload: UnsafeRawBufferPointer(start: nil, count: 0),
                totalSize: 1_024,
                into: destination,
                paddingFiller: deterministicPadding
            )
        }
        XCTAssertThrowsError(
            try encoded.withUnsafeBytes {
                try WCF3Codec.decode($0, expectedContext: other)
            }
        ) {
            XCTAssertEqual(
                $0 as? WCF3Error,
                .connectionBindingMismatch
            )
        }
    }
}
