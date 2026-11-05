import CryptoKit
import Dispatch
import Foundation
import XCTest
@testable import WinnPrivacyCore

final class StageBProtectedFlowTests: XCTestCase {
    private let key = Array(0 ..< 32).map(UInt8.init)

    func testWireRoundTripAndFixedLengths() throws {
        let request = try fixtureRequest()
        let encoded = try StageBReflectorCodec.encodeRequest(
            request,
            key: key
        )
        XCTAssertEqual(encoded.count, 254)
        XCTAssertEqual(Array(encoded.prefix(4)), Array("WBR3".utf8))
        XCTAssertEqual(encoded[4], 1)
        XCTAssertEqual(encoded[5], 1)
        XCTAssertEqual(encoded[6], 0)
        XCTAssertEqual(encoded[7], 0)
        XCTAssertEqual(
            Array(encoded[8 ..< 14]),
            Array("winn/3".utf8)
        )

        let verified = try StageBReflectorCodec.verifyRequest(
            encoded,
            key: key,
            reflectorNowUnixMilliseconds: 1_005
        )
        XCTAssertEqual(verified.request, request)
        let response = try StageBReflectorCodec.encodeResponse(
            for: verified,
            key: key,
            reflectorReceivedUnixMilliseconds: 1_005,
            reflectorSentUnixMilliseconds: 1_006
        )
        XCTAssertEqual(response.count, 302)
        XCTAssertEqual(response[5], 2)
        XCTAssertEqual(
            try StageBReflectorCodec.verifyResponse(
                response,
                expectedRequest: request,
                key: key
            ).request,
            request
        )
    }

    func testHandAuthoredWireOffsetsAndDomains() throws {
        let request = try fixtureRequest()
        var body = [UInt8](repeating: 0, count: 222)
        body.replaceSubrange(0 ..< 4, with: Array("WBR3".utf8))
        body[4] = 1
        body[5] = 1
        body.replaceSubrange(8 ..< 14, with: Array("winn/3".utf8))
        body.replaceSubrange(14 ..< 30, with: request.runID)
        body.replaceSubrange(
            30 ..< 46,
            with: request.attemptNonce
        )
        body.replaceSubrange(
            46 ..< 78,
            with: request.sourceSHA256
        )
        body.replaceSubrange(
            78 ..< 110,
            with: request.artifactSHA256
        )
        body.replaceSubrange(
            110 ..< 126,
            with: request.context.sessionID
        )
        body.replaceSubrange(
            126 ..< 142,
            with: request.context.bindingID
        )
        writeUInt64(
            request.context.pskGeneration,
            to: &body,
            at: 142
        )
        writeUInt64(
            request.context.sequenceEpoch,
            to: &body,
            at: 150
        )
        writeUInt64(request.canarySequence, to: &body, at: 158)
        writeUInt64(
            request.issuedAtUnixMilliseconds,
            to: &body,
            at: 166
        )
        writeUInt64(
            request.expiresAtUnixMilliseconds,
            to: &body,
            at: 174
        )
        writeUInt64(
            request.requestSentMonotonicNanoseconds,
            to: &body,
            at: 182
        )
        body.replaceSubrange(
            190 ..< 222,
            with: request.challenge
        )
        XCTAssertEqual(body[6], 0)
        XCTAssertEqual(body[7], 0)
        XCTAssertEqual(Array(body[142 ..< 150]),
                       [0, 0, 0, 0, 0, 0, 0, 7])
        XCTAssertEqual(Array(body[158 ..< 166]),
                       [0, 0, 0, 0, 0, 0, 0, 7])

        let requestDomain =
            Array("winn-stageb-request/v1\0".utf8)
        let requestTag = Array(
            HMAC<SHA256>.authenticationCode(
                for: Data(requestDomain + body),
                using: SymmetricKey(data: key)
            )
        )
        let manualRequest = Data(body + requestTag)
        XCTAssertEqual(
            manualRequest,
            try StageBReflectorCodec.encodeRequest(
                request,
                key: key
            )
        )
        let noNULRequestTag = Array(
            HMAC<SHA256>.authenticationCode(
                for: Data(
                    Array("winn-stageb-request/v1".utf8) + body
                ),
                using: SymmetricKey(data: key)
            )
        )
        XCTAssertNotEqual(requestTag, noNULRequestTag)

        var responsePrefix = body
        responsePrefix[5] = 2
        responsePrefix.append(contentsOf: requestTag)
        responsePrefix.append(contentsOf: [UInt8](repeating: 0, count: 16))
        writeUInt64(1_005, to: &responsePrefix, at: 254)
        writeUInt64(1_006, to: &responsePrefix, at: 262)
        XCTAssertEqual(responsePrefix.count, 270)
        let responseDomain =
            Array("winn-stageb-response/v1\0".utf8)
        let responseTag = Array(
            HMAC<SHA256>.authenticationCode(
                for: Data(responseDomain + responsePrefix),
                using: SymmetricKey(data: key)
            )
        )
        let manualResponse = Data(responsePrefix + responseTag)
        let verified = try StageBReflectorCodec.verifyRequest(
            manualRequest,
            key: key,
            reflectorNowUnixMilliseconds: 1_005
        )
        XCTAssertEqual(
            manualResponse,
            try StageBReflectorCodec.encodeResponse(
                for: verified,
                key: key,
                reflectorReceivedUnixMilliseconds: 1_005,
                reflectorSentUnixMilliseconds: 1_006
            )
        )
        let wrongResponseDomainTag = Array(
            HMAC<SHA256>.authenticationCode(
                for: Data(requestDomain + responsePrefix),
                using: SymmetricKey(data: key)
            )
        )
        XCTAssertNotEqual(responseTag, wrongResponseDomainTag)
    }

    func testGoOwnedCanonicalPublicVectorExactBytesAndDigests()
        throws
    {
        let testFile = URL(fileURLWithPath: #filePath)
        let vectorURL = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("stagebreflector")
            .appendingPathComponent("testdata")
            .appendingPathComponent("stageb-v1-vectors.json")
        let vectorJSON = try Data(contentsOf: vectorURL)
        let fixture = try JSONDecoder().decode(
            StageBCanonicalFixture.self,
            from: vectorJSON
        )
        XCTAssertEqual(fixture.schema,
                       "winn-stageb-reflector-vectors/1")
        XCTAssertEqual(fixture.wireSchema,
                       "winn-stageb-reflector-wire/1")
        XCTAssertEqual(fixture.protocolVersion, "winn/3")
        XCTAssertEqual(fixture.scope, "local-conformance-only")
        XCTAssertEqual(fixture.inputsClass,
                       "deterministic-public-non-secret")
        let vectorKey = try XCTUnwrap(
            Data(base64Encoded: fixture.publicTestKeyBase64)
        )
        let vectorRequest = try XCTUnwrap(
            Data(base64Encoded: fixture.requestBase64)
        )
        let vectorResponse = try XCTUnwrap(
            Data(base64Encoded: fixture.responseBase64)
        )
        XCTAssertEqual(vectorKey.count, 32)
        XCTAssertEqual(vectorRequest.count, 254)
        XCTAssertEqual(vectorResponse.count, 302)

        let request = try canonicalVectorRequest(fixture.requestInput)
        let swiftRequest = try StageBReflectorCodec.encodeRequest(
            request,
            key: [UInt8](vectorKey)
        )
        XCTAssertEqual(swiftRequest, vectorRequest)
        XCTAssertEqual(sha256Hex(swiftRequest), fixture.requestSHA256)
        let verifiedRequest = try StageBReflectorCodec.verifyRequest(
            vectorRequest,
            key: [UInt8](vectorKey),
            reflectorNowUnixMilliseconds:
                fixture.reflectorNowUnixMilliseconds
        )
        let swiftResponse = try StageBReflectorCodec.encodeResponse(
            for: verifiedRequest,
            key: [UInt8](vectorKey),
            reflectorReceivedUnixMilliseconds:
                fixture.reflectorReceivedUnixMilliseconds,
            reflectorSentUnixMilliseconds:
                fixture.reflectorSentUnixMilliseconds
        )
        XCTAssertEqual(swiftResponse, vectorResponse)
        XCTAssertEqual(sha256Hex(swiftResponse), fixture.responseSHA256)
        XCTAssertNoThrow(
            try StageBReflectorCodec.verifyResponse(
                vectorResponse,
                expectedRequest: request,
                key: [UInt8](vectorKey)
            )
        )

        var badRequestTag = vectorRequest
        badRequestTag[253] ^= 1
        XCTAssertThrowsError(
            try StageBReflectorCodec.verifyRequest(
                badRequestTag,
                key: [UInt8](vectorKey),
                reflectorNowUnixMilliseconds:
                    fixture.reflectorNowUnixMilliseconds
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .authenticationFailed)
        }
        var wrongKey = [UInt8](vectorKey)
        wrongKey[0] ^= 1
        XCTAssertThrowsError(
            try StageBReflectorCodec.verifyRequest(
                vectorRequest,
                key: wrongKey,
                reflectorNowUnixMilliseconds:
                    fixture.reflectorNowUnixMilliseconds
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .authenticationFailed)
        }
        var badResponseTag = vectorResponse
        badResponseTag[301] ^= 1
        XCTAssertThrowsError(
            try StageBReflectorCodec.verifyResponse(
                badResponseTag,
                expectedRequest: request,
                key: [UInt8](vectorKey)
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .authenticationFailed)
        }

        var topLevel = try XCTUnwrap(
            JSONSerialization.jsonObject(with: vectorJSON)
                as? [String: Any]
        )
        topLevel["unexpected"] = true
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                StageBCanonicalFixture.self,
                from: JSONSerialization.data(
                    withJSONObject: topLevel
                )
            )
        )
        topLevel.removeValue(forKey: "unexpected")
        var nested = try XCTUnwrap(
            topLevel["request_input"] as? [String: Any]
        )
        nested["unexpected"] = true
        topLevel["request_input"] = nested
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                StageBCanonicalFixture.self,
                from: JSONSerialization.data(
                    withJSONObject: topLevel
                )
            )
        )
    }

    func testEveryRequestBodyFieldIsAuthenticated() throws {
        let encoded = try StageBReflectorCodec.encodeRequest(
            fixtureRequest(),
            key: key
        )
        for offset in 0 ..< 222 {
            var mutated = encoded
            mutated[offset] ^= 1
            XCTAssertThrowsError(
                try StageBReflectorCodec.verifyRequest(
                    mutated,
                    key: key,
                    reflectorNowUnixMilliseconds: 1_005
                ),
                "offset \(offset)"
            )
        }
        var wrongTag = encoded
        wrongTag[253] ^= 1
        XCTAssertThrowsError(
            try StageBReflectorCodec.verifyRequest(
                wrongTag,
                key: key,
                reflectorNowUnixMilliseconds: 1_005
            )
        )
        XCTAssertThrowsError(
            try StageBReflectorCodec.verifyRequest(
                encoded,
                key: Array(repeating: 9, count: 32),
                reflectorNowUnixMilliseconds: 1_005
            )
        )
    }

    func testExactAndMalformedDatagramLengthsRejected() throws {
        let request = try fixtureRequest()
        let encoded = try StageBReflectorCodec.encodeRequest(
            request,
            key: key
        )
        for malformed in [
            Data(encoded.dropLast()),
            encoded + Data([0]),
            Data(repeating: 0, count: 4_096),
        ] {
            XCTAssertThrowsError(
                try StageBReflectorCodec.verifyRequest(
                    malformed,
                    key: key,
                    reflectorNowUnixMilliseconds: 1_005
                )
            ) {
                XCTAssertEqual($0 as? StageBError, .invalidLength)
            }
        }

        let verified = try StageBReflectorCodec.verifyRequest(
            encoded,
            key: key,
            reflectorNowUnixMilliseconds: 1_005
        )
        let response = try StageBReflectorCodec.encodeResponse(
            for: verified,
            key: key,
            reflectorReceivedUnixMilliseconds: 1_005,
            reflectorSentUnixMilliseconds: 1_006
        )
        for malformed in [
            Data(response.dropLast()),
            response + Data([0]),
        ] {
            XCTAssertThrowsError(
                try StageBReflectorCodec.verifyResponse(
                    malformed,
                    expectedRequest: request,
                    key: key
                )
            ) {
                XCTAssertEqual($0 as? StageBError, .invalidLength)
            }
        }
    }

    func testRequestFixedFieldAndValueValidation() throws {
        let context = try testContext()
        let zero16 = [UInt8](repeating: 0, count: 16)
        let nonzero16 = [UInt8](repeating: 1, count: 16)
        let nonzero32 = [UInt8](repeating: 2, count: 32)
        XCTAssertThrowsError(
            try StageBRequest(
                runID: zero16,
                attemptNonce: nonzero16,
                sourceSHA256: nonzero32,
                artifactSHA256: nonzero32,
                context: context,
                canarySequence: 1,
                issuedAtUnixMilliseconds: 1,
                expiresAtUnixMilliseconds: 2,
                requestSentMonotonicNanoseconds: 3,
                challenge: nonzero32
            )
        )
        XCTAssertThrowsError(
            try StageBRequest(
                runID: nonzero16,
                attemptNonce: nonzero16,
                sourceSHA256: nonzero32,
                artifactSHA256: nonzero32,
                context: context,
                canarySequence: 0,
                issuedAtUnixMilliseconds: 1,
                expiresAtUnixMilliseconds: 2,
                requestSentMonotonicNanoseconds: 3,
                challenge: nonzero32
            )
        )
        XCTAssertThrowsError(
            try StageBRequest(
                runID: nonzero16,
                attemptNonce: nonzero16,
                sourceSHA256: nonzero32,
                artifactSHA256: nonzero32,
                context: context,
                canarySequence: 1,
                issuedAtUnixMilliseconds: 1,
                expiresAtUnixMilliseconds: 10_002,
                requestSentMonotonicNanoseconds: 3,
                challenge: nonzero32
            )
        )
    }

    func testRequestClockClosedInterval() throws {
        let encoded = try StageBReflectorCodec.encodeRequest(
            fixtureRequest(),
            key: key
        )
        XCTAssertNoThrow(
            try StageBReflectorCodec.verifyRequest(
                encoded,
                key: key,
                reflectorNowUnixMilliseconds: 1_000
            )
        )
        XCTAssertNoThrow(
            try StageBReflectorCodec.verifyRequest(
                encoded,
                key: key,
                reflectorNowUnixMilliseconds: 1_010
            )
        )
        for time: UInt64 in [999, 1_011] {
            XCTAssertThrowsError(
                try StageBReflectorCodec.verifyRequest(
                    encoded,
                    key: key,
                    reflectorNowUnixMilliseconds: time
                )
            ) {
                XCTAssertEqual($0 as? StageBError, .invalidClock)
            }
        }
    }

    func testNearUInt64MaxLifetimeAndDeadlineOverflow() throws {
        let context = try testContext()
        let nonzero16 = [UInt8](repeating: 1, count: 16)
        let nonzero32 = [UInt8](repeating: 2, count: 32)
        XCTAssertNoThrow(
            try StageBRequest(
                runID: nonzero16,
                attemptNonce: nonzero16,
                sourceSHA256: nonzero32,
                artifactSHA256: nonzero32,
                context: context,
                canarySequence: 1,
                issuedAtUnixMilliseconds:
                    UInt64.max - 10_000,
                expiresAtUnixMilliseconds: UInt64.max,
                requestSentMonotonicNanoseconds: 1,
                challenge: nonzero32
            )
        )
        XCTAssertThrowsError(
            try StageBAttemptLease(
                attemptNonce: nonzero16,
                pathID: nonzero16,
                context: context,
                requestedAtMonotonicNanoseconds:
                    UInt64.max -
                    StageBProtectedFlow.deadlineNanoseconds + 1
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .arithmeticOverflow)
        }
        let exact = try StageBAttemptLease(
            attemptNonce: nonzero16,
            pathID: nonzero16,
            context: context,
            requestedAtMonotonicNanoseconds:
                UInt64.max -
                StageBProtectedFlow.deadlineNanoseconds
        )
        XCTAssertEqual(
            exact.deadlineMonotonicNanoseconds,
            UInt64.max
        )
    }

    func testResponseAuthenticationBindingAndReflectorTime() throws {
        let request = try fixtureRequest()
        let encoded = try StageBReflectorCodec.encodeRequest(
            request,
            key: key
        )
        let verified = try StageBReflectorCodec.verifyRequest(
            encoded,
            key: key,
            reflectorNowUnixMilliseconds: 1_005
        )
        let response = try StageBReflectorCodec.encodeResponse(
            for: verified,
            key: key,
            reflectorReceivedUnixMilliseconds: 1_005,
            reflectorSentUnixMilliseconds: 1_006
        )
        for offset in 0 ..< response.count {
            var mutated = response
            mutated[offset] ^= 1
            XCTAssertThrowsError(
                try StageBReflectorCodec.verifyResponse(
                    mutated,
                    expectedRequest: request,
                    key: key
                ),
                "offset \(offset)"
            )
        }
        let other = try fixtureRequest(canary: 8)
        XCTAssertThrowsError(
            try StageBReflectorCodec.verifyResponse(
                response,
                expectedRequest: other,
                key: key
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .bindingMismatch)
        }
        XCTAssertThrowsError(
            try StageBReflectorCodec.encodeResponse(
                for: verified,
                key: key,
                reflectorReceivedUnixMilliseconds: 1_006,
                reflectorSentUnixMilliseconds: 1_005
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .invalidClock)
        }
    }

    func testAuthenticatedRemacedSemanticResponseMutationsRejected()
        throws
    {
        let request = try fixtureRequest()
        let valid = try response(for: request)
        for offset in 0 ..< 14 {
            let remaced = remacResponse(valid) { bytes in
                bytes[offset] ^= 1
            }
            XCTAssertThrowsError(
                try StageBReflectorCodec.verifyResponse(
                    remaced,
                    expectedRequest: request,
                    key: key
                ),
                "fixed offset \(offset)"
            ) {
                XCTAssertEqual($0 as? StageBError, .invalidFixedField)
            }
        }
        for (label, mutation) in [
            ("run", { (bytes: inout [UInt8]) in bytes[14] ^= 1 }),
            ("attempt", { (bytes: inout [UInt8]) in bytes[30] ^= 1 }),
            ("source", { (bytes: inout [UInt8]) in bytes[46] ^= 1 }),
            ("artifact", { (bytes: inout [UInt8]) in bytes[78] ^= 1 }),
            ("session", { (bytes: inout [UInt8]) in bytes[110] ^= 1 }),
            ("binding", { (bytes: inout [UInt8]) in bytes[126] ^= 1 }),
            ("psk", { (bytes: inout [UInt8]) in bytes[149] ^= 1 }),
            ("epoch", { (bytes: inout [UInt8]) in bytes[157] ^= 1 }),
            ("canary", { (bytes: inout [UInt8]) in bytes[165] ^= 1 }),
            ("issued", { (bytes: inout [UInt8]) in bytes[173] ^= 1 }),
            ("expires", { (bytes: inout [UInt8]) in bytes[181] ^= 1 }),
            ("request-clock", {
                (bytes: inout [UInt8]) in bytes[189] ^= 1
            }),
            ("challenge", {
                (bytes: inout [UInt8]) in bytes[190] ^= 1
            }),
        ] {
            let remaced = remacResponse(valid, mutate: mutation)
            XCTAssertThrowsError(
                try StageBReflectorCodec.verifyResponse(
                    remaced,
                    expectedRequest: request,
                    key: key
                ),
                label
            ) {
                XCTAssertEqual($0 as? StageBError, .bindingMismatch)
            }
        }

        let wrongEcho = remacResponse(valid) { bytes in
            bytes[222] ^= 1
        }
        XCTAssertThrowsError(
            try StageBReflectorCodec.verifyResponse(
                wrongEcho,
                expectedRequest: request,
                key: key
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .authenticationFailed)
        }

        let reversedTime = remacResponse(valid) { bytes in
            writeUInt64(1_007, to: &bytes, at: 254)
            writeUInt64(1_006, to: &bytes, at: 262)
        }
        XCTAssertThrowsError(
            try StageBReflectorCodec.verifyResponse(
                reversedTime,
                expectedRequest: request,
                key: key
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .invalidClock)
        }
        let timeCases: [(String, UInt64, UInt64)] = [
            ("received-before-issue", 999, 1_006),
            ("sent-after-expiry", 1_005, 1_011),
        ]
        for (label, received, sent) in timeCases {
            let remaced = remacResponse(valid) { bytes in
                writeUInt64(received, to: &bytes, at: 254)
                writeUInt64(sent, to: &bytes, at: 262)
            }
            XCTAssertThrowsError(
                try StageBReflectorCodec.verifyResponse(
                    remaced,
                    expectedRequest: request,
                    key: key
                ),
                label
            ) {
                XCTAssertEqual($0 as? StageBError, .invalidClock)
            }
        }
    }

    func testReplayCacheRejectsReplayAndLiveCapacity() throws {
        let first = try verifiedRequest(fixtureRequest(canary: 1))
        let second = try verifiedRequest(fixtureRequest(canary: 2))
        let cache = try StageBReplayCache(capacity: 2)
        try cache.consume(verifiedRequest: first, nowUnixMilliseconds: 1_005)
        try cache.consume(verifiedRequest: second, nowUnixMilliseconds: 1_006)
        XCTAssertThrowsError(
            try cache.consume(
                verifiedRequest: first,
                nowUnixMilliseconds: 1_011
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .replay)
        }
        let later = try verifiedRequest(
            fixtureRequest(
                canary: 4,
                issue: 1_011,
                expiry: 1_020
            ),
            now: 1_011
        )
        try cache.consume(
            verifiedRequest: later,
            nowUnixMilliseconds: 1_011
        )
        XCTAssertEqual(cache.count, 1)
        let rollback = try verifiedRequest(fixtureRequest(canary: 3))
        XCTAssertThrowsError(
            try cache.consume(
                verifiedRequest: rollback,
                nowUnixMilliseconds: 1_005
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .reversedTime)
        }
        XCTAssertEqual(cache.count, 1)
        XCTAssertThrowsError(
            try StageBReplayCache(
                capacity: StageBProtectedFlow.maximumReplayCapacity + 1
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .cacheCapacity)
        }
        XCTAssertNoThrow(
            try StageBReplayCache(
                capacity: StageBProtectedFlow.maximumReplayCapacity
            )
        )
    }

    func testFourPredicateStateMachineAndExactBoundary() throws {
        let lease = try fixtureLease()
        let request = try fixtureRequest(sentMonotonic: 100)
        let binding = StageBEventBinding(lease: lease)
        let attempt = try makeAttempt(
            lease: lease,
            request: request,
            processingNow: lease.deadlineMonotonicNanoseconds
        )
        let response = try response(for: request)
        XCTAssertEqual(
            try attempt.recordFreshAWGHandshake(
                binding: binding,
                atMonotonicNanoseconds: 101
            ),
            .active
        )
        XCTAssertEqual(
            try attempt.recordAuthenticatedTunnelBytes(
                binding: binding,
                outboundBytes: 1,
                inboundBytes: 1,
                atMonotonicNanoseconds: 102
            ),
            .active
        )
        XCTAssertEqual(
            try attempt.recordProtectedDNSResponse(
                binding: binding,
                atMonotonicNanoseconds: 103
            ),
            .active
        )
        XCTAssertEqual(
            try attempt.acceptAuthenticatedReflectorResponse(
                response
            ),
            .succeeded
        )
        XCTAssertEqual(attempt.localReceipt().measurementScope,
                       "local-conformance-only")

        let lateLease = try fixtureLease()
        let late = try makeAttempt(lease: lateLease, request: request)
        XCTAssertThrowsError(
            try late.recordFreshAWGHandshake(
                binding: StageBEventBinding(lease: lateLease),
                atMonotonicNanoseconds:
                    lateLease.deadlineMonotonicNanoseconds + 1
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .deadlineExceeded)
        }
        XCTAssertEqual(late.status, .failed)
    }

    func testCoreProofAuthorityAcceptsOnlyTheExactLadderPermutation()
        throws
    {
        let lease = try fixtureLease()
        let binding = StageBEventBinding(lease: lease)
        let request = try fixtureRequest()
        let datagram = try response(for: request)
        let exactOrder: [StageBCoreProofEvent] = [
            .handshake,
            .tunnelBytes,
            .dns,
            .reflector,
        ]
        var succeeded = 0
        var rejected = 0

        for ordering in stageBCorePermutations(
            StageBCoreProofEvent.allCases
        ) {
            let attempt = try makeAttempt(
                lease: lease,
                request: request,
                processingNow: 110
            )
            var thrown: StageBError?
            for (index, event) in ordering.enumerated() {
                do {
                    let time = UInt64(101 + index)
                    switch event {
                    case .handshake:
                        _ = try attempt.recordFreshAWGHandshake(
                            binding: binding,
                            atMonotonicNanoseconds: time
                        )
                    case .tunnelBytes:
                        _ = try attempt.recordAuthenticatedTunnelBytes(
                            binding: binding,
                            outboundBytes: 1,
                            inboundBytes: 1,
                            atMonotonicNanoseconds: time
                        )
                    case .dns:
                        _ = try attempt.recordProtectedDNSResponse(
                            binding: binding,
                            atMonotonicNanoseconds: time
                        )
                    case .reflector:
                        _ = try attempt
                            .acceptAuthenticatedReflectorResponse(
                                datagram
                            )
                    }
                } catch let error as StageBError {
                    thrown = error
                    break
                }
            }

            if ordering == exactOrder {
                XCTAssertNil(thrown, "ordering \(ordering)")
                XCTAssertEqual(attempt.status, .succeeded)
                succeeded += 1
            } else {
                XCTAssertEqual(
                    thrown,
                    .invalidSequence,
                    "ordering \(ordering)"
                )
                XCTAssertEqual(attempt.status, .failed)
                rejected += 1
            }
        }

        XCTAssertEqual(succeeded, 1)
        XCTAssertEqual(rejected, 23)
    }

    func testAttemptRejectsZeroDuplicateReversedAndBindingMismatch()
        throws
    {
        let lease = try fixtureLease()
        let binding = StageBEventBinding(lease: lease)

        let zero = try makeAttempt(lease: lease)
        XCTAssertThrowsError(
            try zero.recordAuthenticatedTunnelBytes(
                binding: binding,
                outboundBytes: 0,
                inboundBytes: 1,
                atMonotonicNanoseconds: 101
            )
        )
        XCTAssertEqual(zero.status, .failed)

        let duplicate = try makeAttempt(lease: lease)
        _ = try duplicate.recordFreshAWGHandshake(
            binding: binding,
            atMonotonicNanoseconds: 101
        )
        XCTAssertThrowsError(
            try duplicate.recordFreshAWGHandshake(
                binding: binding,
                atMonotonicNanoseconds: 102
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .duplicateEvent)
        }

        let reversed = try makeAttempt(lease: lease)
        _ = try reversed.recordFreshAWGHandshake(
            binding: binding,
            atMonotonicNanoseconds: 102
        )
        XCTAssertThrowsError(
            try reversed.recordProtectedDNSResponse(
                binding: binding,
                atMonotonicNanoseconds: 101
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .reversedTime)
        }

        let mismatch = try makeAttempt(lease: lease)
        let other = try fixtureLease(pathByte: 0xaa)
        XCTAssertThrowsError(
            try mismatch.recordProtectedDNSResponse(
                binding: StageBEventBinding(lease: other),
                atMonotonicNanoseconds: 101
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .bindingMismatch)
        }
    }

    func testCancelledAndSupersededAttemptsIgnoreLaterEvents() throws {
        let lease = try fixtureLease()
        let binding = StageBEventBinding(lease: lease)
        let cancelled = try makeAttempt(lease: lease)
        cancelled.cancel()
        XCTAssertThrowsError(
            try cancelled.recordFreshAWGHandshake(
                binding: binding,
                atMonotonicNanoseconds: 101
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .cancelled)
        }
        XCTAssertFalse(cancelled.localReceipt().freshAWGHandshake)

        let superseded = try makeAttempt(lease: lease)
        superseded.supersedePath()
        XCTAssertThrowsError(
            try superseded.recordProtectedDNSResponse(
                binding: binding,
                atMonotonicNanoseconds: 101
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .superseded)
        }
        XCTAssertFalse(
            superseded.localReceipt().protectedDNSResponseObserved
        )
    }

    func testUnifiedAttemptEnforcesRequestResponseDeadlineChain() throws {
        let request = try fixtureRequest(sentMonotonic: 100)
        let lease = try fixtureLease()
        let datagram = try response(for: request)
        let exact = try makeAttempt(
            lease: lease,
            request: request,
            processingNow: lease.deadlineMonotonicNanoseconds
        )
        try primeThroughProtectedDNS(exact, lease: lease)
        XCTAssertEqual(
            try exact.acceptAuthenticatedReflectorResponse(
                datagram
            ),
            .succeeded
        )

        let late = try makeAttempt(
            lease: lease,
            request: request,
            processingNow:
                lease.deadlineMonotonicNanoseconds + 1
        )
        try primeThroughProtectedDNS(late, lease: lease)
        XCTAssertThrowsError(
            try late.acceptAuthenticatedReflectorResponse(
                datagram
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .deadlineExceeded)
        }
        XCTAssertEqual(late.status, .failed)

        let sentAfterRequested = try fixtureRequest(sentMonotonic: 101)
        let observedBeforeSent = try makeAttempt(
            lease: lease,
            request: sentAfterRequested,
            processingNow: 100
        )
        try primeThroughProtectedDNS(
            observedBeforeSent,
            lease: lease
        )
        XCTAssertThrowsError(
            try observedBeforeSent.acceptAuthenticatedReflectorResponse(
                try response(for: sentAfterRequested)
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .reversedTime)
        }
        XCTAssertThrowsError(
            try makeAttempt(
                lease: lease,
                request: fixtureRequest(sentMonotonic: 99)
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .reversedTime)
        }
        XCTAssertThrowsError(
            try makeAttempt(
                lease: lease,
                request: fixtureRequest(
                    sentMonotonic:
                        lease.deadlineMonotonicNanoseconds + 1
                )
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .deadlineExceeded)
        }
    }

    func testDomainOwnedKeyAndExactOutboundTagCannotBeSubstituted()
        throws
    {
        let lease = try fixtureLease()
        let request = try fixtureRequest()
        var sourceKey = key
        let domain = try StageBAcceptanceDomain(
            capacity: 4,
            key: sourceKey,
            monotonicClock: { 101 }
        )
        sourceKey[0] ^= 1
        let alternateKey = [UInt8](repeating: 0xa5, count: 32)

        let alternateRequestDatagram =
            try StageBReflectorCodec.encodeRequest(
                request,
                key: alternateKey
            )
        let alternateVerified =
            try StageBReflectorCodec.verifyRequest(
                alternateRequestDatagram,
                key: alternateKey,
                reflectorNowUnixMilliseconds: 1_005
            )
        let alternateResponse =
            try StageBReflectorCodec.encodeResponse(
                for: alternateVerified,
                key: alternateKey,
                reflectorReceivedUnixMilliseconds: 1_005,
                reflectorSentUnixMilliseconds: 1_006
            )
        let alternateAttempt = try domain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
        try primeThroughProtectedDNS(
            alternateAttempt,
            lease: lease
        )
        XCTAssertEqual(
            alternateAttempt.requestDatagram,
            try StageBReflectorCodec.encodeRequest(
                request,
                key: key
            )
        )
        XCTAssertThrowsError(
            try alternateAttempt
                .acceptAuthenticatedReflectorResponse(
                    alternateResponse
                )
        ) {
            XCTAssertEqual($0 as? StageBError, .authenticationFailed)
        }

        let exactTagAttempt = try domain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
        try primeThroughProtectedDNS(
            exactTagAttempt,
            lease: lease
        )
        var mutatedOutbound = exactTagAttempt.requestDatagram
        mutatedOutbound[253] ^= 1
        XCTAssertThrowsError(
            try StageBReflectorCodec.verifyRequest(
                mutatedOutbound,
                key: key,
                reflectorNowUnixMilliseconds: 1_005
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .authenticationFailed)
        }
        let wrongEcho = remacResponse(try response(for: request)) {
            bytes in
            bytes[222] ^= 1
        }
        XCTAssertThrowsError(
            try exactTagAttempt
                .acceptAuthenticatedReflectorResponse(wrongEcho)
        ) {
            XCTAssertEqual($0 as? StageBError, .authenticationFailed)
        }

        let mismatchedRequest = try fixtureRequest(canary: 8)
        let mismatchedAttempt = try domain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
        try primeThroughProtectedDNS(
            mismatchedAttempt,
            lease: lease
        )
        XCTAssertThrowsError(
            try mismatchedAttempt
                .acceptAuthenticatedReflectorResponse(
                    try response(for: mismatchedRequest)
                )
        ) {
            XCTAssertEqual($0 as? StageBError, .bindingMismatch)
        }
        XCTAssertEqual(domain.acceptedResponseCount, 0)
        XCTAssertThrowsError(
            try StageBAcceptanceDomain(
                capacity: 1,
                key: [UInt8](repeating: 0, count: 31),
                monotonicClock: { 1 }
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .invalidKey)
        }
    }

    func testSharedResponseGuardRejectsTwoOwnersAndRollback() throws {
        let lease = try fixtureLease()
        let request = try fixtureRequest(sentMonotonic: 100)
        let datagram = try response(for: request)
        let clock = StageBTestMonotonicClock([102, 102, 101])
        let domain = try StageBAcceptanceDomain(
            capacity: 2,
            key: key,
            monotonicClock: { clock.next() }
        )
        let first = try domain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
        let second = try domain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
        try primeThroughProtectedDNS(first, lease: lease)
        try primeThroughProtectedDNS(second, lease: lease)
        XCTAssertNoThrow(
            try first.acceptAuthenticatedReflectorResponse(
                datagram
            )
        )
        XCTAssertThrowsError(
            try second.acceptAuthenticatedReflectorResponse(
                datagram
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .replay)
        }
        XCTAssertEqual(second.status, .failed)
        XCTAssertEqual(domain.acceptedResponseCount, 1)

        let rollbackRequest = try fixtureRequest(
            canary: 8,
            sentMonotonic: 100
        )
        let rollback = try domain.makeAttempt(
            lease: lease,
            expectedRequest: rollbackRequest
        )
        try primeThroughProtectedDNS(rollback, lease: lease)
        XCTAssertThrowsError(
            try rollback.acceptAuthenticatedReflectorResponse(
                try response(for: rollbackRequest)
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .reversedTime)
        }
        XCTAssertEqual(domain.acceptedResponseCount, 1)
        XCTAssertThrowsError(
            try StageBAcceptanceDomain(
                capacity:
                    StageBProtectedFlow.maximumReplayCapacity + 1,
                key: key,
                monotonicClock: { 1 }
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .cacheCapacity)
        }

        let laterRequested =
            lease.deadlineMonotonicNanoseconds + 1
        let capacityClock = StageBTestMonotonicClock(
            [102, 103, laterRequested, 102]
        )
        let capacityDomain = try StageBAcceptanceDomain(
            capacity: 1,
            key: key,
            monotonicClock: { capacityClock.next() }
        )
        let capacityFirst = try capacityDomain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
        try primeThroughProtectedDNS(capacityFirst, lease: lease)
        _ = try capacityFirst.acceptAuthenticatedReflectorResponse(
            datagram
        )
        let capacityRequest = try fixtureRequest(canary: 9)
        let capacitySecond = try capacityDomain.makeAttempt(
            lease: lease,
            expectedRequest: capacityRequest
        )
        try primeThroughProtectedDNS(capacitySecond, lease: lease)
        XCTAssertThrowsError(
            try capacitySecond.acceptAuthenticatedReflectorResponse(
                try response(for: capacityRequest)
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .cacheCapacity)
        }

        let laterLease = try fixtureLease(
            requestedAtMonotonicNanoseconds: laterRequested
        )
        let laterRequest = try fixtureRequest(
            canary: 10,
            sentMonotonic: laterRequested
        )
        let recycled = try capacityDomain.makeAttempt(
            lease: laterLease,
            expectedRequest: laterRequest
        )
        try primeThroughProtectedDNS(recycled, lease: laterLease)
        XCTAssertNoThrow(
            try recycled.acceptAuthenticatedReflectorResponse(
                try response(for: laterRequest)
            )
        )
        XCTAssertEqual(capacityDomain.acceptedResponseCount, 1)

        let rollbackOriginal = try capacityDomain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
        try primeThroughProtectedDNS(
            rollbackOriginal,
            lease: lease
        )
        XCTAssertThrowsError(
            try rollbackOriginal.acceptAuthenticatedReflectorResponse(
                datagram
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .reversedTime)
        }
    }

    func testConcurrentAttemptsShareOneRaceSafeReplayDecision() throws {
        let lease = try fixtureLease()
        let request = try fixtureRequest()
        let datagram = try response(for: request)
        let domain = try StageBAcceptanceDomain(
            capacity: 8,
            key: key,
            monotonicClock: { 102 }
        )
        let attempts = try (0 ..< 8).map { _ in
            try domain.makeAttempt(
                lease: lease,
                expectedRequest: request
            )
        }
        for attempt in attempts {
            try primeThroughProtectedDNS(attempt, lease: lease)
        }
        let resultLock = NSLock()
        var successes = 0
        var failures = [StageBError]()
        DispatchQueue.concurrentPerform(iterations: attempts.count) {
            index in
            do {
                _ = try attempts[index]
                    .acceptAuthenticatedReflectorResponse(
                        datagram
                    )
                resultLock.lock()
                successes += 1
                resultLock.unlock()
            } catch let error as StageBError {
                resultLock.lock()
                failures.append(error)
                resultLock.unlock()
            } catch {
                XCTFail("unexpected error category")
            }
        }
        XCTAssertEqual(successes, 1)
        XCTAssertEqual(failures.count, 7)
        XCTAssertTrue(failures.allSatisfy { $0 == .replay })
        XCTAssertEqual(domain.acceptedResponseCount, 1)
    }

    func testReverseSchedulerDistinctResponsesUseInternalClockOrder()
        throws
    {
        let lease = try fixtureLease()
        let firstRequest = try fixtureRequest(canary: 21)
        let secondRequest = try fixtureRequest(canary: 22)
        let clock = StageBTestMonotonicClock([102, 103])
        let domain = try StageBAcceptanceDomain(
            capacity: 2,
            key: key,
            monotonicClock: { clock.next() }
        )
        let first = try domain.makeAttempt(
            lease: lease,
            expectedRequest: firstRequest
        )
        let second = try domain.makeAttempt(
            lease: lease,
            expectedRequest: secondRequest
        )
        try primeThroughProtectedDNS(first, lease: lease)
        try primeThroughProtectedDNS(second, lease: lease)

        // Deliberately process the logical "second" response first. The
        // acceptance domain, not either caller, assigns ordered observations.
        XCTAssertNoThrow(
            try second.acceptAuthenticatedReflectorResponse(
                try response(for: secondRequest)
            )
        )
        XCTAssertNoThrow(
            try first.acceptAuthenticatedReflectorResponse(
                try response(for: firstRequest)
            )
        )
        XCTAssertEqual(
            second.localReceipt()
                .reflectorObservedAtMonotonicNanoseconds,
            102
        )
        XCTAssertEqual(
            first.localReceipt()
                .reflectorObservedAtMonotonicNanoseconds,
            103
        )
        XCTAssertEqual(domain.acceptedResponseCount, 2)
    }

    func testCancellationAndSupersessionConvergeOnOneAuthority()
        throws
    {
        let lease = try fixtureLease()
        let request = try fixtureRequest()
        let datagram = try response(for: request)
        let domain = try StageBAcceptanceDomain(
            capacity: 2,
            key: key,
            monotonicClock: { 101 }
        )
        let cancelled = try domain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
        cancelled.cancel()
        XCTAssertThrowsError(
            try cancelled.acceptAuthenticatedReflectorResponse(
                datagram
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .cancelled)
        }
        XCTAssertThrowsError(
            try cancelled.recordProtectedDNSResponse(
                binding: StageBEventBinding(lease: lease),
                atMonotonicNanoseconds: 102
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .cancelled)
        }
        XCTAssertEqual(cancelled.status, .cancelled)
        XCTAssertEqual(domain.acceptedResponseCount, 0)
        XCTAssertFalse(
            cancelled.localReceipt()
                .authenticatedReflectorResponseObserved
        )

        let superseded = try domain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
        superseded.supersedePath()
        XCTAssertThrowsError(
            try superseded.acceptAuthenticatedReflectorResponse(
                datagram
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .superseded)
        }
        XCTAssertEqual(superseded.status, .superseded)
        XCTAssertEqual(domain.acceptedResponseCount, 0)
    }

    func testTerminalAuthenticationMismatchMakesLaterInputNoOp()
        throws
    {
        let lease = try fixtureLease()
        let request = try fixtureRequest()
        let datagram = try response(for: request)
        let mismatch = try makeAttempt(lease: lease, request: request)
        try primeThroughProtectedDNS(mismatch, lease: lease)
        var malformed = datagram
        malformed[301] ^= 1
        XCTAssertThrowsError(
            try mismatch.acceptAuthenticatedReflectorResponse(
                malformed
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .authenticationFailed)
        }
        XCTAssertThrowsError(
            try mismatch.acceptAuthenticatedReflectorResponse(
                datagram
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .terminal)
        }
        XCTAssertFalse(
            mismatch.localReceipt()
                .authenticatedReflectorResponseObserved
        )
    }

    func testTimeoutExactBoundaryAndPlusOne() throws {
        let lease = try fixtureLease()
        let exact = try makeAttempt(lease: lease)
        exact.timeout(
            atMonotonicNanoseconds:
                lease.deadlineMonotonicNanoseconds
        )
        XCTAssertEqual(exact.status, .active)
        let late = try makeAttempt(lease: lease)
        late.timeout(
            atMonotonicNanoseconds:
                lease.deadlineMonotonicNanoseconds + 1
        )
        XCTAssertEqual(late.status, .failed)
        XCTAssertThrowsError(
            try late.recordFreshAWGHandshake(
                binding: StageBEventBinding(lease: lease),
                atMonotonicNanoseconds:
                    lease.deadlineMonotonicNanoseconds
            )
        ) {
            XCTAssertEqual($0 as? StageBError, .terminal)
        }
    }

    func testErrorsAndReceiptDoNotExposeSensitiveMaterial() throws {
        let request = try fixtureRequest()
        let encoded = try StageBReflectorCodec.encodeRequest(
            request,
            key: key
        )
        var mutated = encoded
        mutated[253] ^= 1
        do {
            _ = try StageBReflectorCodec.verifyRequest(
                mutated,
                key: key,
                reflectorNowUnixMilliseconds: 1_005
            )
            XCTFail("expected rejection")
        } catch {
            let rendered = String(describing: error)
            for secret in [
                Data(key).base64EncodedString(),
                Data(request.challenge).base64EncodedString(),
                Data(encoded.suffix(32)).base64EncodedString(),
                "127.0.0.1",
                "00008140",
            ] {
                XCTAssertFalse(rendered.contains(secret))
            }
        }
        let receipt = try makeAttempt().localReceipt()
        let rendered = String(describing: receipt)
        XCTAssertTrue(rendered.contains("local-conformance-only"))
        XCTAssertFalse(rendered.contains(Data(key).base64EncodedString()))
    }

    private func fixtureRequest(
        canary: UInt64 = 7,
        issue: UInt64 = 1_000,
        expiry: UInt64 = 1_010,
        sentMonotonic: UInt64 = 100
    ) throws -> StageBRequest {
        try StageBRequest(
            runID: Array(1 ... 16),
            attemptNonce: Array(17 ... 32),
            sourceSHA256: Array(33 ... 64),
            artifactSHA256: Array(65 ... 96),
            context: testContext(),
            canarySequence: canary,
            issuedAtUnixMilliseconds: issue,
            expiresAtUnixMilliseconds: expiry,
            requestSentMonotonicNanoseconds: sentMonotonic,
            challenge: Array(97 ... 128)
        )
    }

    private func fixtureLease(
        pathByte: UInt8 = 0x55,
        requestedAtMonotonicNanoseconds: UInt64 = 100
    ) throws -> StageBAttemptLease {
        try StageBAttemptLease(
            attemptNonce: Array(17 ... 32),
            pathID: Array(repeating: pathByte, count: 16),
            context: testContext(),
            requestedAtMonotonicNanoseconds:
                requestedAtMonotonicNanoseconds
        )
    }

    private func verifiedRequest(
        _ request: StageBRequest,
        now: UInt64 = 1_005
    ) throws -> StageBVerifiedRequest {
        try StageBReflectorCodec.verifyRequest(
            StageBReflectorCodec.encodeRequest(request, key: key),
            key: key,
            reflectorNowUnixMilliseconds: now
        )
    }

    private func response(
        for request: StageBRequest
    ) throws -> Data {
        try StageBReflectorCodec.encodeResponse(
            for: verifiedRequest(request),
            key: key,
            reflectorReceivedUnixMilliseconds: 1_005,
            reflectorSentUnixMilliseconds: 1_006
        )
    }

    private func makeAttempt(
        lease suppliedLease: StageBAttemptLease? = nil,
        request suppliedRequest: StageBRequest? = nil,
        acceptanceDomain suppliedDomain: StageBAcceptanceDomain? = nil,
        processingNow: UInt64 = 101
    ) throws -> StageBProtectedFlowAttempt {
        let lease = try suppliedLease ?? fixtureLease()
        let request = try suppliedRequest ?? fixtureRequest()
        let domain = try suppliedDomain ?? StageBAcceptanceDomain(
            capacity: 8,
            key: key,
            monotonicClock: { processingNow }
        )
        return try domain.makeAttempt(
            lease: lease,
            expectedRequest: request
        )
    }

    private func primeThroughProtectedDNS(
        _ attempt: StageBProtectedFlowAttempt,
        lease: StageBAttemptLease
    ) throws {
        let binding = StageBEventBinding(lease: lease)
        let time = max(
            lease.requestedAtMonotonicNanoseconds,
            attempt.expectedRequest.requestSentMonotonicNanoseconds
        )
        _ = try attempt.recordFreshAWGHandshake(
            binding: binding,
            atMonotonicNanoseconds: time
        )
        _ = try attempt.recordAuthenticatedTunnelBytes(
            binding: binding,
            outboundBytes: 1,
            inboundBytes: 1,
            atMonotonicNanoseconds: time
        )
        _ = try attempt.recordProtectedDNSResponse(
            binding: binding,
            atMonotonicNanoseconds: time
        )
    }

    private func remacResponse(
        _ datagram: Data,
        mutate: (inout [UInt8]) -> Void
    ) -> Data {
        var bytes = [UInt8](datagram)
        mutate(&bytes)
        let domain = Array("winn-stageb-response/v1\0".utf8)
        let tag = HMAC<SHA256>.authenticationCode(
            for: Data(domain + bytes[0 ..< 270]),
            using: SymmetricKey(data: key)
        )
        bytes.replaceSubrange(270 ..< 302, with: Array(tag))
        return Data(bytes)
    }

    private func writeUInt64(
        _ value: UInt64,
        to bytes: inout [UInt8],
        at offset: Int
    ) {
        for index in 0 ..< 8 {
            bytes[offset + index] = UInt8(
                truncatingIfNeeded:
                    value >> UInt64(56 - index * 8)
            )
        }
    }

    private func canonicalVectorRequest(
        _ input: StageBCanonicalRequestInput
    ) throws -> StageBRequest {
        let context = try WCF3ConnectionContext(
            sessionID: try decodeBase64(input.wcf3SessionIDBase64),
            bindingID: try decodeBase64(input.wcf3BindingIDBase64),
            pskGeneration: input.pskGeneration,
            sequenceEpoch: input.sequenceEpoch
        )
        return try StageBRequest(
            runID: try decodeBase64(input.runIDBase64),
            attemptNonce: try decodeBase64(input.attemptNonceBase64),
            sourceSHA256: try decodeBase64(input.sourceSHA256Base64),
            artifactSHA256: try decodeBase64(
                input.artifactSHA256Base64
            ),
            context: context,
            canarySequence: input.canarySequence,
            issuedAtUnixMilliseconds:
                input.issuedAtUnixMilliseconds,
            expiresAtUnixMilliseconds:
                input.expiresAtUnixMilliseconds,
            requestSentMonotonicNanoseconds:
                input.requestSentMonotonicNanoseconds,
            challenge: try decodeBase64(input.challengeBase64)
        )
    }

    private func decodeBase64(_ encoded: String) throws -> [UInt8] {
        [UInt8](try XCTUnwrap(Data(base64Encoded: encoded)))
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map {
            String(format: "%02x", $0)
        }.joined()
    }
}

private struct StageBCanonicalFixture: Decodable {
    let schema: String
    let wireSchema: String
    let protocolVersion: String
    let scope: String
    let inputsClass: String
    let publicTestKeyBase64: String
    let requestInput: StageBCanonicalRequestInput
    let reflectorNowUnixMilliseconds: UInt64
    let reflectorReceivedUnixMilliseconds: UInt64
    let reflectorSentUnixMilliseconds: UInt64
    let requestBase64: String
    let requestSHA256: String
    let responseBase64: String
    let responseSHA256: String

    init(from decoder: Decoder) throws {
        try requireExactKeys(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let container = try decoder.container(
            keyedBy: CodingKeys.self
        )
        schema = try container.decode(String.self, forKey: .schema)
        wireSchema = try container.decode(
            String.self,
            forKey: .wireSchema
        )
        protocolVersion = try container.decode(
            String.self,
            forKey: .protocolVersion
        )
        scope = try container.decode(String.self, forKey: .scope)
        inputsClass = try container.decode(
            String.self,
            forKey: .inputsClass
        )
        publicTestKeyBase64 = try container.decode(
            String.self,
            forKey: .publicTestKeyBase64
        )
        requestInput = try container.decode(
            StageBCanonicalRequestInput.self,
            forKey: .requestInput
        )
        reflectorNowUnixMilliseconds = try container.decode(
            UInt64.self,
            forKey: .reflectorNowUnixMilliseconds
        )
        reflectorReceivedUnixMilliseconds = try container.decode(
            UInt64.self,
            forKey: .reflectorReceivedUnixMilliseconds
        )
        reflectorSentUnixMilliseconds = try container.decode(
            UInt64.self,
            forKey: .reflectorSentUnixMilliseconds
        )
        requestBase64 = try container.decode(
            String.self,
            forKey: .requestBase64
        )
        requestSHA256 = try container.decode(
            String.self,
            forKey: .requestSHA256
        )
        responseBase64 = try container.decode(
            String.self,
            forKey: .responseBase64
        )
        responseSHA256 = try container.decode(
            String.self,
            forKey: .responseSHA256
        )
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case wireSchema = "wire_schema"
        case protocolVersion = "protocol"
        case scope
        case inputsClass = "inputs_class"
        case publicTestKeyBase64 = "public_test_key_base64"
        case requestInput = "request_input"
        case reflectorNowUnixMilliseconds =
            "reflector_now_unix_milliseconds"
        case reflectorReceivedUnixMilliseconds =
            "reflector_received_unix_milliseconds"
        case reflectorSentUnixMilliseconds =
            "reflector_sent_unix_milliseconds"
        case requestBase64 = "request_base64"
        case requestSHA256 = "request_sha256"
        case responseBase64 = "response_base64"
        case responseSHA256 = "response_sha256"
    }
}

private struct StageBCanonicalRequestInput: Decodable {
    let runIDBase64: String
    let attemptNonceBase64: String
    let sourceSHA256Base64: String
    let artifactSHA256Base64: String
    let wcf3SessionIDBase64: String
    let wcf3BindingIDBase64: String
    let pskGeneration: UInt64
    let sequenceEpoch: UInt64
    let canarySequence: UInt64
    let issuedAtUnixMilliseconds: UInt64
    let expiresAtUnixMilliseconds: UInt64
    let requestSentMonotonicNanoseconds: UInt64
    let challengeBase64: String

    init(from decoder: Decoder) throws {
        try requireExactKeys(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let container = try decoder.container(
            keyedBy: CodingKeys.self
        )
        runIDBase64 = try container.decode(
            String.self,
            forKey: .runIDBase64
        )
        attemptNonceBase64 = try container.decode(
            String.self,
            forKey: .attemptNonceBase64
        )
        sourceSHA256Base64 = try container.decode(
            String.self,
            forKey: .sourceSHA256Base64
        )
        artifactSHA256Base64 = try container.decode(
            String.self,
            forKey: .artifactSHA256Base64
        )
        wcf3SessionIDBase64 = try container.decode(
            String.self,
            forKey: .wcf3SessionIDBase64
        )
        wcf3BindingIDBase64 = try container.decode(
            String.self,
            forKey: .wcf3BindingIDBase64
        )
        pskGeneration = try container.decode(
            UInt64.self,
            forKey: .pskGeneration
        )
        sequenceEpoch = try container.decode(
            UInt64.self,
            forKey: .sequenceEpoch
        )
        canarySequence = try container.decode(
            UInt64.self,
            forKey: .canarySequence
        )
        issuedAtUnixMilliseconds = try container.decode(
            UInt64.self,
            forKey: .issuedAtUnixMilliseconds
        )
        expiresAtUnixMilliseconds = try container.decode(
            UInt64.self,
            forKey: .expiresAtUnixMilliseconds
        )
        requestSentMonotonicNanoseconds = try container.decode(
            UInt64.self,
            forKey: .requestSentMonotonicNanoseconds
        )
        challengeBase64 = try container.decode(
            String.self,
            forKey: .challengeBase64
        )
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case runIDBase64 = "run_id_base64"
        case attemptNonceBase64 = "attempt_nonce_base64"
        case sourceSHA256Base64 = "source_sha256_base64"
        case artifactSHA256Base64 = "artifact_sha256_base64"
        case wcf3SessionIDBase64 = "wcf3_session_id_base64"
        case wcf3BindingIDBase64 = "wcf3_binding_id_base64"
        case pskGeneration = "psk_generation"
        case sequenceEpoch = "sequence_epoch"
        case canarySequence = "canary_sequence"
        case issuedAtUnixMilliseconds =
            "issued_at_unix_milliseconds"
        case expiresAtUnixMilliseconds =
            "expires_at_unix_milliseconds"
        case requestSentMonotonicNanoseconds =
            "request_sent_monotonic_nanoseconds"
        case challengeBase64 = "challenge_base64"
    }
}

private struct StageBStrictCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private enum StageBCoreProofEvent: CaseIterable {
    case handshake
    case tunnelBytes
    case dns
    case reflector
}

private func stageBCorePermutations<T>(_ values: [T]) -> [[T]] {
    guard let first = values.first else { return [[]] }
    return stageBCorePermutations(Array(values.dropFirst())).flatMap {
        suffix in
        (0 ... suffix.count).map { index in
            var ordering = suffix
            ordering.insert(first, at: index)
            return ordering
        }
    }
}

private func requireExactKeys(
    _ decoder: Decoder,
    allowed: Set<String>
) throws {
    let container = try decoder.container(
        keyedBy: StageBStrictCodingKey.self
    )
    let actual = Set(container.allKeys.map(\.stringValue))
    guard actual == allowed else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "fixture key set mismatch"
            )
        )
    }
}

private final class StageBTestMonotonicClock: @unchecked Sendable {
    private let lock = NSLock()
    private let values: [UInt64]
    private var index = 0

    init(_ values: [UInt64]) {
        precondition(!values.isEmpty)
        self.values = values
    }

    func next() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let value = values[min(index, values.count - 1)]
        index += 1
        return value
    }
}
