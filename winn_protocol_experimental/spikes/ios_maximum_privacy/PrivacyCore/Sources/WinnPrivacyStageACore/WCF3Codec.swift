import Foundation

public struct WCF3DecodedFrame: Equatable, Sendable {
    public let header: WCF3FrameHeader
    public let payloadRange: Range<Int>
    public let totalSize: Int

    public init(
        header: WCF3FrameHeader,
        payloadRange: Range<Int>,
        totalSize: Int
    ) {
        self.header = header
        self.payloadRange = payloadRange
        self.totalSize = totalSize
    }
}

public enum WCF3Codec {
    public typealias PaddingFiller = (UnsafeMutableRawBufferPointer) -> Void

    @discardableResult
    public static func encode(
        header: WCF3FrameHeader,
        payload: UnsafeRawBufferPointer,
        totalSize: Int,
        into destination: UnsafeMutableRawBufferPointer,
        paddingFiller: PaddingFiller
    ) throws -> Int {
        try validate(header: header, payloadLength: payload.count)
        let minimumSize = WCF3Constants.headerSize + payload.count
        guard totalSize >= minimumSize,
              totalSize <= WCF3Constants.maximumFrameSize
        else {
            throw WCF3Error.frameSizeOutOfRange
        }
        guard destination.count >= totalSize else {
            throw WCF3Error.destinationTooSmall
        }

        destination.initializeMemory(as: UInt8.self, repeating: 0)
        write(WCF3Constants.magic, to: destination, at: 0)
        destination[4] = header.kind.rawValue
        var encodedFlags = header.flags & ~WCF3Constants.flagPadded
        if totalSize > minimumSize {
            encodedFlags |= WCF3Constants.flagPadded
        }
        destination[5] = encodedFlags
        writeUInt16(UInt16(payload.count), to: destination, at: 6)
        write(header.context.sessionID, to: destination, at: 8)
        write(header.context.bindingID, to: destination, at: 24)
        writeUInt64(header.context.pskGeneration, to: destination, at: 40)
        writeUInt64(header.context.sequenceEpoch, to: destination, at: 48)
        writeUInt64(header.sequence, to: destination, at: 56)

        if payload.count > 0 {
            let payloadDestination = UnsafeMutableRawBufferPointer(
                rebasing: destination[
                    WCF3Constants.headerSize ..< minimumSize
                ]
            )
            payloadDestination.copyBytes(from: payload)
        }
        if totalSize > minimumSize {
            paddingFiller(
                UnsafeMutableRawBufferPointer(
                    rebasing: destination[minimumSize ..< totalSize]
                )
            )
        }
        return totalSize
    }

    public static func decode(
        _ encoded: UnsafeRawBufferPointer,
        maximumPayload: Int = WCF3Constants.maximumPayloadSize,
        expectedContext: WCF3ConnectionContext? = nil
    ) throws -> WCF3DecodedFrame {
        guard encoded.count >= WCF3Constants.headerSize,
              encoded.count <= WCF3Constants.maximumFrameSize
        else {
            throw WCF3Error.frameSizeOutOfRange
        }
        guard Array(encoded[0 ..< 4]) == WCF3Constants.magic else {
            throw WCF3Error.invalidMagic
        }
        guard let kind = WCF3Kind(rawValue: encoded[4]) else {
            throw WCF3Error.invalidKind
        }
        let flags = encoded[5]
        guard flags & ~WCF3Constants.allowedFlags == 0 else {
            throw WCF3Error.invalidFlags
        }
        let payloadLength = Int(readUInt16(from: encoded, at: 6))
        guard maximumPayload > 0,
              maximumPayload <= WCF3Constants.maximumPayloadSize,
              payloadLength <= maximumPayload,
              WCF3Constants.headerSize + payloadLength <= encoded.count
        else {
            throw WCF3Error.invalidPayloadLength
        }
        let padded = encoded.count >
            WCF3Constants.headerSize + payloadLength
        guard padded == (flags & WCF3Constants.flagPadded != 0) else {
            throw WCF3Error.invalidPaddingState
        }

        let context = try WCF3ConnectionContext(
            sessionID: Array(encoded[8 ..< 24]),
            bindingID: Array(encoded[24 ..< 40]),
            pskGeneration: readUInt64(from: encoded, at: 40),
            sequenceEpoch: readUInt64(from: encoded, at: 48)
        )
        if let expectedContext, expectedContext != context {
            throw WCF3Error.connectionBindingMismatch
        }
        let header = WCF3FrameHeader(
            kind: kind,
            flags: flags,
            context: context,
            sequence: readUInt64(from: encoded, at: 56)
        )
        try validate(header: header, payloadLength: payloadLength)
        return WCF3DecodedFrame(
            header: header,
            payloadRange:
                WCF3Constants.headerSize ..<
                WCF3Constants.headerSize + payloadLength,
            totalSize: encoded.count
        )
    }

    private static func validate(
        header: WCF3FrameHeader,
        payloadLength: Int
    ) throws {
        guard header.flags & ~WCF3Constants.allowedFlags == 0 else {
            throw WCF3Error.invalidFlags
        }
        if header.flags & WCF3Constants.flagFinal != 0,
           header.flags & WCF3Constants.flagFragment == 0 {
            throw WCF3Error.invalidFragmentFlags
        }
        if header.flags & WCF3Constants.flagFragment != 0,
           header.kind != .data {
            throw WCF3Error.invalidFragmentFlags
        }
        guard header.sequence > 0 else {
            throw WCF3Error.invalidSequence
        }
        guard payloadLength <= WCF3Constants.maximumPayloadSize else {
            throw WCF3Error.payloadTooLarge
        }
        switch header.kind {
        case .data:
            guard payloadLength > 0 else {
                throw WCF3Error.invalidPayloadLength
            }
        case .probe, .probeAck:
            guard payloadLength == WCF3Constants.probePayloadSize else {
                throw WCF3Error.invalidPayloadLength
            }
        case .cover:
            guard payloadLength == 0,
                  header.flags &
                    (WCF3Constants.flagFragment |
                     WCF3Constants.flagFinal) == 0
            else {
                throw WCF3Error.invalidPayloadLength
            }
        }
    }

    private static func write(
        _ source: [UInt8],
        to destination: UnsafeMutableRawBufferPointer,
        at offset: Int
    ) {
        source.withUnsafeBytes { bytes in
            UnsafeMutableRawBufferPointer(
                rebasing: destination[offset ..< offset + source.count]
            ).copyBytes(from: bytes)
        }
    }

    private static func writeUInt16(
        _ value: UInt16,
        to destination: UnsafeMutableRawBufferPointer,
        at offset: Int
    ) {
        destination[offset] = UInt8((value >> 8) & 0xff)
        destination[offset + 1] = UInt8(value & 0xff)
    }

    private static func writeUInt64(
        _ value: UInt64,
        to destination: UnsafeMutableRawBufferPointer,
        at offset: Int
    ) {
        for index in 0 ..< 8 {
            destination[offset + index] =
                UInt8((value >> UInt64(56 - index * 8)) & 0xff)
        }
    }

    private static func readUInt16(
        from source: UnsafeRawBufferPointer,
        at offset: Int
    ) -> UInt16 {
        (UInt16(source[offset]) << 8) |
            UInt16(source[offset + 1])
    }

    private static func readUInt64(
        from source: UnsafeRawBufferPointer,
        at offset: Int
    ) -> UInt64 {
        var value: UInt64 = 0
        for index in 0 ..< 8 {
            value = (value << 8) | UInt64(source[offset + index])
        }
        return value
    }
}
