#ifndef RUNNER_WINN_FRAME_H_
#define RUNNER_WINN_FRAME_H_

// Wire framing for the Winn Protocol engine subprocess on Windows.
//
// WINN_PROTOCOL_PLATFORM_PLAN.md section 2 fixes the *semantic* contract:
//
//   WinnTunnelCreate(configJson, udpFd) -> handle | error
//   WinnTunnelWriteInbound(handle, buf, len)      // host tun -> protocol
//   WinnTunnelReadOutbound(handle, buf, cap) -> n // protocol -> host tun
//   WinnTunnelStatusJSON(handle) -> json
//   WinnTunnelClose(handle)
//
// and fixes the Windows *transport* as "subprocess + duplex pipe". It does not
// fix the byte layout on that pipe. This header defines that layout so the
// Windows host and the Go engine can be built independently. If the `datapath`
// lane publishes a different layout, this header is the single place to change.
//
// Deliberately portable: standard C++17 only, no <windows.h>, no exceptions,
// no dynamic dispatch. It compiles and its self-test runs on any host, which
// is the only way this layer can be verified without a Windows machine.
//
//   offset  size  field
//   0       4     magic    u32 little-endian, kFrameMagic
//   4       2     version  u16 little-endian, kFrameVersion
//   6       2     opcode   u16 little-endian, see Opcode
//   8       4     length   u32 little-endian, payload byte count
//   12      4     reserved u32 little-endian, must be zero
//   16      len   payload
//
// Every field is little-endian because both defined targets (windows/amd64 and
// windows/arm64) are little-endian and Go's encoding/binary.LittleEndian maps
// to it with no conversion. `reserved` keeps the header 16-byte aligned so a
// payload copied out of it never straddles a cache line unnecessarily, and
// gives one free extension slot without a version bump.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace winsvpn::winn {

// 'W' 'N' 'N' '3' read as a little-endian u32.
constexpr uint32_t kFrameMagic = 0x334E4E57u;
constexpr uint16_t kFrameVersion = 1;
constexpr size_t kFrameHeaderBytes = 16;

// One IP packet per frame. The tunnel MTU is 1420, but an over-large frame
// must be rejected rather than truncated, so the ceiling is generous and
// explicit. It also bounds the reader's buffer growth.
constexpr uint32_t kMaxFramePayloadBytes = 65535;

// A reader that has buffered more than this without completing a frame is
// being fed garbage or a hostile length, and is torn down.
constexpr size_t kMaxReaderBufferBytes =
    kFrameHeaderBytes + kMaxFramePayloadBytes;

enum class Opcode : uint16_t {
  // host -> engine: payload is the UTF-8 config JSON. WinnTunnelCreate.
  kCreate = 0x0001,
  // engine -> host: payload is UTF-8 status JSON for the created handle.
  kCreateAck = 0x0002,
  // host -> engine: payload is exactly one IP packet. WinnTunnelWriteInbound.
  kInbound = 0x0010,
  // engine -> host: payload is exactly one IP packet. WinnTunnelReadOutbound.
  kOutbound = 0x0011,
  // host -> engine: empty payload. WinnTunnelStatusJSON.
  kStatusRequest = 0x0020,
  // engine -> host: payload is UTF-8 status JSON.
  kStatusResponse = 0x0021,
  // host -> engine: empty payload. WinnTunnelClose.
  kClose = 0x0030,
  // engine -> host: empty payload, acknowledges kClose.
  kCloseAck = 0x0031,
  // engine -> host: payload is UTF-8 error text.
  kError = 0x00F0,
};

// Direction is part of the contract, not a convention. Each side rejects any
// frame carrying an opcode it is not supposed to receive, so a confused or
// hostile peer cannot, for example, feed the host an inbound packet and have
// it looped straight back out.
constexpr bool IsHostToEngineOpcode(Opcode opcode) {
  return opcode == Opcode::kCreate || opcode == Opcode::kInbound ||
         opcode == Opcode::kStatusRequest || opcode == Opcode::kClose;
}

constexpr bool IsEngineToHostOpcode(Opcode opcode) {
  return opcode == Opcode::kCreateAck || opcode == Opcode::kOutbound ||
         opcode == Opcode::kStatusResponse || opcode == Opcode::kCloseAck ||
         opcode == Opcode::kError;
}

constexpr bool IsKnownOpcode(Opcode opcode) {
  return IsHostToEngineOpcode(opcode) || IsEngineToHostOpcode(opcode);
}

struct Frame {
  Opcode opcode = Opcode::kError;
  std::vector<uint8_t> payload;
};

enum class DecodeStatus {
  // A complete frame was produced.
  kFrame,
  // The buffer holds a valid prefix; more bytes are required.
  kNeedMore,
  // The buffer is unrecoverable. The caller must tear the channel down; it
  // must never resynchronize by scanning forward for the next magic, because
  // that turns a length confusion into an attacker-chosen frame boundary.
  kInvalid,
};

inline void AppendLittleEndianU16(std::vector<uint8_t>* out, uint16_t value) {
  out->push_back(static_cast<uint8_t>(value & 0xFFu));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

inline void AppendLittleEndianU32(std::vector<uint8_t>* out, uint32_t value) {
  out->push_back(static_cast<uint8_t>(value & 0xFFu));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
}

inline uint16_t ReadLittleEndianU16(const uint8_t* bytes) {
  return static_cast<uint16_t>(static_cast<uint16_t>(bytes[0]) |
                               static_cast<uint16_t>(bytes[1] << 8));
}

inline uint32_t ReadLittleEndianU32(const uint8_t* bytes) {
  return static_cast<uint32_t>(bytes[0]) |
         (static_cast<uint32_t>(bytes[1]) << 8) |
         (static_cast<uint32_t>(bytes[2]) << 16) |
         (static_cast<uint32_t>(bytes[3]) << 24);
}

// Returns false and leaves `out` untouched when the payload is too large.
inline bool EncodeFrame(Opcode opcode,
                        const uint8_t* payload,
                        size_t payload_size,
                        std::vector<uint8_t>* out) {
  if (out == nullptr || payload_size > kMaxFramePayloadBytes ||
      (payload == nullptr && payload_size != 0) || !IsKnownOpcode(opcode)) {
    return false;
  }
  out->clear();
  out->reserve(kFrameHeaderBytes + payload_size);
  AppendLittleEndianU32(out, kFrameMagic);
  AppendLittleEndianU16(out, kFrameVersion);
  AppendLittleEndianU16(out, static_cast<uint16_t>(opcode));
  AppendLittleEndianU32(out, static_cast<uint32_t>(payload_size));
  AppendLittleEndianU32(out, 0u);
  if (payload_size != 0) {
    out->insert(out->end(), payload, payload + payload_size);
  }
  return true;
}

inline bool EncodeFrame(Opcode opcode,
                        const std::string& payload,
                        std::vector<uint8_t>* out) {
  return EncodeFrame(opcode,
                     reinterpret_cast<const uint8_t*>(payload.data()),
                     payload.size(), out);
}

// Incremental decoder over a byte stream. A pipe hands back arbitrary chunk
// sizes, so frames must be reassembled rather than assumed to arrive whole.
class FrameReader {
 public:
  // `accept` filters by direction: the host constructs a reader that accepts
  // only engine->host opcodes, and the engine the reverse.
  explicit FrameReader(bool accept_engine_to_host)
      : accept_engine_to_host_(accept_engine_to_host) {}

  // Bytes before begin_ are frames already returned. They are dropped here,
  // once per Append, so a reader that pops n frames out of one large read
  // moves at most the one partial frame left at its end, instead of moving
  // the whole remainder after every frame (quadratic in the frames per read:
  // about 1.5 MB of memmove per 64 KiB read of 1,400-byte frames).
  void Append(const uint8_t* bytes, size_t size) {
    if (bytes == nullptr || size == 0) return;
    if (begin_ != 0) {
      buffer_.erase(buffer_.begin(),
                    buffer_.begin() + static_cast<std::ptrdiff_t>(begin_));
      begin_ = 0;
    }
    buffer_.insert(buffer_.end(), bytes, bytes + size);
  }

  size_t buffered() const { return buffer_.size() - begin_; }

  // Pops one frame if a complete, valid one is buffered.
  //
  // kMaxReaderBufferBytes bounds the bytes held WITHOUT a complete frame. It
  // used to be checked against everything buffered, so a host that read a
  // full 64 KiB chunk on top of any partial frame of more than 15 bytes was
  // told the engine had sent an invalid frame, with complete frames sitting
  // in the buffer, and tore the session down under load.
  DecodeStatus Next(Frame* frame) {
    if (frame == nullptr) return DecodeStatus::kInvalid;
    const size_t available = buffered();
    if (available < kFrameHeaderBytes) return DecodeStatus::kNeedMore;

    const uint8_t* header = buffer_.data() + begin_;
    if (ReadLittleEndianU32(header) != kFrameMagic ||
        ReadLittleEndianU16(header + 4) != kFrameVersion ||
        ReadLittleEndianU32(header + 12) != 0u) {
      return DecodeStatus::kInvalid;
    }
    const Opcode opcode = static_cast<Opcode>(ReadLittleEndianU16(header + 6));
    const uint32_t length = ReadLittleEndianU32(header + 8);
    if (length > kMaxFramePayloadBytes || !IsKnownOpcode(opcode)) {
      return DecodeStatus::kInvalid;
    }
    const bool direction_ok = accept_engine_to_host_
                                  ? IsEngineToHostOpcode(opcode)
                                  : IsHostToEngineOpcode(opcode);
    if (!direction_ok) return DecodeStatus::kInvalid;
    // Opcodes whose payload is fixed as empty must be exactly empty. A
    // trailing payload on kClose would otherwise be silently discarded.
    if ((opcode == Opcode::kStatusRequest || opcode == Opcode::kClose ||
         opcode == Opcode::kCloseAck) &&
        length != 0) {
      return DecodeStatus::kInvalid;
    }
    // A zero-length packet frame carries no IP packet and is a protocol error
    // rather than a no-op, because silently dropping it hides a broken engine.
    if ((opcode == Opcode::kInbound || opcode == Opcode::kOutbound) &&
        length == 0) {
      return DecodeStatus::kInvalid;
    }

    const size_t total = kFrameHeaderBytes + static_cast<size_t>(length);
    if (available < total) {
      // The declared length is already bounded, so an incomplete frame stays
      // under the cap; the check is kept for what it always meant.
      return available > kMaxReaderBufferBytes ? DecodeStatus::kInvalid
                                               : DecodeStatus::kNeedMore;
    }

    frame->opcode = opcode;
    frame->payload.assign(header + kFrameHeaderBytes, header + total);
    begin_ += total;
    if (begin_ == buffer_.size()) {
      buffer_.clear();
      begin_ = 0;
    }
    return DecodeStatus::kFrame;
  }

 private:
  bool accept_engine_to_host_;
  std::vector<uint8_t> buffer_;
  size_t begin_ = 0;
};

}  // namespace winsvpn::winn

#endif  // RUNNER_WINN_FRAME_H_
