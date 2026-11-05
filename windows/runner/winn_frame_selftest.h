#ifndef RUNNER_WINN_FRAME_SELFTEST_H_
#define RUNNER_WINN_FRAME_SELFTEST_H_

// Conformance self-test for the Winn engine framing in winn_frame.h.
//
// Header-only and platform-free on purpose: the Windows binaries call it from
// their validation self-test path, and it is also compiled and executed
// directly on the development host, which is the only place this layer can
// actually be run without a Windows machine. Keep it free of <windows.h> and
// of anything that would stop a plain `clang++ -std=c++17` from building it.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "winn_frame.h"

namespace winsvpn::winn {

// Byte-exact expectation for a known frame. If this ever changes, every lane
// that speaks the framing has to change with it, which is the point.
inline bool CheckGoldenEncoding(std::string* failure) {
  const std::string payload = "hi";
  std::vector<uint8_t> encoded;
  if (!EncodeFrame(Opcode::kCreate, payload, &encoded)) {
    *failure = "golden: EncodeFrame rejected a valid create frame";
    return false;
  }
  const uint8_t expected[] = {
      0x57, 0x4E, 0x4E, 0x33,  // magic 'W' 'N' 'N' '3'
      0x01, 0x00,              // version 1
      0x01, 0x00,              // opcode kCreate
      0x02, 0x00, 0x00, 0x00,  // length 2
      0x00, 0x00, 0x00, 0x00,  // reserved
      0x68, 0x69,              // "hi"
  };
  if (encoded.size() != sizeof(expected)) {
    *failure = "golden: encoded size drifted";
    return false;
  }
  for (size_t i = 0; i < sizeof(expected); ++i) {
    if (encoded[i] != expected[i]) {
      *failure = "golden: encoded byte " + std::to_string(i) + " drifted";
      return false;
    }
  }
  return true;
}

inline bool CheckRoundTrip(std::string* failure) {
  std::vector<uint8_t> stream;
  const std::vector<uint8_t> packet_a = {0x45, 0x00, 0x00, 0x28, 0xAB, 0xCD};
  const std::vector<uint8_t> packet_b(1420, 0x5A);
  for (const auto& item : {packet_a, packet_b}) {
    std::vector<uint8_t> encoded;
    if (!EncodeFrame(Opcode::kOutbound, item.data(), item.size(), &encoded)) {
      *failure = "roundtrip: EncodeFrame rejected a valid outbound frame";
      return false;
    }
    stream.insert(stream.end(), encoded.begin(), encoded.end());
  }
  std::vector<uint8_t> status;
  if (!EncodeFrame(Opcode::kStatusResponse, std::string("{\"up\":true}"),
                   &status)) {
    *failure = "roundtrip: EncodeFrame rejected a valid status frame";
    return false;
  }
  stream.insert(stream.end(), status.begin(), status.end());

  // Feed the stream one byte at a time. A reader that only works on whole
  // frames passes a naive test and then corrupts traffic on a real pipe.
  FrameReader reader(/*accept_engine_to_host=*/true);
  std::vector<Frame> frames;
  for (size_t i = 0; i < stream.size(); ++i) {
    reader.Append(&stream[i], 1);
    for (;;) {
      Frame frame;
      const DecodeStatus status_code = reader.Next(&frame);
      if (status_code == DecodeStatus::kInvalid) {
        *failure = "roundtrip: reader rejected a valid stream at byte " +
                   std::to_string(i);
        return false;
      }
      if (status_code == DecodeStatus::kNeedMore) break;
      frames.push_back(frame);
    }
  }
  if (frames.size() != 3) {
    *failure = "roundtrip: expected 3 frames, got " +
               std::to_string(frames.size());
    return false;
  }
  if (frames[0].opcode != Opcode::kOutbound || frames[0].payload != packet_a ||
      frames[1].opcode != Opcode::kOutbound || frames[1].payload != packet_b ||
      frames[2].opcode != Opcode::kStatusResponse) {
    *failure = "roundtrip: frame contents drifted";
    return false;
  }
  if (reader.buffered() != 0) {
    *failure = "roundtrip: reader retained trailing bytes";
    return false;
  }
  return true;
}

inline bool CheckRejections(std::string* failure) {
  struct Case {
    const char* name;
    Opcode opcode;
    uint32_t declared_length;
    size_t actual_payload;
    uint32_t magic;
    uint16_t version;
    uint32_t reserved;
    bool accept_engine_to_host;
  };
  const Case cases[] = {
      {"bad magic", Opcode::kOutbound, 4, 4, 0xDEADBEEFu, kFrameVersion, 0,
       true},
      {"bad version", Opcode::kOutbound, 4, 4, kFrameMagic, 99, 0, true},
      {"nonzero reserved", Opcode::kOutbound, 4, 4, kFrameMagic, kFrameVersion,
       1, true},
      {"unknown opcode", static_cast<Opcode>(0x7777), 4, 4, kFrameMagic,
       kFrameVersion, 0, true},
      // The host must refuse a frame that only the engine should ever receive.
      {"wrong direction", Opcode::kInbound, 4, 4, kFrameMagic, kFrameVersion, 0,
       true},
      {"oversize length", Opcode::kOutbound, kMaxFramePayloadBytes + 1, 4,
       kFrameMagic, kFrameVersion, 0, true},
      {"empty packet", Opcode::kOutbound, 0, 0, kFrameMagic, kFrameVersion, 0,
       true},
      {"payload on close ack", Opcode::kCloseAck, 4, 4, kFrameMagic,
       kFrameVersion, 0, true},
  };
  for (const Case& item : cases) {
    std::vector<uint8_t> raw;
    AppendLittleEndianU32(&raw, item.magic);
    AppendLittleEndianU16(&raw, item.version);
    AppendLittleEndianU16(&raw, static_cast<uint16_t>(item.opcode));
    AppendLittleEndianU32(&raw, item.declared_length);
    AppendLittleEndianU32(&raw, item.reserved);
    raw.insert(raw.end(), item.actual_payload, 0x41);

    FrameReader reader(item.accept_engine_to_host);
    reader.Append(raw.data(), raw.size());
    Frame frame;
    if (reader.Next(&frame) != DecodeStatus::kInvalid) {
      *failure = std::string("rejection: reader accepted ") + item.name;
      return false;
    }
  }

  std::vector<uint8_t> encoded;
  const std::vector<uint8_t> too_big(kMaxFramePayloadBytes + 1, 0x00);
  if (EncodeFrame(Opcode::kInbound, too_big.data(), too_big.size(),
                  &encoded)) {
    *failure = "rejection: EncodeFrame accepted an oversize payload";
    return false;
  }
  if (EncodeFrame(static_cast<Opcode>(0x4242), std::string("x"), &encoded)) {
    *failure = "rejection: EncodeFrame accepted an unknown opcode";
    return false;
  }
  return true;
}

// Every host reads the engine's pipe in 64 KiB chunks. A chunk that lands on
// top of a partial frame must decode every complete frame it carries, in
// order, at every chunk size, with nothing left over at the end.
inline bool CheckLargeReads(std::string* failure) {
  std::vector<uint8_t> stream;
  std::vector<std::vector<uint8_t>> sent;
  for (size_t i = 0; i < 600; ++i) {
    std::vector<uint8_t> packet(40 + (i * 97) % 1400,
                                static_cast<uint8_t>(i & 0xff));
    packet[0] = 0x45;
    std::vector<uint8_t> encoded;
    if (!EncodeFrame(Opcode::kOutbound, packet.data(), packet.size(),
                     &encoded)) {
      *failure = "large reads: EncodeFrame rejected a valid packet";
      return false;
    }
    stream.insert(stream.end(), encoded.begin(), encoded.end());
    sent.push_back(packet);
  }
  const size_t chunks[] = {65536, 65535, 4096, 1500, 17};
  for (size_t chunk : chunks) {
    FrameReader reader(/*accept_engine_to_host=*/true);
    size_t got = 0;
    for (size_t offset = 0; offset < stream.size(); offset += chunk) {
      const size_t size = std::min(chunk, stream.size() - offset);
      reader.Append(&stream[offset], size);
      Frame frame;
      for (;;) {
        const DecodeStatus status = reader.Next(&frame);
        if (status == DecodeStatus::kInvalid) {
          *failure = "large reads: a valid stream was refused at chunk size " +
                     std::to_string(chunk) + " after " + std::to_string(got) +
                     " frames";
          return false;
        }
        if (status == DecodeStatus::kNeedMore) break;
        if (got >= sent.size() || frame.payload != sent[got] ||
            frame.opcode != Opcode::kOutbound) {
          *failure = "large reads: frame " + std::to_string(got) +
                     " drifted at chunk size " + std::to_string(chunk);
          return false;
        }
        ++got;
      }
    }
    if (got != sent.size() || reader.buffered() != 0) {
      *failure = "large reads: decoded " + std::to_string(got) + " of " +
                 std::to_string(sent.size()) + " at chunk size " +
                 std::to_string(chunk);
      return false;
    }
  }
  return true;
}

// True when the framing behaves exactly as the contract requires.
inline bool RunWinnFrameSelfTest(std::string* failure) {
  std::string local;
  std::string* sink = failure == nullptr ? &local : failure;
  sink->clear();
  return CheckGoldenEncoding(sink) && CheckRoundTrip(sink) &&
         CheckRejections(sink) && CheckLargeReads(sink);
}

}  // namespace winsvpn::winn

#endif  // RUNNER_WINN_FRAME_SELFTEST_H_
