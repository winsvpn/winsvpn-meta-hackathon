#!/usr/bin/env bash
# WNN3 framing conformance: two independent implementations, one byte-exact
# vector, compared by a third party.
#
# WHY THIS EXISTS. A framing bug shared by the encoder and the decoder of a
# single implementation is invisible to that implementation's own round-trip
# test -- it encodes wrongly, decodes its own wrong bytes back, and passes.
# windows/runner/winn_frame.h (C++, what the Windows host ships) and
# windows/winn_framing_fixture/ (Go, written from the layout rather than from
# the C++ code) are the two implementations. This script makes them prove they
# agree.
#
# It compares BYTES THEY EACH PRODUCE, not each side's assertion that it matches
# a constant. Two implementations that each assert their own hardcoded vector
# still drift together the moment someone updates both constants; two that each
# print what they actually produce cannot.
#
# WHY IT RUNS WITHOUT WINDOWS, which is the whole reason it is worth having:
# winn_frame_selftest.h is header-only and free of <windows.h> on purpose, and
# the Go fixture is standard-library only in its own module. Neither half needs
# a Windows machine, MSVC, administrator rights, or a network. The rest of the
# Windows Winn lane can only be verified on real hardware; this layer does not
# have to be, so it should not be.

set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_dir="${repo_root}/windows/winn_framing_fixture"
runner_dir="${repo_root}/windows/runner"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/wins-winn-framing.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

die() { echo "WNN3 FRAMING CONFORMANCE: FAIL -- $*" >&2; exit 1; }

command -v go >/dev/null 2>&1 || die "a Go toolchain is required for the fixture half"
cxx=""
for candidate in clang++ g++ c++; do
  if command -v "${candidate}" >/dev/null 2>&1; then cxx="${candidate}"; break; fi
done
[[ -n "${cxx}" ]] || die "a C++17 compiler is required for the winn_frame.h half"

# The C++ half. Generated rather than committed: it is a driver for the header,
# it has no reason to be maintained separately, and generating it means it can
# never drift from the vectors below.
cat >"${work_dir}/conformance.cc" <<'CC'
#include <cstdio>
#include <string>
#include <vector>

#include "winn_frame.h"
#include "winn_frame_selftest.h"

using winsvpn::winn::DecodeStatus;
using winsvpn::winn::EncodeFrame;
using winsvpn::winn::Frame;
using winsvpn::winn::FrameReader;
using winsvpn::winn::Opcode;
using winsvpn::winn::ReadLittleEndianU16;
using winsvpn::winn::ReadLittleEndianU32;
using winsvpn::winn::kFrameHeaderBytes;
using winsvpn::winn::kFrameMagic;
using winsvpn::winn::kFrameVersion;

static void print_hex(const std::vector<uint8_t>& bytes) {
  for (uint8_t b : bytes) std::printf("%02x", b);
}

int main() {
  // 1. The header's own self-test: golden encoding, round trip, rejections.
  std::string failure;
  if (!winsvpn::winn::RunWinnFrameSelfTest(&failure)) {
    std::fprintf(stderr, "winn_frame_selftest: %s\n", failure.c_str());
    return 1;
  }

  // 2. Decode the golden host->engine frame with the real reader.
  // accept_engine_to_host=false: kCreate is host-bound.
  const std::vector<uint8_t> golden = {
      0x57, 0x4E, 0x4E, 0x33, 0x01, 0x00, 0x01, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x69};
  FrameReader reader(/*accept_engine_to_host=*/false);
  reader.Append(golden.data(), golden.size());
  Frame decoded;
  if (reader.Next(&decoded) != DecodeStatus::kFrame) {
    std::fprintf(stderr, "golden decode: real FrameReader rejected the vector\n");
    return 1;
  }
  if (reader.buffered() != 0) {
    std::fprintf(stderr, "golden decode: reader retained trailing bytes\n");
    return 1;
  }

  // 3. The ten golden frames, each produced by the REAL C++ encoder in
  // winn_frame.h and printed raw. The shell's third-party diff compares them
  // byte-for-byte against what the Go carrier encoder emits with the same
  // opcode and payload, so a layout drift in either line fails the whole run.
  struct Case {
    const char* name;
    Opcode op;
    std::string payload;
  };
  const std::vector<Case> cases = {
      {"frame-01", Opcode::kCreateAck, "hi"},
      {"frame-02", Opcode::kOutbound,
       std::string("\x45\x00\x00\x28\xAB\xCD", 6)},
      {"frame-03", Opcode::kStatusResponse, "{\"up\":true}"},
      {"frame-04", Opcode::kCloseAck, ""},
      {"frame-05", Opcode::kError, "boom"},
      {"frame-06", Opcode::kOutbound,
       std::string("\x45\x00\x00\x28\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA"
                   "\xBB\xCC\xDD\xEE\xFF\x00", 20)},
      {"frame-07", Opcode::kCreateAck, "{\"handle\":1}"},
      {"frame-08", Opcode::kStatusResponse, "{}"},
      {"frame-09", Opcode::kError, "auth failed"},
      // The carrier: one full tunnel-sized IP payload, all 0x5A, so the length
      // field, header sizing and byte-identity are all stressed at once. This is
      // the vector the shell singles out for its magic/version/header checks.
      {"frame-10", Opcode::kOutbound, std::string(1420, '\x5a')},
  };
  for (const Case& c : cases) {
    std::vector<uint8_t> encoded;
    if (!EncodeFrame(c.op, c.payload, &encoded)) {
      std::fprintf(stderr, "encode %s: real EncodeFrame rejected it\n", c.name);
      return 1;
    }
    if (std::string(c.name) == "frame-10") {
      // Independent structural guard on the carrier, kept alongside the shell's
      // so two differently-shaped checks disagree on any drift.
      if (encoded.size() != kFrameHeaderBytes + 1420) {
        std::fprintf(stderr, "frame-10: header is not 16 bytes (total %zu)\n",
                     encoded.size());
        return 1;
      }
      const uint32_t magic = ReadLittleEndianU32(encoded.data());
      if (magic != kFrameMagic) {
        std::fprintf(stderr, "frame-10: magic mismatch 0x%08X\n",
                     static_cast<unsigned>(magic));
        return 1;
      }
      const uint16_t ver = ReadLittleEndianU16(encoded.data() + 4);
      if (ver != kFrameVersion) {
        std::fprintf(stderr, "frame-10: version != 1\n");
        return 1;
      }
      if (ReadLittleEndianU32(encoded.data() + 8) != 1420u) {
        std::fprintf(stderr, "frame-10: length field does not carry the payload\n");
        return 1;
      }
    }
    std::printf("vector: %s ", c.name);
    print_hex(encoded);
    std::printf("\n");
  }

  std::printf("impl: c++ (winn_frame.h, what the Windows host ships)\n");
  std::printf("checks: golden-decode golden-encode rejections\n");
  std::printf("WNN3 FRAMING CONFORMANCE: PASS\n");
  return 0;
}
CC

echo "Building the C++ half (${cxx})..."
"${cxx}" -std=c++17 -O0 -Wall -Wextra -Werror \
  -I "${runner_dir}" -o "${work_dir}/conformance_cc" "${work_dir}/conformance.cc" \
  || die "the C++ half did not compile"

"${work_dir}/conformance_cc" >"${work_dir}/cc.out" 2>"${work_dir}/cc.err" \
  || { cat "${work_dir}/cc.err" >&2; die "the C++ half failed its own checks"; }

echo "Running the Go half..."
( cd "${fixture_dir}" && GOFLAGS=-mod=readonly GOTOOLCHAIN=local \
    go run . -selftest ) >"${work_dir}/go.out" 2>"${work_dir}/go.err" \
  || { cat "${work_dir}/go.err" >&2; die "the Go half failed its own checks"; }

# Tenth golden vector: the carrier. The Go carrier encoder's raw output must be
# byte-identical to what winn_frame.h encoded, and the header must have the
# exact shape the wire contract fixes. These are checked independently of the
# sort/diff below, so a parallel header defect fails naming the broken field.
cc_carrier_hex="$(sed -n 's/^vector: frame-10 //p' "${work_dir}/cc.out")"
go_carrier_hex="$(sed -n 's/^vector: frame-10 //p' "${work_dir}/go.out")"
[[ -n "${cc_carrier_hex}" ]] || die "the C++ half emitted no carrier vector (frame-10)"
[[ -n "${go_carrier_hex}" ]] || die "the Go half emitted no carrier vector (frame-10)"

# Magic 0x334E4E57 written little-endian is the bytes 57 4e 4e 33.
[[ "${cc_carrier_hex:0:8}" == "574e4e33" ]] \
  || die "carrier magic missing: expected 0x334E4E57, got ${cc_carrier_hex:0:8}"
# Version 1 as a u16 little-endian is the bytes 01 00.
[[ "${cc_carrier_hex:8:4}" == "0100" ]] || die "carrier version != 1"
# The header is exactly 16 bytes: total frame length minus 16 must equal both
# the little-endian length field (bytes 8..11) and the carried payload bytes.
total_hex_bytes=$(( ${#cc_carrier_hex} / 2 ))
carrier_payload_len=$(( total_hex_bytes - 16 ))
len_low="0x${cc_carrier_hex:16:2}"
len_hi="0x${cc_carrier_hex:18:2}"
declared_len=$(( (len_low) | ((len_hi)<<8) ))
[[ "${carrier_payload_len}" -eq "${declared_len}" ]] \
  || die "carrier header is not 16 bytes (payload ${carrier_payload_len} != declared ${declared_len})"
[[ "${carrier_payload_len}" -gt 0 ]] || die "carrier frame carries no payload"
# Byte-identical payload between the two implementations.
[[ "${cc_carrier_hex:32}" == "${go_carrier_hex:32}" ]] \
  || die "carrier payload differs between c++ and go"

sed -n 's/^vector: //p' "${work_dir}/cc.out" | sort >"${work_dir}/cc.vectors"
sed -n 's/^vector: //p' "${work_dir}/go.out" | sort >"${work_dir}/go.vectors"

[[ -s "${work_dir}/cc.vectors" ]] || die "the C++ half emitted no vectors"
[[ -s "${work_dir}/go.vectors" ]] || die "the Go half emitted no vectors"

if ! diff -u "${work_dir}/cc.vectors" "${work_dir}/go.vectors" >"${work_dir}/diff"; then
  echo "The two implementations disagree about the WNN3 wire layout:" >&2
  cat "${work_dir}/diff" >&2
  die "vectors differ"
fi

echo
sed 's/^/  cc  | /' "${work_dir}/cc.out"
sed 's/^/  go  | /' "${work_dir}/go.out"
echo
echo "Both implementations agree on $(wc -l <"${work_dir}/cc.vectors" | tr -d ' ') vector(s), all byte-identical."
echo "WNN3 FRAMING CONFORMANCE: PASS (10/10; c++ winn_frame.h == go carrier encoder)"
