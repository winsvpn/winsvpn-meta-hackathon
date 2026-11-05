#ifndef WINN_AWG_UAPI_SANITIZER_H
#define WINN_AWG_UAPI_SANITIZER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  WINN_AWG_UAPI_MAX_INPUT_BYTES = 32 * 1024,
  WINN_AWG_UAPI_MAX_LINES = 128,
  WINN_AWG_UAPI_MAX_LINE_BYTES = 512,
  WINN_AWG_UAPI_MAX_ALLOWED_IPS = 16
};

typedef enum WinnAWGUAPIStatus {
  WINN_AWG_UAPI_OK = 0,
  WINN_AWG_UAPI_INVALID_ARGUMENT,
  WINN_AWG_UAPI_EMPTY_INPUT,
  WINN_AWG_UAPI_INPUT_TOO_LARGE,
  WINN_AWG_UAPI_INVALID_TERMINATION,
  WINN_AWG_UAPI_TOO_MANY_LINES,
  WINN_AWG_UAPI_LINE_TOO_LONG,
  WINN_AWG_UAPI_MALFORMED_LINE,
  WINN_AWG_UAPI_UNKNOWN_FIELD,
  WINN_AWG_UAPI_DUPLICATE_FIELD,
  WINN_AWG_UAPI_MISSING_FIELD,
  WINN_AWG_UAPI_INVALID_HEX,
  WINN_AWG_UAPI_INVALID_DECIMAL,
  WINN_AWG_UAPI_INVALID_PROTOCOL_VERSION,
  WINN_AWG_UAPI_INVALID_HANDSHAKE_NANOSECONDS,
  WINN_AWG_UAPI_ZERO_PEERS,
  WINN_AWG_UAPI_MULTIPLE_PEERS,
  WINN_AWG_UAPI_WRONG_PEER
} WinnAWGUAPIStatus;

/*
 * Fixed, secret-free result from the pinned amneziawg-go v0.2.18 IpcGet
 * payload. The explicit reserved bytes make every byte deterministic.
 */
typedef struct WinnAWGUAPISnapshot {
  uint8_t peer_public_key[32];
  uint64_t latest_handshake_unix_seconds;
  uint32_t latest_handshake_nanoseconds;
  uint8_t reserved[4];
  uint64_t received_bytes;
  uint64_t transmitted_bytes;
} WinnAWGUAPISnapshot;

/*
 * Parses exactly input_length bytes. input is not required to be NUL
 * terminated, this function does not own it, and this function never frees it.
 * On every failure for which output is non-NULL, all output bytes are zero. No
 * input slice or secret field is retained or returned.
 *
 * Required future wgGetConfig integration boundary:
 *   1. Bound the returned C string with strnlen(raw,
 *      WINN_AWG_UAPI_MAX_INPUT_BYTES + 1), rejecting a result greater than
 *      WINN_AWG_UAPI_MAX_INPUT_BYTES before calling this API.
 *   2. Pass the measured length without the terminating NUL.
 *   3. After this call, securely zero the complete owned raw allocation and
 *      release it exactly once on every success and failure path.
 * The adapter must not log, bridge, or otherwise copy the raw C string.
 */
WinnAWGUAPIStatus winn_awg_uapi_sanitize(
    const uint8_t *input,
    size_t input_length,
    const uint8_t expected_peer_public_key[32],
    WinnAWGUAPISnapshot *output);

#ifdef __cplusplus
}
#endif

#endif
