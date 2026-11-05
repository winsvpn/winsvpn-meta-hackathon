#include "WinnAWGUAPISanitizer.h"

#include <limits.h>
#include <stdbool.h>
#include <string.h>

_Static_assert(
    sizeof(WinnAWGUAPISnapshot) == 64U,
    "WinnAWGUAPISnapshot ABI size changed");
_Static_assert(
    offsetof(WinnAWGUAPISnapshot, latest_handshake_unix_seconds) == 32U,
    "WinnAWGUAPISnapshot seconds offset changed");
_Static_assert(
    offsetof(WinnAWGUAPISnapshot, latest_handshake_nanoseconds) == 40U,
    "WinnAWGUAPISnapshot nanoseconds offset changed");
_Static_assert(
    offsetof(WinnAWGUAPISnapshot, received_bytes) == 48U,
    "WinnAWGUAPISnapshot receive counter offset changed");
_Static_assert(
    offsetof(WinnAWGUAPISnapshot, transmitted_bytes) == 56U,
    "WinnAWGUAPISnapshot transmit counter offset changed");

typedef struct WinnSlice {
  const uint8_t *bytes;
  size_t count;
} WinnSlice;

enum WinnInterfaceField {
  WINN_INTERFACE_PRIVATE_KEY = 1U << 0,
  WINN_INTERFACE_LISTEN_PORT = 1U << 1,
  WINN_INTERFACE_FWMARK = 1U << 2,
  WINN_INTERFACE_JC = 1U << 3,
  WINN_INTERFACE_JMIN = 1U << 4,
  WINN_INTERFACE_JMAX = 1U << 5,
  WINN_INTERFACE_S1 = 1U << 6,
  WINN_INTERFACE_S2 = 1U << 7,
  WINN_INTERFACE_S3 = 1U << 8,
  WINN_INTERFACE_S4 = 1U << 9,
  WINN_INTERFACE_H1 = 1U << 10,
  WINN_INTERFACE_H2 = 1U << 11,
  WINN_INTERFACE_H3 = 1U << 12,
  WINN_INTERFACE_H4 = 1U << 13,
  WINN_INTERFACE_I1 = 1U << 14,
  WINN_INTERFACE_I2 = 1U << 15,
  WINN_INTERFACE_I3 = 1U << 16,
  WINN_INTERFACE_I4 = 1U << 17,
  WINN_INTERFACE_I5 = 1U << 18
};

enum WinnPeerField {
  WINN_PEER_PUBLIC_KEY = 1U << 0,
  WINN_PEER_PRESHARED_KEY = 1U << 1,
  WINN_PEER_PROTOCOL_VERSION = 1U << 2,
  WINN_PEER_ENDPOINT = 1U << 3,
  WINN_PEER_HANDSHAKE_SECONDS = 1U << 4,
  WINN_PEER_HANDSHAKE_NANOSECONDS = 1U << 5,
  WINN_PEER_TRANSMITTED_BYTES = 1U << 6,
  WINN_PEER_RECEIVED_BYTES = 1U << 7,
  WINN_PEER_KEEPALIVE = 1U << 8
};

static bool winn_slice_equals_literal(
    WinnSlice slice,
    const char *literal,
    size_t literal_length) {
  return slice.count == literal_length &&
         memcmp(slice.bytes, literal, literal_length) == 0;
}

#define WINN_SLICE_EQUALS(slice, literal) \
  winn_slice_equals_literal((slice), (literal), sizeof(literal) - 1U)

static bool winn_slice_equals(WinnSlice first, WinnSlice second) {
  return first.count == second.count &&
         memcmp(first.bytes, second.bytes, first.count) == 0;
}

static bool winn_parse_decimal(
    WinnSlice value,
    uint64_t maximum,
    uint64_t *parsed) {
  uint64_t result = 0;
  size_t index;

  if (value.count == 0U ||
      (value.count > 1U && value.bytes[0] == (uint8_t)'0')) {
    return false;
  }
  for (index = 0; index < value.count; ++index) {
    uint8_t byte = value.bytes[index];
    uint64_t digit;
    if (byte < (uint8_t)'0' || byte > (uint8_t)'9') {
      return false;
    }
    digit = (uint64_t)(byte - (uint8_t)'0');
    if (result > (maximum - digit) / 10U) {
      return false;
    }
    result = result * 10U + digit;
  }
  if (parsed != NULL) {
    *parsed = result;
  }
  return true;
}

static uint8_t winn_hex_nibble(uint8_t byte, bool *valid) {
  if (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') {
    return (uint8_t)(byte - (uint8_t)'0');
  }
  if (byte >= (uint8_t)'a' && byte <= (uint8_t)'f') {
    return (uint8_t)(byte - (uint8_t)'a' + 10U);
  }
  *valid = false;
  return 0;
}

static bool winn_parse_hex32(WinnSlice value, uint8_t *decoded) {
  size_t index;
  bool valid = true;
  if (value.count != 64U) {
    return false;
  }
  for (index = 0; index < 32U; ++index) {
    uint8_t high = winn_hex_nibble(value.bytes[index * 2U], &valid);
    uint8_t low = winn_hex_nibble(value.bytes[index * 2U + 1U], &valid);
    if (!valid) {
      return false;
    }
    if (decoded != NULL) {
      decoded[index] = (uint8_t)((high << 4U) | low);
    }
  }
  return true;
}

static bool winn_hex32_is_nonzero(WinnSlice value) {
  size_t index;
  for (index = 0U; index < value.count; ++index) {
    if (value.bytes[index] != (uint8_t)'0') {
      return true;
    }
  }
  return false;
}

static bool winn_validate_header_spec(WinnSlice value) {
  size_t index;
  size_t separator = SIZE_MAX;
  uint64_t start;
  uint64_t end;

  for (index = 0; index < value.count; ++index) {
    if (value.bytes[index] == (uint8_t)'-') {
      if (separator != SIZE_MAX) {
        return false;
      }
      separator = index;
    }
  }
  if (separator == SIZE_MAX) {
    return winn_parse_decimal(value, UINT32_MAX, NULL);
  }
  if (!winn_parse_decimal(
          (WinnSlice){value.bytes, separator}, UINT32_MAX, &start) ||
      !winn_parse_decimal(
          (WinnSlice){
              value.bytes + separator + 1U,
              value.count - separator - 1U},
          UINT32_MAX,
          &end)) {
    return false;
  }
  return end >= start;
}

static bool winn_validate_ipv4(WinnSlice address) {
  size_t index = 0;
  unsigned component_count = 0;

  while (index < address.count) {
    size_t start = index;
    uint64_t component;
    while (index < address.count &&
           address.bytes[index] != (uint8_t)'.') {
      ++index;
    }
    if (!winn_parse_decimal(
            (WinnSlice){address.bytes + start, index - start},
            255U,
            &component)) {
      return false;
    }
    (void)component;
    ++component_count;
    if (index == address.count) {
      break;
    }
    ++index;
    if (index == address.count) {
      return false;
    }
  }
  return component_count == 4U;
}

static bool winn_is_lower_hex(uint8_t byte) {
  return (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
         (byte >= (uint8_t)'a' && byte <= (uint8_t)'f');
}

static bool winn_validate_ipv6(WinnSlice address) {
  size_t index = 0;
  unsigned units = 0;
  bool compressed = false;

  if (address.count == 0U) {
    return false;
  }
  if (address.bytes[0] == (uint8_t)':') {
    if (address.count < 2U || address.bytes[1] != (uint8_t)':') {
      return false;
    }
    compressed = true;
    index = 2U;
    if (index == address.count) {
      return true;
    }
  }

  while (index < address.count) {
    size_t start = index;
    bool has_dot = false;

    while (index < address.count &&
           address.bytes[index] != (uint8_t)':') {
      has_dot = has_dot || address.bytes[index] == (uint8_t)'.';
      ++index;
    }
    if (start == index) {
      return false;
    }
    if (has_dot) {
      if (index != address.count ||
          !winn_validate_ipv4(
              (WinnSlice){address.bytes + start, index - start})) {
        return false;
      }
      units += 2U;
      break;
    }
    if (index - start > 4U) {
      return false;
    }
    {
      size_t digit;
      for (digit = start; digit < index; ++digit) {
        if (!winn_is_lower_hex(address.bytes[digit])) {
          return false;
        }
      }
    }
    ++units;
    if (units > 8U || index == address.count) {
      break;
    }

    if (index + 1U < address.count &&
        address.bytes[index + 1U] == (uint8_t)':') {
      if (compressed) {
        return false;
      }
      compressed = true;
      index += 2U;
      if (index == address.count) {
        break;
      }
    } else {
      ++index;
      if (index == address.count) {
        return false;
      }
    }
  }

  return compressed ? units < 8U : units == 8U;
}

static bool winn_validate_endpoint(WinnSlice value) {
  size_t index;
  WinnSlice address;
  WinnSlice port;
  uint64_t parsed_port;

  if (value.count == 0U) {
    return false;
  }
  if (value.bytes[0] == (uint8_t)'[') {
    size_t closing = SIZE_MAX;
    for (index = 1U; index < value.count; ++index) {
      if (value.bytes[index] == (uint8_t)']') {
        closing = index;
        break;
      }
    }
    if (closing == SIZE_MAX || closing + 2U > value.count ||
        value.bytes[closing + 1U] != (uint8_t)':') {
      return false;
    }
    address = (WinnSlice){value.bytes + 1U, closing - 1U};
    port = (WinnSlice){
        value.bytes + closing + 2U,
        value.count - closing - 2U};
    if (!winn_validate_ipv6(address)) {
      return false;
    }
  } else {
    size_t separator = SIZE_MAX;
    for (index = 0U; index < value.count; ++index) {
      if (value.bytes[index] == (uint8_t)':') {
        if (separator != SIZE_MAX) {
          return false;
        }
        separator = index;
      }
    }
    if (separator == SIZE_MAX) {
      return false;
    }
    address = (WinnSlice){value.bytes, separator};
    port = (WinnSlice){
        value.bytes + separator + 1U,
        value.count - separator - 1U};
    if (!winn_validate_ipv4(address)) {
      return false;
    }
  }
  return winn_parse_decimal(port, UINT16_MAX, &parsed_port) &&
         parsed_port != 0U;
}

static bool winn_validate_allowed_ip(WinnSlice value) {
  size_t index;
  size_t separator = SIZE_MAX;
  WinnSlice address;
  WinnSlice prefix;
  uint64_t maximum;

  for (index = 0U; index < value.count; ++index) {
    if (value.bytes[index] == (uint8_t)'/') {
      if (separator != SIZE_MAX) {
        return false;
      }
      separator = index;
    }
  }
  if (separator == SIZE_MAX) {
    return false;
  }
  address = (WinnSlice){value.bytes, separator};
  prefix = (WinnSlice){
      value.bytes + separator + 1U,
      value.count - separator - 1U};
  if (winn_validate_ipv4(address)) {
    maximum = 32U;
  } else if (winn_validate_ipv6(address)) {
    maximum = 128U;
  } else {
    return false;
  }
  return winn_parse_decimal(prefix, maximum, NULL);
}

static uint32_t winn_interface_field_bit(WinnSlice key) {
  if (WINN_SLICE_EQUALS(key, "private_key")) {
    return WINN_INTERFACE_PRIVATE_KEY;
  }
  if (WINN_SLICE_EQUALS(key, "listen_port")) {
    return WINN_INTERFACE_LISTEN_PORT;
  }
  if (WINN_SLICE_EQUALS(key, "fwmark")) {
    return WINN_INTERFACE_FWMARK;
  }
  if (WINN_SLICE_EQUALS(key, "jc")) {
    return WINN_INTERFACE_JC;
  }
  if (WINN_SLICE_EQUALS(key, "jmin")) {
    return WINN_INTERFACE_JMIN;
  }
  if (WINN_SLICE_EQUALS(key, "jmax")) {
    return WINN_INTERFACE_JMAX;
  }
  if (WINN_SLICE_EQUALS(key, "s1")) {
    return WINN_INTERFACE_S1;
  }
  if (WINN_SLICE_EQUALS(key, "s2")) {
    return WINN_INTERFACE_S2;
  }
  if (WINN_SLICE_EQUALS(key, "s3")) {
    return WINN_INTERFACE_S3;
  }
  if (WINN_SLICE_EQUALS(key, "s4")) {
    return WINN_INTERFACE_S4;
  }
  if (WINN_SLICE_EQUALS(key, "h1")) {
    return WINN_INTERFACE_H1;
  }
  if (WINN_SLICE_EQUALS(key, "h2")) {
    return WINN_INTERFACE_H2;
  }
  if (WINN_SLICE_EQUALS(key, "h3")) {
    return WINN_INTERFACE_H3;
  }
  if (WINN_SLICE_EQUALS(key, "h4")) {
    return WINN_INTERFACE_H4;
  }
  if (WINN_SLICE_EQUALS(key, "i1")) {
    return WINN_INTERFACE_I1;
  }
  if (WINN_SLICE_EQUALS(key, "i2")) {
    return WINN_INTERFACE_I2;
  }
  if (WINN_SLICE_EQUALS(key, "i3")) {
    return WINN_INTERFACE_I3;
  }
  if (WINN_SLICE_EQUALS(key, "i4")) {
    return WINN_INTERFACE_I4;
  }
  if (WINN_SLICE_EQUALS(key, "i5")) {
    return WINN_INTERFACE_I5;
  }
  return 0U;
}

static WinnAWGUAPIStatus winn_consume_interface_field(
    WinnSlice key,
    WinnSlice value,
    uint32_t *seen) {
  uint32_t bit = winn_interface_field_bit(key);
  uint64_t maximum;

  if (bit == 0U) {
    return WINN_AWG_UAPI_UNKNOWN_FIELD;
  }
  if ((*seen & bit) != 0U) {
    return WINN_AWG_UAPI_DUPLICATE_FIELD;
  }
  *seen |= bit;

  if (bit == WINN_INTERFACE_PRIVATE_KEY) {
    return winn_parse_hex32(value, NULL) &&
                   winn_hex32_is_nonzero(value)
               ? WINN_AWG_UAPI_OK
               : WINN_AWG_UAPI_INVALID_HEX;
  }
  if (bit == WINN_INTERFACE_LISTEN_PORT) {
    maximum = UINT16_MAX;
  } else if (bit == WINN_INTERFACE_FWMARK ||
             bit == WINN_INTERFACE_JC ||
             bit == WINN_INTERFACE_JMIN ||
             bit == WINN_INTERFACE_JMAX ||
             bit == WINN_INTERFACE_S1 ||
             bit == WINN_INTERFACE_S2 ||
             bit == WINN_INTERFACE_S3 ||
             bit == WINN_INTERFACE_S4) {
    maximum = UINT32_MAX;
  } else if (bit == WINN_INTERFACE_H1 ||
             bit == WINN_INTERFACE_H2 ||
             bit == WINN_INTERFACE_H3 ||
             bit == WINN_INTERFACE_H4) {
    return winn_validate_header_spec(value) ? WINN_AWG_UAPI_OK
                                             : WINN_AWG_UAPI_INVALID_DECIMAL;
  } else {
    /* The preflight admits only printable ASCII, and empty values fail first. */
    return WINN_AWG_UAPI_OK;
  }
  {
    uint64_t parsed;
    return winn_parse_decimal(value, maximum, &parsed) && parsed != 0U
               ? WINN_AWG_UAPI_OK
               : WINN_AWG_UAPI_INVALID_DECIMAL;
  }
}

static WinnAWGUAPIStatus winn_preflight(
    const uint8_t *input,
    size_t input_length) {
  size_t line_start = 0U;
  size_t line_count = 0U;
  size_t index;

  if (input_length == 0U) {
    return WINN_AWG_UAPI_EMPTY_INPUT;
  }
  if (input_length > WINN_AWG_UAPI_MAX_INPUT_BYTES) {
    return WINN_AWG_UAPI_INPUT_TOO_LARGE;
  }
  if (input[input_length - 1U] != (uint8_t)'\n') {
    return WINN_AWG_UAPI_INVALID_TERMINATION;
  }

  for (index = 0U; index < input_length; ++index) {
    uint8_t byte = input[index];
    if (byte == 0U || byte == (uint8_t)'\r' ||
        (byte != (uint8_t)'\n' &&
         (byte < (uint8_t)' ' || byte > (uint8_t)'~'))) {
      return WINN_AWG_UAPI_INVALID_TERMINATION;
    }
    if (byte == (uint8_t)'\n') {
      size_t line_length = index - line_start;
      ++line_count;
      if (line_count > WINN_AWG_UAPI_MAX_LINES) {
        return WINN_AWG_UAPI_TOO_MANY_LINES;
      }
      if (line_length == 0U) {
        return WINN_AWG_UAPI_MALFORMED_LINE;
      }
      if (line_length > WINN_AWG_UAPI_MAX_LINE_BYTES) {
        return WINN_AWG_UAPI_LINE_TOO_LONG;
      }
      line_start = index + 1U;
    }
  }
  return WINN_AWG_UAPI_OK;
}

WinnAWGUAPIStatus winn_awg_uapi_sanitize(
    const uint8_t *input,
    size_t input_length,
    const uint8_t expected_peer_public_key[32],
    WinnAWGUAPISnapshot *output) {
  static const uint32_t required_peer_fields =
      WINN_PEER_PUBLIC_KEY |
      WINN_PEER_PRESHARED_KEY |
      WINN_PEER_PROTOCOL_VERSION |
      WINN_PEER_HANDSHAKE_SECONDS |
      WINN_PEER_HANDSHAKE_NANOSECONDS |
      WINN_PEER_TRANSMITTED_BYTES |
      WINN_PEER_RECEIVED_BYTES |
      WINN_PEER_KEEPALIVE;
  WinnAWGUAPISnapshot candidate;
  WinnSlice allowed_ips[WINN_AWG_UAPI_MAX_ALLOWED_IPS];
  size_t allowed_ip_count = 0U;
  uint32_t interface_seen = 0U;
  uint32_t peer_seen = 0U;
  unsigned peer_count = 0U;
  size_t line_start = 0U;
  size_t index;
  WinnAWGUAPIStatus status;

  if (output != NULL) {
    memset(output, 0, sizeof(*output));
  }
  if (input == NULL || expected_peer_public_key == NULL || output == NULL) {
    return WINN_AWG_UAPI_INVALID_ARGUMENT;
  }
  memset(&candidate, 0, sizeof(candidate));

  status = winn_preflight(input, input_length);
  if (status != WINN_AWG_UAPI_OK) {
    return status;
  }

  for (index = 0U; index < input_length; ++index) {
    size_t separator;
    WinnSlice key;
    WinnSlice value;
    uint32_t bit = 0U;

    if (input[index] != (uint8_t)'\n') {
      continue;
    }
    separator = line_start;
    while (separator < index && input[separator] != (uint8_t)'=') {
      ++separator;
    }
    if (separator == line_start || separator == index ||
        separator + 1U == index) {
      return WINN_AWG_UAPI_MALFORMED_LINE;
    }
    key = (WinnSlice){input + line_start, separator - line_start};
    value = (WinnSlice){input + separator + 1U, index - separator - 1U};
    line_start = index + 1U;

    if (WINN_SLICE_EQUALS(key, "public_key")) {
      ++peer_count;
      if (peer_count > 1U) {
        return WINN_AWG_UAPI_MULTIPLE_PEERS;
      }
      bit = WINN_PEER_PUBLIC_KEY;
      if (!winn_parse_hex32(value, candidate.peer_public_key)) {
        return WINN_AWG_UAPI_INVALID_HEX;
      }
    } else if (peer_count == 0U) {
      status = winn_consume_interface_field(
          key, value, &interface_seen);
      if (status != WINN_AWG_UAPI_OK) {
        return status;
      }
      continue;
    } else if (WINN_SLICE_EQUALS(key, "preshared_key")) {
      bit = WINN_PEER_PRESHARED_KEY;
      if (!winn_parse_hex32(value, NULL)) {
        return WINN_AWG_UAPI_INVALID_HEX;
      }
    } else if (WINN_SLICE_EQUALS(key, "protocol_version")) {
      bit = WINN_PEER_PROTOCOL_VERSION;
      if (!WINN_SLICE_EQUALS(value, "1")) {
        return WINN_AWG_UAPI_INVALID_PROTOCOL_VERSION;
      }
    } else if (WINN_SLICE_EQUALS(key, "endpoint")) {
      bit = WINN_PEER_ENDPOINT;
      if (!winn_validate_endpoint(value)) {
        return WINN_AWG_UAPI_MALFORMED_LINE;
      }
    } else if (WINN_SLICE_EQUALS(key, "last_handshake_time_sec")) {
      bit = WINN_PEER_HANDSHAKE_SECONDS;
      if (!winn_parse_decimal(
              value,
              UINT64_MAX,
              &candidate.latest_handshake_unix_seconds)) {
        return WINN_AWG_UAPI_INVALID_DECIMAL;
      }
    } else if (WINN_SLICE_EQUALS(key, "last_handshake_time_nsec")) {
      uint64_t nanoseconds;
      bit = WINN_PEER_HANDSHAKE_NANOSECONDS;
      if (!winn_parse_decimal(value, 999999999U, &nanoseconds)) {
        return WINN_AWG_UAPI_INVALID_HANDSHAKE_NANOSECONDS;
      }
      candidate.latest_handshake_nanoseconds = (uint32_t)nanoseconds;
    } else if (WINN_SLICE_EQUALS(key, "tx_bytes")) {
      bit = WINN_PEER_TRANSMITTED_BYTES;
      if (!winn_parse_decimal(
              value, UINT64_MAX, &candidate.transmitted_bytes)) {
        return WINN_AWG_UAPI_INVALID_DECIMAL;
      }
    } else if (WINN_SLICE_EQUALS(key, "rx_bytes")) {
      bit = WINN_PEER_RECEIVED_BYTES;
      if (!winn_parse_decimal(
              value, UINT64_MAX, &candidate.received_bytes)) {
        return WINN_AWG_UAPI_INVALID_DECIMAL;
      }
    } else if (WINN_SLICE_EQUALS(key, "persistent_keepalive_interval")) {
      bit = WINN_PEER_KEEPALIVE;
      if (!winn_parse_decimal(value, UINT16_MAX, NULL)) {
        return WINN_AWG_UAPI_INVALID_DECIMAL;
      }
    } else if (WINN_SLICE_EQUALS(key, "allowed_ip")) {
      size_t allowed_index;
      if (allowed_ip_count >= WINN_AWG_UAPI_MAX_ALLOWED_IPS) {
        return WINN_AWG_UAPI_TOO_MANY_LINES;
      }
      if (!winn_validate_allowed_ip(value)) {
        return WINN_AWG_UAPI_MALFORMED_LINE;
      }
      for (allowed_index = 0U;
           allowed_index < allowed_ip_count;
           ++allowed_index) {
        if (winn_slice_equals(allowed_ips[allowed_index], value)) {
          return WINN_AWG_UAPI_DUPLICATE_FIELD;
        }
      }
      allowed_ips[allowed_ip_count++] = value;
      continue;
    } else {
      return WINN_AWG_UAPI_UNKNOWN_FIELD;
    }

    if ((peer_seen & bit) != 0U) {
      return WINN_AWG_UAPI_DUPLICATE_FIELD;
    }
    peer_seen |= bit;
  }

  if (peer_count == 0U) {
    return WINN_AWG_UAPI_ZERO_PEERS;
  }
  if ((interface_seen & WINN_INTERFACE_PRIVATE_KEY) == 0U) {
    return WINN_AWG_UAPI_MISSING_FIELD;
  }
  if ((peer_seen & required_peer_fields) != required_peer_fields) {
    return WINN_AWG_UAPI_MISSING_FIELD;
  }
  if (candidate.latest_handshake_unix_seconds == 0U &&
      candidate.latest_handshake_nanoseconds != 0U) {
    return WINN_AWG_UAPI_INVALID_HANDSHAKE_NANOSECONDS;
  }
  {
    uint8_t difference = 0U;
    for (index = 0U; index < 32U; ++index) {
      difference |= (uint8_t)(
          candidate.peer_public_key[index] ^
          expected_peer_public_key[index]);
    }
    if (difference != 0U) {
      return WINN_AWG_UAPI_WRONG_PEER;
    }
  }

  *output = candidate;
  return WINN_AWG_UAPI_OK;
}
