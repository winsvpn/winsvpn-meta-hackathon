#include "../NativeEngine/WinnAWGUAPISanitizer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression)                                                   \
  do {                                                                      \
    if (!(expression)) {                                                    \
      fprintf(stderr, "check failed at line %d\n", __LINE__);               \
      return 1;                                                             \
    }                                                                       \
  } while (0)

static const char golden[] =
    "private_key=4444444444444444444444444444444444444444444444444444444444444444\n"
    "listen_port=51820\n"
    "fwmark=7\n"
    "jc=4\n"
    "jmin=40\n"
    "jmax=70\n"
    "s1=90\n"
    "s2=91\n"
    "s3=92\n"
    "s4=93\n"
    "h1=1\n"
    "h2=4-6\n"
    "h3=7\n"
    "h4=10-12\n"
    "i1=<b 0a0b><d>\n"
    "public_key=2222222222222222222222222222222222222222222222222222222222222222\n"
    "preshared_key=5555555555555555555555555555555555555555555555555555555555555555\n"
    "protocol_version=1\n"
    "endpoint=192.0.2.10:51820\n"
    "last_handshake_time_sec=1900000000\n"
    "last_handshake_time_nsec=123456789\n"
    "tx_bytes=356\n"
    "rx_bytes=712\n"
    "persistent_keepalive_interval=25\n"
    "allowed_ip=0.0.0.0/0\n"
    "allowed_ip=::/0\n";

static const uint8_t expected_peer[32] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};

static int bytes_are_zero(const void *bytes, size_t count) {
  const uint8_t *cursor = bytes;
  size_t index;
  for (index = 0; index < count; ++index) {
    if (cursor[index] != 0U) {
      return 0;
    }
  }
  return 1;
}

static int contains_run(
    const uint8_t *bytes,
    size_t count,
    uint8_t byte,
    size_t run_length) {
  size_t start;
  if (run_length > count) {
    return 0;
  }
  for (start = 0; start <= count - run_length; ++start) {
    size_t index;
    for (index = 0; index < run_length; ++index) {
      if (bytes[start + index] != byte) {
        break;
      }
    }
    if (index == run_length) {
      return 1;
    }
  }
  return 0;
}

static WinnAWGUAPIStatus sanitize(
    const void *input,
    size_t count,
    const uint8_t peer[32],
    WinnAWGUAPISnapshot *snapshot) {
  memset(snapshot, 0xa5, sizeof(*snapshot));
  return winn_awg_uapi_sanitize(input, count, peer, snapshot);
}

static int expect_rejection(
    const void *input,
    size_t count,
    WinnAWGUAPIStatus expected_status) {
  WinnAWGUAPISnapshot snapshot;
  WinnAWGUAPIStatus status =
      sanitize(input, count, expected_peer, &snapshot);
  CHECK(status == expected_status);
  CHECK(bytes_are_zero(&snapshot, sizeof(snapshot)));
  return 0;
}

static char *replace_once(
    const char *source,
    const char *needle,
    const char *replacement,
    size_t *result_length) {
  const char *position = strstr(source, needle);
  size_t source_length = strlen(source);
  size_t needle_length = strlen(needle);
  size_t replacement_length = strlen(replacement);
  char *result;

  if (position == NULL) {
    return NULL;
  }
  *result_length =
      source_length - needle_length + replacement_length;
  result = malloc(*result_length + 1U);
  if (result == NULL) {
    return NULL;
  }
  {
    size_t prefix = (size_t)(position - source);
    memcpy(result, source, prefix);
    memcpy(result + prefix, replacement, replacement_length);
    memcpy(
        result + prefix + replacement_length,
        position + needle_length,
        source_length - prefix - needle_length + 1U);
  }
  return result;
}

static int test_success_and_secret_nonappearance(void) {
  WinnAWGUAPISnapshot snapshot;
  WinnAWGUAPIStatus status =
      sanitize(golden, sizeof(golden) - 1U, expected_peer, &snapshot);
  CHECK(status == WINN_AWG_UAPI_OK);
  CHECK(memcmp(snapshot.peer_public_key, expected_peer, 32U) == 0);
  CHECK(snapshot.latest_handshake_unix_seconds == UINT64_C(1900000000));
  CHECK(snapshot.latest_handshake_nanoseconds == UINT32_C(123456789));
  CHECK(snapshot.received_bytes == UINT64_C(712));
  CHECK(snapshot.transmitted_bytes == UINT64_C(356));
  CHECK(bytes_are_zero(snapshot.reserved, sizeof(snapshot.reserved)));
  CHECK(!contains_run(
      (const uint8_t *)&snapshot, sizeof(snapshot), 0x44U, 32U));
  CHECK(!contains_run(
      (const uint8_t *)&snapshot, sizeof(snapshot), 0x55U, 32U));
  CHECK(sizeof(snapshot) == 64U);
  return 0;
}

static int test_arguments_and_bounds(void) {
  WinnAWGUAPISnapshot snapshot;
  uint8_t *oversized;
  char *lines;
  size_t cursor = 0U;
  unsigned index;

  CHECK(
      winn_awg_uapi_sanitize(
          NULL, 1U, expected_peer, &snapshot) ==
      WINN_AWG_UAPI_INVALID_ARGUMENT);
  CHECK(bytes_are_zero(&snapshot, sizeof(snapshot)));
  CHECK(
      winn_awg_uapi_sanitize(
          (const uint8_t *)golden,
          sizeof(golden) - 1U,
          NULL,
          &snapshot) == WINN_AWG_UAPI_INVALID_ARGUMENT);
  CHECK(bytes_are_zero(&snapshot, sizeof(snapshot)));
  CHECK(
      winn_awg_uapi_sanitize(
          (const uint8_t *)golden,
          sizeof(golden) - 1U,
          expected_peer,
          NULL) == WINN_AWG_UAPI_INVALID_ARGUMENT);
  CHECK(expect_rejection("", 0U, WINN_AWG_UAPI_EMPTY_INPUT) == 0);

  oversized = malloc(WINN_AWG_UAPI_MAX_INPUT_BYTES + 1U);
  CHECK(oversized != NULL);
  memset(oversized, 'a', WINN_AWG_UAPI_MAX_INPUT_BYTES + 1U);
  oversized[WINN_AWG_UAPI_MAX_INPUT_BYTES] = '\n';
  CHECK(expect_rejection(
      oversized,
      WINN_AWG_UAPI_MAX_INPUT_BYTES + 1U,
      WINN_AWG_UAPI_INPUT_TOO_LARGE) == 0);
  free(oversized);

  lines = malloc((WINN_AWG_UAPI_MAX_LINES + 1U) * 4U + 1U);
  CHECK(lines != NULL);
  for (index = 0U; index < WINN_AWG_UAPI_MAX_LINES + 1U; ++index) {
    memcpy(lines + cursor, "x=1\n", 4U);
    cursor += 4U;
  }
  CHECK(expect_rejection(
      lines, cursor, WINN_AWG_UAPI_TOO_MANY_LINES) == 0);
  free(lines);

  lines = malloc(WINN_AWG_UAPI_MAX_INPUT_BYTES);
  CHECK(lines != NULL);
  for (index = 0U; index < 64U; ++index) {
    size_t start = (size_t)index * 512U;
    memcpy(lines + start, "x=", 2U);
    memset(lines + start + 2U, 'a', 509U);
    lines[start + 511U] = '\n';
  }
  CHECK(expect_rejection(
      lines,
      WINN_AWG_UAPI_MAX_INPUT_BYTES,
      WINN_AWG_UAPI_UNKNOWN_FIELD) == 0);
  free(lines);

  lines = malloc(WINN_AWG_UAPI_MAX_LINES * 4U);
  CHECK(lines != NULL);
  for (index = 0U; index < WINN_AWG_UAPI_MAX_LINES; ++index) {
    memcpy(lines + (size_t)index * 4U, "x=1\n", 4U);
  }
  CHECK(expect_rejection(
      lines,
      WINN_AWG_UAPI_MAX_LINES * 4U,
      WINN_AWG_UAPI_UNKNOWN_FIELD) == 0);
  free(lines);
  return 0;
}

static int test_termination_and_line_limits(void) {
  char *buffer;
  size_t golden_length = sizeof(golden) - 1U;
  size_t prefix_length;

  CHECK(expect_rejection(
      golden,
      golden_length - 1U,
      WINN_AWG_UAPI_INVALID_TERMINATION) == 0);

  buffer = malloc(golden_length + 2U);
  CHECK(buffer != NULL);
  memcpy(buffer, golden, golden_length);
  buffer[golden_length] = '\n';
  CHECK(expect_rejection(
      buffer, golden_length + 1U, WINN_AWG_UAPI_MALFORMED_LINE) == 0);
  buffer[0] = '\0';
  CHECK(expect_rejection(
      buffer,
      golden_length,
      WINN_AWG_UAPI_INVALID_TERMINATION) == 0);
  memcpy(buffer, golden, golden_length);
  buffer[10] = '\r';
  CHECK(expect_rejection(
      buffer,
      golden_length,
      WINN_AWG_UAPI_INVALID_TERMINATION) == 0);
  memcpy(buffer, golden, golden_length);
  buffer[10] = (char)0xff;
  CHECK(expect_rejection(
      buffer,
      golden_length,
      WINN_AWG_UAPI_INVALID_TERMINATION) == 0);
  free(buffer);

  prefix_length = WINN_AWG_UAPI_MAX_LINE_BYTES + 1U;
  buffer = malloc(prefix_length + 1U);
  CHECK(buffer != NULL);
  memcpy(buffer, "i1=", 3U);
  memset(buffer + 3U, 'a', prefix_length - 3U);
  buffer[prefix_length] = '\n';
  CHECK(expect_rejection(
      buffer,
      prefix_length + 1U,
      WINN_AWG_UAPI_LINE_TOO_LONG) == 0);
  free(buffer);

  prefix_length = WINN_AWG_UAPI_MAX_LINE_BYTES;
  buffer = malloc(prefix_length + golden_length + 1U);
  CHECK(buffer != NULL);
  memcpy(buffer, "i2=", 3U);
  memset(buffer + 3U, 'a', prefix_length - 3U);
  buffer[prefix_length] = '\n';
  memcpy(buffer + prefix_length + 1U, golden, golden_length);
  {
    WinnAWGUAPISnapshot snapshot;
    CHECK(sanitize(
        buffer,
        prefix_length + 1U + golden_length,
        expected_peer,
        &snapshot) == WINN_AWG_UAPI_OK);
  }
  free(buffer);
  return 0;
}

static int test_every_truncated_prefix_is_rejected(void) {
  const char *required_line = "persistent_keepalive_interval=25\n";
  const char *required_position = strstr(golden, required_line);
  size_t required_end;
  size_t prefix_length;

  CHECK(required_position != NULL);
  required_end =
      (size_t)(required_position - golden) + strlen(required_line);
  for (prefix_length = 0U;
       prefix_length < sizeof(golden) - 1U;
       ++prefix_length) {
    WinnAWGUAPISnapshot snapshot;
    WinnAWGUAPIStatus status = sanitize(
        golden, prefix_length, expected_peer, &snapshot);
    if (prefix_length < required_end ||
        golden[prefix_length - 1U] != '\n') {
      CHECK(status != WINN_AWG_UAPI_OK);
      CHECK(bytes_are_zero(&snapshot, sizeof(snapshot)));
    }
  }
  return 0;
}

static int test_required_wrong_and_multiple_peers(void) {
  char *mutated;
  size_t length;
  uint8_t wrong_peer[32];

  CHECK(expect_rejection(
      "listen_port=51820\n",
      strlen("listen_port=51820\n"),
      WINN_AWG_UAPI_ZERO_PEERS) == 0);

  mutated = replace_once(
      golden,
      "private_key=4444444444444444444444444444444444444444444444444444444444444444\n",
      "",
      &length);
  CHECK(mutated != NULL);
  CHECK(expect_rejection(
      mutated, length, WINN_AWG_UAPI_MISSING_FIELD) == 0);
  free(mutated);

  mutated = replace_once(golden, "rx_bytes=712\n", "", &length);
  CHECK(mutated != NULL);
  CHECK(expect_rejection(
      mutated, length, WINN_AWG_UAPI_MISSING_FIELD) == 0);
  free(mutated);

  memset(wrong_peer, 0x99, sizeof(wrong_peer));
  {
    WinnAWGUAPISnapshot snapshot;
    CHECK(sanitize(
        golden,
        sizeof(golden) - 1U,
        wrong_peer,
        &snapshot) == WINN_AWG_UAPI_WRONG_PEER);
    CHECK(bytes_are_zero(&snapshot, sizeof(snapshot)));
  }

  mutated = replace_once(
      golden,
      "allowed_ip=::/0\n",
      "allowed_ip=::/0\n"
      "public_key=3333333333333333333333333333333333333333333333333333333333333333\n",
      &length);
  CHECK(mutated != NULL);
  CHECK(expect_rejection(
      mutated, length, WINN_AWG_UAPI_MULTIPLE_PEERS) == 0);
  free(mutated);
  return 0;
}

static int test_every_required_field_is_enforced(void) {
  static const struct {
    const char *line;
    WinnAWGUAPIStatus status;
  } required[] = {
      {
          "private_key=4444444444444444444444444444444444444444444444444444444444444444\n",
          WINN_AWG_UAPI_MISSING_FIELD},
      {
          "public_key=2222222222222222222222222222222222222222222222222222222222222222\n",
          WINN_AWG_UAPI_UNKNOWN_FIELD},
      {
          "preshared_key=5555555555555555555555555555555555555555555555555555555555555555\n",
          WINN_AWG_UAPI_MISSING_FIELD},
      {"protocol_version=1\n", WINN_AWG_UAPI_MISSING_FIELD},
      {
          "last_handshake_time_sec=1900000000\n",
          WINN_AWG_UAPI_MISSING_FIELD},
      {
          "last_handshake_time_nsec=123456789\n",
          WINN_AWG_UAPI_MISSING_FIELD},
      {"tx_bytes=356\n", WINN_AWG_UAPI_MISSING_FIELD},
      {"rx_bytes=712\n", WINN_AWG_UAPI_MISSING_FIELD},
      {
          "persistent_keepalive_interval=25\n",
          WINN_AWG_UAPI_MISSING_FIELD}};
  size_t index;

  for (index = 0U; index < sizeof(required) / sizeof(required[0]); ++index) {
    char *mutated;
    size_t length;
    mutated = replace_once(golden, required[index].line, "", &length);
    CHECK(mutated != NULL);
    CHECK(expect_rejection(
        mutated, length, required[index].status) == 0);
    free(mutated);
  }
  return 0;
}

static int test_duplicates_unknown_and_hex(void) {
  static const struct {
    const char *needle;
    const char *replacement;
    WinnAWGUAPIStatus status;
  } cases[] = {
      {
          "listen_port=51820\n",
          "listen_port=51820\nlisten_port=51820\n",
          WINN_AWG_UAPI_DUPLICATE_FIELD},
      {
          "tx_bytes=356\n",
          "tx_bytes=356\ntx_bytes=356\n",
          WINN_AWG_UAPI_DUPLICATE_FIELD},
      {
          "allowed_ip=0.0.0.0/0\n",
          "allowed_ip=0.0.0.0/0\nallowed_ip=0.0.0.0/0\n",
          WINN_AWG_UAPI_DUPLICATE_FIELD},
      {
          "fwmark=7\n",
          "mystery=7\n",
          WINN_AWG_UAPI_UNKNOWN_FIELD},
      {
          "rx_bytes=712\n",
          "mystery=712\n",
          WINN_AWG_UAPI_UNKNOWN_FIELD},
      {
          "public_key=2222222222222222222222222222222222222222222222222222222222222222\n",
          "public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
          WINN_AWG_UAPI_INVALID_HEX},
      {
          "preshared_key=5555555555555555555555555555555555555555555555555555555555555555\n",
          "preshared_key=5555\n",
          WINN_AWG_UAPI_INVALID_HEX},
      {
          "private_key=4444444444444444444444444444444444444444444444444444444444444444\n",
          "private_key=0000000000000000000000000000000000000000000000000000000000000000\n",
          WINN_AWG_UAPI_INVALID_HEX}};
  size_t index;

  for (index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    char *mutated;
    size_t length;
    mutated = replace_once(
        golden, cases[index].needle, cases[index].replacement, &length);
    CHECK(mutated != NULL);
    CHECK(expect_rejection(
        mutated, length, cases[index].status) == 0);
    free(mutated);
  }
  return 0;
}

static int test_decimal_protocol_and_nanoseconds(void) {
  static const struct {
    const char *needle;
    const char *replacement;
    WinnAWGUAPIStatus status;
  } cases[] = {
      {"tx_bytes=356", "tx_bytes=-1", WINN_AWG_UAPI_INVALID_DECIMAL},
      {"tx_bytes=356", "tx_bytes=0356", WINN_AWG_UAPI_INVALID_DECIMAL},
      {
          "tx_bytes=356",
          "tx_bytes=18446744073709551616",
          WINN_AWG_UAPI_INVALID_DECIMAL},
      {
          "protocol_version=1",
          "protocol_version=2",
          WINN_AWG_UAPI_INVALID_PROTOCOL_VERSION},
      {
          "last_handshake_time_nsec=123456789",
          "last_handshake_time_nsec=1000000000",
          WINN_AWG_UAPI_INVALID_HANDSHAKE_NANOSECONDS},
      {
          "persistent_keepalive_interval=25",
          "persistent_keepalive_interval=65536",
          WINN_AWG_UAPI_INVALID_DECIMAL},
      {
          "listen_port=51820",
          "listen_port=0",
          WINN_AWG_UAPI_INVALID_DECIMAL},
      {"fwmark=7", "fwmark=0", WINN_AWG_UAPI_INVALID_DECIMAL},
      {"jc=4", "jc=0", WINN_AWG_UAPI_INVALID_DECIMAL},
      {"s1=90", "s1=0", WINN_AWG_UAPI_INVALID_DECIMAL},
      {
          "last_handshake_time_sec=1900000000",
          "last_handshake_time_sec=0",
          WINN_AWG_UAPI_INVALID_HANDSHAKE_NANOSECONDS}};
  size_t index;

  for (index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    char *mutated;
    size_t length;
    mutated = replace_once(
        golden, cases[index].needle, cases[index].replacement, &length);
    CHECK(mutated != NULL);
    CHECK(expect_rejection(
        mutated, length, cases[index].status) == 0);
    free(mutated);
  }
  return 0;
}

static int test_exact_second_handshake_is_valid(void) {
  char *mutated;
  size_t length;
  WinnAWGUAPISnapshot snapshot;

  mutated = replace_once(
      golden,
      "last_handshake_time_nsec=123456789",
      "last_handshake_time_nsec=0",
      &length);
  CHECK(mutated != NULL);
  CHECK(sanitize(
      mutated, length, expected_peer, &snapshot) == WINN_AWG_UAPI_OK);
  CHECK(snapshot.latest_handshake_unix_seconds == UINT64_C(1900000000));
  CHECK(snapshot.latest_handshake_nanoseconds == 0U);
  free(mutated);
  return 0;
}

static int test_endpoint_allowed_ip_and_malformed_lines(void) {
  static const struct {
    const char *needle;
    const char *replacement;
    WinnAWGUAPIStatus status;
  } cases[] = {
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=example.com:51820",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=[2001:db8::1]:51820",
          WINN_AWG_UAPI_OK},
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=[::]:1",
          WINN_AWG_UAPI_OK},
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=[::ffff:192.0.2.1]:65535",
          WINN_AWG_UAPI_OK},
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=192.0.2.10:0",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=192.0.2.10:65536",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=192.000.2.10:51820",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=[1::2::3]:51820",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=[1:2:3:4:5:6:7:8:9]:51820",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "endpoint=192.0.2.10:51820",
          "endpoint=[2001:DB8::1]:51820",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "allowed_ip=0.0.0.0/0",
          "allowed_ip=10.0.0.0/33",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "allowed_ip=0.0.0.0/0",
          "allowed_ip=255.255.255.255/32",
          WINN_AWG_UAPI_OK},
      {
          "allowed_ip=::/0",
          "allowed_ip=::ffff:192.0.2.0/120",
          WINN_AWG_UAPI_OK},
      {
          "allowed_ip=::/0",
          "allowed_ip=2001:db8::/129",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "allowed_ip=::/0",
          "allowed_ip=1::2::3/64",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "allowed_ip=::/0",
          "allowed_ip=1:2:3:4:5:6:7:8:9/64",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "allowed_ip=0.0.0.0/0",
          "allowed_ip=010.0.0.0/8",
          WINN_AWG_UAPI_MALFORMED_LINE},
      {
          "fwmark=7\n",
          "fwmark=\n",
          WINN_AWG_UAPI_MALFORMED_LINE}};
  size_t index;

  for (index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    char *mutated;
    size_t length;
    WinnAWGUAPISnapshot snapshot;
    WinnAWGUAPIStatus status;
    mutated = replace_once(
        golden, cases[index].needle, cases[index].replacement, &length);
    CHECK(mutated != NULL);
    status = sanitize(mutated, length, expected_peer, &snapshot);
    CHECK(status == cases[index].status);
    if (status != WINN_AWG_UAPI_OK) {
      CHECK(bytes_are_zero(&snapshot, sizeof(snapshot)));
    }
    free(mutated);
  }
  return 0;
}

static int test_allowed_ip_limit(void) {
  const char *needle =
      "allowed_ip=0.0.0.0/0\n"
      "allowed_ip=::/0\n";
  const char *position = strstr(golden, needle);
  size_t prefix;
  size_t suffix;
  char additions[512U];
  size_t additions_length = 0U;
  char *mutated;
  unsigned index;

  CHECK(position != NULL);
  prefix = (size_t)(position - golden);
  suffix = strlen(position + strlen(needle));
  for (index = 0U; index < 16U; ++index) {
    int written = snprintf(
        additions + additions_length,
        sizeof(additions) - additions_length,
        "allowed_ip=10.0.%u.0/24\n",
        index);
    CHECK(written > 0);
    CHECK((size_t)written < sizeof(additions) - additions_length);
    additions_length += (size_t)written;
  }
  mutated = malloc(prefix + additions_length + suffix + 1U);
  CHECK(mutated != NULL);
  memcpy(mutated, golden, prefix);
  memcpy(mutated + prefix, additions, additions_length);
  memcpy(
      mutated + prefix + additions_length,
      position + strlen(needle),
      suffix + 1U);
  {
    WinnAWGUAPISnapshot snapshot;
    CHECK(sanitize(
        mutated,
        prefix + additions_length + suffix,
        expected_peer,
        &snapshot) == WINN_AWG_UAPI_OK);
  }
  free(mutated);

  {
    int written = snprintf(
        additions + additions_length,
        sizeof(additions) - additions_length,
        "allowed_ip=10.1.0.0/24\n");
    CHECK(written > 0);
    CHECK((size_t)written < sizeof(additions) - additions_length);
    additions_length += (size_t)written;
  }
  mutated = malloc(prefix + additions_length + suffix + 1U);
  CHECK(mutated != NULL);
  memcpy(mutated, golden, prefix);
  memcpy(mutated + prefix, additions, additions_length);
  memcpy(
      mutated + prefix + additions_length,
      position + strlen(needle),
      suffix + 1U);
  CHECK(expect_rejection(
      mutated,
      prefix + additions_length + suffix,
      WINN_AWG_UAPI_TOO_MANY_LINES) == 0);
  free(mutated);
  return 0;
}

int main(void) {
  CHECK(test_success_and_secret_nonappearance() == 0);
  CHECK(test_arguments_and_bounds() == 0);
  CHECK(test_termination_and_line_limits() == 0);
  CHECK(test_every_truncated_prefix_is_rejected() == 0);
  CHECK(test_required_wrong_and_multiple_peers() == 0);
  CHECK(test_every_required_field_is_enforced() == 0);
  CHECK(test_duplicates_unknown_and_hex() == 0);
  CHECK(test_decimal_protocol_and_nanoseconds() == 0);
  CHECK(test_exact_second_handshake_is_valid() == 0);
  CHECK(test_endpoint_allowed_ip_and_malformed_lines() == 0);
  CHECK(test_allowed_ip_limit() == 0);
  puts("WINN_AWG_UAPI_SANITIZER_PASS");
  return 0;
}
