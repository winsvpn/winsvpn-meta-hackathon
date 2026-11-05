#include "../NativeEngine/WinnStageBNativeEngine.h"

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

static const char valid_start_config[] =
    "private_key=4444444444444444444444444444444444444444444444444444444444444444\n";

static const char valid_capture[] =
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
    "last_handshake_time_nsec=0\n"
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

typedef struct Fake {
  int32_t turn_on_result;
  unsigned turn_on_count;
  unsigned turn_off_count;
  unsigned get_count;
  unsigned free_count;
  unsigned rng_count;
  int32_t turn_on_fd;
  int32_t turn_off_handle;
  int32_t get_handle;
  int rng_fail_call;
  int rng_zero_call;
  int sha_fail_call;
  int sha_zero_call;
  unsigned sha_count;
  char *next_raw;
  size_t next_raw_size;
  size_t next_raw_actual_size;
  int raw_was_zero_at_free;
  const uint8_t *start_config_pointer;
} Fake;

static int bytes_are_zero(const void *bytes, size_t count) {
  const uint8_t *cursor = (const uint8_t *)bytes;
  size_t index;
  for (index = 0U; index < count; ++index) {
    if (cursor[index] != 0U) {
      return 0;
    }
  }
  return 1;
}

static int contains_byte_run(
    const uint8_t *bytes,
    size_t count,
    uint8_t value,
    size_t run_length) {
  size_t start;
  if (run_length > count) {
    return 0;
  }
  for (start = 0U; start <= count - run_length; ++start) {
    size_t index;
    for (index = 0U; index < run_length; ++index) {
      if (bytes[start + index] != value) {
        break;
      }
    }
    if (index == run_length) {
      return 1;
    }
  }
  return 0;
}

static int32_t fake_turn_on(
    const char *settings,
    int32_t fd,
    void *context) {
  Fake *fake = (Fake *)context;
  ++fake->turn_on_count;
  fake->turn_on_fd = fd;
  fake->start_config_pointer = (const uint8_t *)settings;
  return fake->turn_on_result;
}

static void fake_turn_off(int32_t handle, void *context) {
  Fake *fake = (Fake *)context;
  ++fake->turn_off_count;
  fake->turn_off_handle = handle;
}

static char *fake_get_config(int32_t handle, void *context) {
  Fake *fake = (Fake *)context;
  ++fake->get_count;
  fake->get_handle = handle;
  return fake->next_raw;
}

static size_t fake_raw_size(const char *raw, void *context) {
  Fake *fake = (Fake *)context;
  (void)raw;
  return fake->next_raw_size;
}

static void fake_raw_free(char *raw, void *context) {
  Fake *fake = (Fake *)context;
  ++fake->free_count;
  if (fake->next_raw_size == 0U &&
      fake->next_raw_actual_size != 0U) {
    /*
     * Models the required secure-release fallback when malloc_size fails:
     * erase using allocator-private metadata, then perform the actual free.
     */
    memset(raw, 0, fake->next_raw_actual_size);
  }
  if (fake->next_raw_actual_size != 0U) {
    fake->raw_was_zero_at_free =
        bytes_are_zero(raw, fake->next_raw_actual_size);
  } else {
    fake->raw_was_zero_at_free = 1;
  }
  free(raw);
  fake->next_raw = NULL;
}

static int fake_csprng(
    uint8_t *output,
    size_t output_length,
    void *context) {
  Fake *fake = (Fake *)context;
  uint8_t fill;
  ++fake->rng_count;
  if ((int)fake->rng_count == fake->rng_fail_call) {
    return 0;
  }
  if ((int)fake->rng_count == fake->rng_zero_call) {
    memset(output, 0, output_length);
    return 1;
  }
  fill = (uint8_t)(0x80U + fake->rng_count);
  memset(output, fill, output_length);
  return 1;
}

static int fake_sha256(
    const uint8_t *input,
    size_t input_length,
    uint8_t output[WINN_STAGE_B_SHA256_BYTES],
    void *context) {
  Fake *fake = (Fake *)context;
  uint8_t fill;
  (void)input;
  ++fake->sha_count;
  if ((int)fake->sha_count == fake->sha_fail_call) {
    return 0;
  }
  if ((int)fake->sha_count == fake->sha_zero_call) {
    memset(output, 0, WINN_STAGE_B_SHA256_BYTES);
    return 1;
  }
  if (input_length == sizeof(valid_start_config) - 1U &&
      memcmp(input, valid_start_config, input_length) == 0) {
    fill = 0x33U;
  } else if (input_length == sizeof(expected_peer) &&
             memcmp(input, expected_peer, input_length) == 0) {
    fill = 0x94U;
  } else if (input_length == WINN_STAGE_B_OPAQUE_TOKEN_BYTES) {
    fill = 0x93U;
  } else {
    fill = 0x34U;
  }
  memset(output, fill, WINN_STAGE_B_SHA256_BYTES);
  return 1;
}

static WinnStageBNativeFunctions functions(Fake *fake) {
  WinnStageBNativeFunctions result;
  memset(&result, 0, sizeof(result));
  result.wg_turn_on = fake_turn_on;
  result.wg_turn_off = fake_turn_off;
  result.wg_get_config = fake_get_config;
  result.raw_allocation_size = fake_raw_size;
  result.raw_free = fake_raw_free;
  result.csprng = fake_csprng;
  result.sha256 = fake_sha256;
  result.context = fake;
  return result;
}

static WinnStageBUtunCandidate valid_candidate(void) {
  WinnStageBUtunCandidate candidate;
  memset(&candidate, 0, sizeof(candidate));
  candidate.file_descriptor = 77;
  candidate.peer_control_id = 42U;
  candidate.utun_control_id = 42U;
  candidate.unit = 9U;
  candidate.peer_address_family = 32U;
  candidate.expected_system_address_family = 32U;
  candidate.peer_address_length_valid = 1U;
  return candidate;
}

static WinnStageBNativeStart valid_start(
    WinnStageBUtunCandidate *candidate) {
  WinnStageBNativeStart start;
  memset(&start, 0, sizeof(start));
  start.config = (const uint8_t *)valid_start_config;
  start.config_buffer_length = sizeof(valid_start_config);
  start.utun_candidates = candidate;
  start.utun_candidate_count = 1U;
  memcpy(start.expected_peer_public_key, expected_peer, sizeof(expected_peer));
  memset(start.config_sha256, 0x33, sizeof(start.config_sha256));
  start.engine_generation = UINT64_C(4);
  start.path_generation = UINT64_C(7);
  return start;
}

static WinnStageBNativeEngine *create_engine(Fake *fake) {
  WinnStageBNativeFunctions ops = functions(fake);
  WinnStageBNativeEngine *engine = NULL;
  if (winn_stage_b_native_engine_create(&ops, &engine) !=
      WINN_STAGE_B_NATIVE_OK) {
    return NULL;
  }
  return engine;
}

static char *raw_copy(const char *source, size_t *size) {
  *size = strlen(source) + 1U;
  {
    char *result = (char *)malloc(*size);
    if (result != NULL) {
      memcpy(result, source, *size);
    }
    return result;
  }
}

static void fake_set_raw_copy(Fake *fake, const char *source) {
  fake->next_raw = raw_copy(source, &fake->next_raw_actual_size);
  fake->next_raw_size = fake->next_raw_actual_size;
}

static int start_success(
    Fake *fake,
    WinnStageBNativeEngine *engine,
    WinnStageBNativeIdentity *identity) {
  WinnStageBUtunCandidate candidate = valid_candidate();
  WinnStageBNativeStart start = valid_start(&candidate);
  (void)fake;
  return winn_stage_b_native_engine_start(engine, &start, identity) ==
      WINN_STAGE_B_NATIVE_OK ? 0 : 1;
}

static int test_create_contract(void) {
  Fake fake;
  WinnStageBNativeFunctions ops;
  WinnStageBNativeEngine *engine = (WinnStageBNativeEngine *)(uintptr_t)1U;
  memset(&fake, 0, sizeof(fake));
  ops = functions(&fake);
  CHECK(
      winn_stage_b_native_engine_create(NULL, &engine) ==
      WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  CHECK(engine == NULL);
  CHECK(
      winn_stage_b_native_engine_create(&ops, NULL) ==
      WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  {
    unsigned missing;
    for (missing = 0U; missing < 7U; ++missing) {
      ops = functions(&fake);
      switch (missing) {
        case 0U: ops.wg_turn_on = NULL; break;
        case 1U: ops.wg_turn_off = NULL; break;
        case 2U: ops.wg_get_config = NULL; break;
        case 3U: ops.raw_allocation_size = NULL; break;
        case 4U: ops.raw_free = NULL; break;
        case 5U: ops.csprng = NULL; break;
        default: ops.sha256 = NULL; break;
      }
      CHECK(
          winn_stage_b_native_engine_create(&ops, &engine) ==
          WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
      CHECK(engine == NULL);
    }
  }
  ops = functions(&fake);
  CHECK(
      winn_stage_b_native_engine_create(&ops, &engine) ==
      WINN_STAGE_B_NATIVE_OK);
  CHECK(engine != NULL);
  winn_stage_b_native_engine_destroy(&engine);
  CHECK(engine == NULL);
  winn_stage_b_native_engine_destroy(&engine);
  winn_stage_b_native_engine_destroy(NULL);
  return 0;
}

static int test_start_success_duplicate_and_stop(void) {
  Fake fake;
  WinnStageBNativeEngine *engine;
  WinnStageBUtunCandidate candidate = valid_candidate();
  WinnStageBNativeStart start = valid_start(&candidate);
  WinnStageBNativeIdentity identity;
  WinnStageBNativeIdentity duplicate;
  memset(&fake, 0, sizeof(fake));
  fake.turn_on_result = 1234;
  engine = create_engine(&fake);
  CHECK(engine != NULL);

  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_OK);
  CHECK(fake.turn_on_count == 1U);
  CHECK(fake.turn_on_fd == candidate.file_descriptor);
  CHECK(fake.start_config_pointer == start.config);
  CHECK(identity.engine_instance_uuid[0] == 0x81U);
  CHECK((identity.engine_instance_uuid[6] & 0xf0U) == 0x40U);
  CHECK((identity.engine_instance_uuid[8] & 0xc0U) == 0x80U);
  CHECK(identity.winning_interface_token_sha256[0] == 0x93U);
  CHECK(identity.expected_peer_sha256[0] == 0x94U);
  CHECK(identity.engine_generation == start.engine_generation);
  CHECK(identity.path_generation == start.path_generation);
  CHECK(memcmp(identity.config_sha256, start.config_sha256, 32U) == 0);
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &duplicate) ==
      WINN_STAGE_B_NATIVE_INVALID_STATE);
  CHECK(bytes_are_zero(&duplicate, sizeof(duplicate)));
  CHECK(fake.turn_on_count == 1U);
  CHECK(winn_stage_b_native_engine_stop(engine) == WINN_STAGE_B_NATIVE_OK);
  CHECK(fake.turn_off_count == 1U);
  CHECK(fake.turn_off_handle == 1234);
  CHECK(winn_stage_b_native_engine_stop(engine) == WINN_STAGE_B_NATIVE_OK);
  CHECK(fake.turn_off_count == 1U);
  winn_stage_b_native_engine_destroy(&engine);
  CHECK(fake.turn_off_count == 1U);
  return 0;
}

static int test_external_stop_exact_handle(void) {
  Fake fake;
  WinnStageBNativeEngine *engine;
  WinnStageBUtunCandidate candidate = valid_candidate();
  WinnStageBNativeStart start = valid_start(&candidate);
  WinnStageBNativeIdentity identity;
  WinnStageBNativeObservation observation;
  WinnAWGUAPIStatus detail;
  memset(&fake, 0, sizeof(fake));
  fake.turn_on_result = 4321;
  engine = create_engine(&fake);
  CHECK(engine != NULL);
  CHECK(winn_stage_b_native_engine_start(engine, &start, &identity) ==
        WINN_STAGE_B_NATIVE_OK);
  CHECK(winn_stage_b_native_engine_record_external_stop(engine, 4320) ==
        WINN_STAGE_B_NATIVE_INVALID_STATE);
  CHECK(winn_stage_b_native_engine_record_external_stop(NULL, 4321) ==
        WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  CHECK(winn_stage_b_native_engine_record_external_stop(engine, -1) ==
        WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  fake_set_raw_copy(&fake, valid_capture);
  CHECK(winn_stage_b_native_engine_capture(engine, &observation, &detail) ==
        WINN_STAGE_B_NATIVE_OK);
  CHECK(winn_stage_b_native_engine_record_external_stop(engine, 4321) ==
        WINN_STAGE_B_NATIVE_OK);
  CHECK(fake.turn_off_count == 0U);
  CHECK(winn_stage_b_native_engine_record_external_stop(engine, 4321) ==
        WINN_STAGE_B_NATIVE_INVALID_STATE);
  memset(&observation, 0xa5, sizeof(observation));
  CHECK(winn_stage_b_native_engine_capture(engine, &observation, &detail) ==
        WINN_STAGE_B_NATIVE_INVALID_STATE);
  CHECK(bytes_are_zero(&observation, sizeof(observation)));
  winn_stage_b_native_engine_destroy(&engine);
  CHECK(fake.turn_off_count == 0U);
  return 0;
}

static int test_utun_cardinality_and_validation(void) {
  Fake fake;
  WinnStageBNativeEngine *engine;
  WinnStageBUtunCandidate candidates[2];
  WinnStageBNativeStart start;
  WinnStageBNativeIdentity identity;
  size_t field;
  memset(&fake, 0, sizeof(fake));
  fake.turn_on_result = 2;
  candidates[0] = valid_candidate();
  candidates[1] = valid_candidate();
  engine = create_engine(&fake);
  CHECK(engine != NULL);
  start = valid_start(candidates);

  start.utun_candidate_count = 0U;
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_ZERO_UTUN_CANDIDATES);
  start.utun_candidate_count = 2U;
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_MULTIPLE_UTUN_CANDIDATES);
  start.utun_candidate_count = 1U;
  start.utun_candidates = NULL;
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_UTUN_CANDIDATE);

  for (field = 0U; field < 8U; ++field) {
    WinnStageBUtunCandidate mutated = valid_candidate();
    start.utun_candidates = &mutated;
    switch (field) {
      case 0U: mutated.file_descriptor = -1; break;
      case 1U: mutated.peer_control_id = 0U; break;
      case 2U: mutated.utun_control_id += 1U; break;
      case 3U: mutated.unit = 0U; break;
      case 4U: mutated.peer_address_family = 0U; break;
      case 5U: mutated.expected_system_address_family += 1U; break;
      case 6U: mutated.peer_address_length_valid = 0U; break;
      default: mutated.reserved[1] = 1U; break;
    }
    CHECK(
        winn_stage_b_native_engine_start(engine, &start, &identity) ==
        WINN_STAGE_B_NATIVE_INVALID_UTUN_CANDIDATE);
    CHECK(bytes_are_zero(&identity, sizeof(identity)));
  }
  CHECK(fake.turn_on_count == 0U);
  winn_stage_b_native_engine_destroy(&engine);
  return 0;
}

static int test_config_and_identity_mutations(void) {
  Fake fake;
  WinnStageBNativeEngine *engine;
  WinnStageBUtunCandidate candidate = valid_candidate();
  WinnStageBNativeStart start = valid_start(&candidate);
  WinnStageBNativeIdentity identity;
  uint8_t buffer[sizeof(valid_start_config)];
  uint8_t *oversized;
  memset(&fake, 0, sizeof(fake));
  fake.turn_on_result = 2;
  engine = create_engine(&fake);
  CHECK(engine != NULL);

  memset(&identity, 0xa5, sizeof(identity));
  CHECK(
      winn_stage_b_native_engine_start(NULL, &start, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  CHECK(bytes_are_zero(&identity, sizeof(identity)));
  memset(&identity, 0xa5, sizeof(identity));
  CHECK(
      winn_stage_b_native_engine_start(engine, NULL, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  CHECK(bytes_are_zero(&identity, sizeof(identity)));
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, NULL) ==
      WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);

  start.config = NULL;
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_EMPTY_CONFIG);
  start = valid_start(&candidate);
  start.config_buffer_length = 1U;
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_EMPTY_CONFIG);
  oversized = (uint8_t *)malloc(
      (size_t)WINN_STAGE_B_MAX_CONFIG_BYTES + 2U);
  CHECK(oversized != NULL);
  memset(
      oversized, 'a', (size_t)WINN_STAGE_B_MAX_CONFIG_BYTES + 2U);
  oversized[WINN_STAGE_B_MAX_CONFIG_BYTES] = (uint8_t)'\n';
  oversized[WINN_STAGE_B_MAX_CONFIG_BYTES + 1U] = 0U;
  start.config = oversized;
  start.config_buffer_length =
      (size_t)WINN_STAGE_B_MAX_CONFIG_BYTES + 2U;
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_CONFIG_TOO_LARGE);
  free(oversized);

  memcpy(buffer, valid_start_config, sizeof(buffer));
  start = valid_start(&candidate);
  start.config = buffer;
  buffer[sizeof(buffer) - 1U] = (uint8_t)'x';
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_CONFIG_TERMINATION);
  memcpy(buffer, valid_start_config, sizeof(buffer));
  buffer[sizeof(buffer) - 2U] = (uint8_t)'x';
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_CONFIG_TERMINATION);
  memcpy(buffer, valid_start_config, sizeof(buffer));
  buffer[10] = 0U;
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_CONFIG_TERMINATION);
  memcpy(buffer, valid_start_config, sizeof(buffer));
  buffer[20] = (uint8_t)'6';
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_CONFIG_SHA256_MISMATCH);

  start = valid_start(&candidate);
  memset(start.expected_peer_public_key, 0, 32U);
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_IDENTITY);
  start = valid_start(&candidate);
  memset(start.config_sha256, 0, 32U);
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_IDENTITY);
  start = valid_start(&candidate);
  start.engine_generation = 0U;
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_IDENTITY);
  start = valid_start(&candidate);
  start.path_generation = 0U;
  CHECK(
      winn_stage_b_native_engine_start(engine, &start, &identity) ==
      WINN_STAGE_B_NATIVE_INVALID_IDENTITY);
  CHECK(fake.turn_on_count == 0U);
  winn_stage_b_native_engine_destroy(&engine);
  return 0;
}

static int test_rng_and_turn_on_failures(void) {
  int scenario;
  for (scenario = 1; scenario <= 4; ++scenario) {
    Fake fake;
    WinnStageBNativeEngine *engine;
    WinnStageBUtunCandidate candidate = valid_candidate();
    WinnStageBNativeStart start = valid_start(&candidate);
    WinnStageBNativeIdentity identity;
    WinnStageBNativeStatus expected;
    memset(&fake, 0, sizeof(fake));
    fake.turn_on_result = 6;
    if (scenario == 1) {
      fake.rng_fail_call = 1;
      expected = WINN_STAGE_B_NATIVE_CSPRNG_FAILED;
    } else if (scenario == 2) {
      fake.rng_fail_call = 2;
      expected = WINN_STAGE_B_NATIVE_CSPRNG_FAILED;
    } else if (scenario == 3) {
      fake.rng_zero_call = 2;
      expected = WINN_STAGE_B_NATIVE_CSPRNG_ZERO_OUTPUT;
    } else {
      fake.rng_zero_call = 1;
      expected = WINN_STAGE_B_NATIVE_CSPRNG_ZERO_OUTPUT;
    }
    engine = create_engine(&fake);
    CHECK(engine != NULL);
    CHECK(
        winn_stage_b_native_engine_start(engine, &start, &identity) ==
        expected);
    CHECK(bytes_are_zero(&identity, sizeof(identity)));
    CHECK(fake.turn_on_count == 0U);
    winn_stage_b_native_engine_destroy(&engine);
  }
  {
    Fake fake;
    WinnStageBNativeEngine *engine;
    WinnStageBUtunCandidate candidate = valid_candidate();
    WinnStageBNativeStart start = valid_start(&candidate);
    WinnStageBNativeIdentity identity;
    memset(&fake, 0, sizeof(fake));
    fake.turn_on_result = -1;
    engine = create_engine(&fake);
    CHECK(engine != NULL);
    CHECK(
        winn_stage_b_native_engine_start(engine, &start, &identity) ==
        WINN_STAGE_B_NATIVE_TURN_ON_FAILED);
    CHECK(bytes_are_zero(&identity, sizeof(identity)));
    CHECK(fake.turn_on_count == 1U);
    CHECK(fake.turn_off_count == 0U);
    winn_stage_b_native_engine_destroy(&engine);
    CHECK(fake.turn_off_count == 0U);
  }
  return 0;
}

static int test_sha256_failures(void) {
  int scenario;
  for (scenario = 1; scenario <= 4; ++scenario) {
    Fake fake;
    WinnStageBNativeEngine *engine;
    WinnStageBUtunCandidate candidate = valid_candidate();
    WinnStageBNativeStart start = valid_start(&candidate);
    WinnStageBNativeIdentity identity;
    WinnStageBNativeStatus expected = WINN_STAGE_B_NATIVE_SHA256_FAILED;
    memset(&fake, 0, sizeof(fake));
    fake.turn_on_result = 7;
    if (scenario <= 3) {
      fake.sha_fail_call = scenario;
    } else {
      fake.sha_zero_call = 2;
    }
    engine = create_engine(&fake);
    CHECK(engine != NULL);
    CHECK(
        winn_stage_b_native_engine_start(engine, &start, &identity) ==
        expected);
    CHECK(bytes_are_zero(&identity, sizeof(identity)));
    CHECK(fake.turn_on_count == 0U);
    CHECK(fake.turn_off_count == 0U);
    winn_stage_b_native_engine_destroy(&engine);
  }
  return 0;
}

static int test_capture_success_and_owned_handle(void) {
  Fake fake;
  WinnStageBNativeEngine *engine;
  WinnStageBNativeIdentity identity;
  WinnStageBNativeObservation observation;
  WinnAWGUAPIStatus detail;
  memset(&fake, 0, sizeof(fake));
  fake.turn_on_result = 991;
  engine = create_engine(&fake);
  CHECK(engine != NULL);
  CHECK(start_success(&fake, engine, &identity) == 0);
  fake_set_raw_copy(&fake, valid_capture);
  CHECK(fake.next_raw != NULL);
  CHECK(
      winn_stage_b_native_engine_capture(engine, &observation, &detail) ==
      WINN_STAGE_B_NATIVE_OK);
  CHECK(detail == WINN_AWG_UAPI_OK);
  CHECK(fake.get_count == 1U);
  CHECK(fake.get_handle == 991);
  CHECK(fake.free_count == 1U);
  CHECK(fake.raw_was_zero_at_free);
  CHECK(memcmp(&observation.identity, &identity, sizeof(identity)) == 0);
  CHECK(
      observation.telemetry.latest_handshake_unix_seconds ==
      UINT64_C(1900000000));
  CHECK(observation.telemetry.latest_handshake_nanoseconds == 0U);
  CHECK(observation.telemetry.received_bytes == UINT64_C(712));
  CHECK(!contains_byte_run(
      (const uint8_t *)&observation,
      sizeof(observation),
      0x44U,
      32U));
  CHECK(!contains_byte_run(
      (const uint8_t *)&observation,
      sizeof(observation),
      0x55U,
      32U));
  winn_stage_b_native_engine_destroy(&engine);
  CHECK(fake.turn_off_handle == 991);
  return 0;
}

static int test_capture_failures_scrub_and_free(void) {
  int scenario;
  for (scenario = 0; scenario < 6; ++scenario) {
    Fake fake;
    WinnStageBNativeEngine *engine;
    WinnStageBNativeIdentity identity;
    WinnStageBNativeObservation observation;
    WinnAWGUAPIStatus detail;
    WinnStageBNativeStatus expected;
    memset(&fake, 0, sizeof(fake));
    fake.turn_on_result = 44;
    engine = create_engine(&fake);
    CHECK(engine != NULL);
    CHECK(start_success(&fake, engine, &identity) == 0);
    if (scenario == 0) {
      fake.next_raw = NULL;
      fake.next_raw_size = 0U;
      expected = WINN_STAGE_B_NATIVE_GET_CONFIG_FAILED;
    } else if (scenario == 1) {
      fake_set_raw_copy(&fake, valid_capture);
      CHECK(fake.next_raw != NULL);
      fake.next_raw_size = 0U;
      expected = WINN_STAGE_B_NATIVE_INVALID_RAW_ALLOCATION;
    } else if (scenario == 2) {
      fake.next_raw_size =
          (size_t)WINN_AWG_UAPI_MAX_INPUT_BYTES + 2U;
      fake.next_raw_actual_size = fake.next_raw_size;
      fake.next_raw = (char *)malloc(fake.next_raw_size);
      CHECK(fake.next_raw != NULL);
      memset(fake.next_raw, 'x', fake.next_raw_size);
      expected = WINN_STAGE_B_NATIVE_GET_CONFIG_TOO_LARGE;
    } else if (scenario == 3) {
      fake.next_raw_size = 1U;
      fake.next_raw_actual_size = 1U;
      fake.next_raw = (char *)malloc(1U);
      CHECK(fake.next_raw != NULL);
      fake.next_raw[0] = 'x';
      expected = WINN_STAGE_B_NATIVE_INVALID_RAW_ALLOCATION;
    } else if (scenario == 4) {
      const char malformed[] = "private_key=not-hex\n";
      fake_set_raw_copy(&fake, malformed);
      CHECK(fake.next_raw != NULL);
      expected = WINN_STAGE_B_NATIVE_UAPI_REJECTED;
    } else {
      char wrong_peer[sizeof(valid_capture)];
      char *position;
      memcpy(wrong_peer, valid_capture, sizeof(wrong_peer));
      position = strstr(wrong_peer, "public_key=2222");
      CHECK(position != NULL);
      position[11] = '3';
      fake_set_raw_copy(&fake, wrong_peer);
      CHECK(fake.next_raw != NULL);
      expected = WINN_STAGE_B_NATIVE_UAPI_REJECTED;
    }
    memset(&observation, 0xa5, sizeof(observation));
    detail = WINN_AWG_UAPI_OK;
    CHECK(
        winn_stage_b_native_engine_capture(
            engine, &observation, &detail) == expected);
    CHECK(bytes_are_zero(&observation, sizeof(observation)));
    if (scenario == 0) {
      CHECK(fake.free_count == 0U);
    } else {
      CHECK(fake.free_count == 1U);
      if (!fake.raw_was_zero_at_free) {
        fprintf(stderr, "raw scrub failure in scenario %d\n", scenario);
      }
      CHECK(fake.raw_was_zero_at_free);
    }
    if (scenario >= 4) {
      CHECK(detail != WINN_AWG_UAPI_OK);
    }
    winn_stage_b_native_engine_destroy(&engine);
  }
  return 0;
}

static int test_capture_arguments_and_stopped_state(void) {
  Fake fake;
  WinnStageBNativeEngine *engine;
  WinnStageBNativeObservation observation;
  WinnAWGUAPIStatus detail;
  memset(&fake, 0, sizeof(fake));
  fake.turn_on_result = 3;
  engine = create_engine(&fake);
  CHECK(engine != NULL);
  CHECK(
      winn_stage_b_native_engine_capture(engine, &observation, &detail) ==
      WINN_STAGE_B_NATIVE_INVALID_STATE);
  CHECK(bytes_are_zero(&observation, sizeof(observation)));
  CHECK(
      winn_stage_b_native_engine_capture(NULL, &observation, &detail) ==
      WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  CHECK(
      winn_stage_b_native_engine_capture(engine, NULL, &detail) ==
      WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  CHECK(
      winn_stage_b_native_engine_capture(engine, &observation, NULL) ==
      WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  CHECK(
      winn_stage_b_native_engine_stop(NULL) ==
      WINN_STAGE_B_NATIVE_INVALID_ARGUMENT);
  winn_stage_b_native_engine_destroy(&engine);
  return 0;
}

int main(void) {
  CHECK(test_create_contract() == 0);
  CHECK(test_start_success_duplicate_and_stop() == 0);
  CHECK(test_external_stop_exact_handle() == 0);
  CHECK(test_utun_cardinality_and_validation() == 0);
  CHECK(test_config_and_identity_mutations() == 0);
  CHECK(test_rng_and_turn_on_failures() == 0);
  CHECK(test_sha256_failures() == 0);
  CHECK(test_capture_success_and_owned_handle() == 0);
  CHECK(test_capture_failures_scrub_and_free() == 0);
  CHECK(test_capture_arguments_and_stopped_state() == 0);
  puts("WINN_STAGE_B_NATIVE_ENGINE_PASS");
  return 0;
}
