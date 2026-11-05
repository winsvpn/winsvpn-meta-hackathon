#include "../NativeEngine/WinnStageBFrameworkDarwin.h"
#include "../NativeEngine/WinnStageBFrameworkLoaderInternal.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression)                                                     \
  do {                                                                        \
    if (!(expression)) {                                                      \
      fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__,      \
              #expression);                                                   \
      return 1;                                                               \
    }                                                                         \
  } while (0)

static const char kCanonicalPath[] =
    "/private/var/containers/Bundle/Application/ABC/WCF3.app/Frameworks/"
    "WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine";

static const char *const kSymbols[WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT] = {
    "wgTurnOn",
    "wgTurnOff",
    "wgGetConfig",
    "wgSetConfig",
    "wgBumpSockets",
    "wins_amneziawg_packet_engine_contract_version"};

typedef enum Fault {
  FAULT_NONE = 0,
  FAULT_PREFLIGHT_CALL,
  FAULT_PATH,
  FAULT_SOURCE,
  FAULT_RUNTIME_ZERO,
  FAULT_RUNTIME_EQUALS_SOURCE,
  FAULT_IDENTITY,
  FAULT_MANIFEST,
  FAULT_NOFOLLOW,
  FAULT_LOADER_GATE,
  FAULT_PREFLIGHT_RESERVED,
  FAULT_PLATFORM,
  FAULT_ARCHITECTURE,
  FAULT_MACHO,
  FAULT_DLOPEN,
  FAULT_SYMBOL,
  FAULT_POSTFLIGHT_CALL,
  FAULT_SYMBOL_IMAGE,
  FAULT_POST_PATH,
  FAULT_POST_RETAINED,
  FAULT_POST_MACHO,
  FAULT_POST_RESERVED,
  FAULT_REBIND_HASH,
  FAULT_REBIND_INODE,
  FAULT_CONTRACT
} Fault;

typedef struct Fake {
  Fault fault;
  atomic_uint preflight_calls;
  atomic_uint dlopen_calls;
  atomic_uint dlsym_calls;
  atomic_uint postflight_calls;
  atomic_uint wrong_order;
  atomic_uint wrong_path;
  atomic_uint wrong_flags;
  atomic_uint wrong_handle;
  atomic_uint symbol_counts[WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT];
} Fake;

static atomic_int g_contract_calls;
static atomic_int g_engine_active;
static atomic_int g_engine_overlap;
static atomic_int g_turn_on_calls;
static atomic_int g_turn_off_calls;
static atomic_int g_get_calls;
static atomic_int g_set_calls;
static atomic_int g_bump_calls;
static atomic_int g_late_entered;
static atomic_int g_late_release;
static int g_late_mode;
static int g_contract_result = WINN_STAGE_B_FRAMEWORK_CONTRACT_VERSION;
static char g_config[] = "private_key=redacted\nerrno=0\n\n";
static WinnStageBFrameworkSymbolAddress
    g_addresses[WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT];
static int g_fake_handle;

static void engine_enter(void) {
  if (atomic_fetch_add(&g_engine_active, 1) != 0) {
    atomic_store(&g_engine_overlap, 1);
  }
}

static void engine_leave(void) {
  unsigned index;
  for (index = 0U; index < 10000U; ++index) {
    atomic_signal_fence(memory_order_seq_cst);
  }
  (void)atomic_fetch_sub(&g_engine_active, 1);
}

static int32_t fake_turn_on(const char *settings, int32_t utun_fd) {
  engine_enter();
  (void)atomic_fetch_add(&g_turn_on_calls, 1);
  if (settings == NULL || strcmp(settings, "secret-settings") != 0 ||
      utun_fd != 9) {
    engine_leave();
    return -1;
  }
  if (g_late_mode != 0) {
    atomic_store(&g_late_entered, 1);
    while (atomic_load(&g_late_release) == 0) {
      atomic_signal_fence(memory_order_seq_cst);
    }
  }
  engine_leave();
  return 7;
}

static void fake_turn_off(int32_t handle) {
  engine_enter();
  if (handle == 7) {
    (void)atomic_fetch_add(&g_turn_off_calls, 1);
  }
  engine_leave();
}

static char *fake_get_config(int32_t handle) {
  char *result = NULL;
  engine_enter();
  (void)atomic_fetch_add(&g_get_calls, 1);
  if (handle == 7) {
    result = g_config;
  }
  engine_leave();
  return result;
}

static int64_t fake_set_config(int32_t handle, const char *settings) {
  int64_t result = -1;
  engine_enter();
  (void)atomic_fetch_add(&g_set_calls, 1);
  if (handle == 7 && settings != NULL && settings[0] != '\0') {
    result = 0;
  }
  engine_leave();
  return result;
}

static void fake_bump_sockets(int32_t handle) {
  engine_enter();
  if (handle == 7) {
    (void)atomic_fetch_add(&g_bump_calls, 1);
  }
  engine_leave();
}

static int fake_contract_version(void) {
  (void)atomic_fetch_add(&g_contract_calls, 1);
  return g_contract_result;
}

static void initialize_addresses(void) {
  WinnStageBFrameworkWGTurnOn turn_on = fake_turn_on;
  WinnStageBFrameworkWGTurnOff turn_off = fake_turn_off;
  WinnStageBFrameworkWGGetConfig get_config = fake_get_config;
  WinnStageBFrameworkWGSetConfig set_config = fake_set_config;
  WinnStageBFrameworkWGBumpSockets bump_sockets = fake_bump_sockets;
  WinnStageBFrameworkContractVersion contract_version = fake_contract_version;
  memcpy(&g_addresses[0], &turn_on, sizeof(turn_on));
  memcpy(&g_addresses[1], &turn_off, sizeof(turn_off));
  memcpy(&g_addresses[2], &get_config, sizeof(get_config));
  memcpy(&g_addresses[3], &set_config, sizeof(set_config));
  memcpy(&g_addresses[4], &bump_sockets, sizeof(bump_sockets));
  memcpy(&g_addresses[5], &contract_version, sizeof(contract_version));
}

static void initialize_fake(Fake *fake, Fault fault) {
  memset(fake, 0, sizeof(*fake));
  fake->fault = fault;
  initialize_addresses();
  g_contract_result = fault == FAULT_CONTRACT ? 2 : 1;
}

static void fill_runtime_digest(uint8_t digest[32]) {
  size_t index;
  for (index = 0U; index < 32U; ++index) {
    digest[index] = (uint8_t)(index + 1U);
  }
}

static int fake_preflight(
    const WinnStageBFrameworkExpected *expected,
    WinnStageBFrameworkPreflight *output,
    void *context) {
  Fake *fake = (Fake *)context;
  (void)atomic_fetch_add(&fake->preflight_calls, 1);
  if (fake->fault == FAULT_PREFLIGHT_CALL) {
    return 0;
  }
  memset(output, 0, sizeof(*output));
  memcpy(output->canonical_path, kCanonicalPath, sizeof(kCanonicalPath));
  memcpy(output->source_binary_sha256, expected->source_binary_sha256,
         sizeof(output->source_binary_sha256));
  fill_runtime_digest(output->signed_runtime_sha256);
  output->device = 11U;
  output->inode = 12U;
  output->file_size = 4096U;
  output->retained_file_token = 14U;
  output->platform = expected->platform;
  output->architecture = expected->architecture;
  output->link_count = 1U;
  output->manifest_strictly_parsed = 1U;
  output->descriptor_relative_nofollow = 1U;
  output->macho_contract_valid = 1U;
  output->platform_loader_gate_expected = 1U;
  switch (fake->fault) {
    case FAULT_PATH:
      memcpy(output->canonical_path, "/tmp/engine", sizeof("/tmp/engine"));
      break;
    case FAULT_SOURCE:
      output->source_binary_sha256[0] ^= 1U;
      break;
    case FAULT_RUNTIME_ZERO:
      memset(output->signed_runtime_sha256, 0,
             sizeof(output->signed_runtime_sha256));
      break;
    case FAULT_RUNTIME_EQUALS_SOURCE:
      memcpy(output->signed_runtime_sha256, output->source_binary_sha256,
             sizeof(output->signed_runtime_sha256));
      break;
    case FAULT_IDENTITY:
      output->link_count = 2U;
      break;
    case FAULT_MANIFEST:
      output->manifest_strictly_parsed = 0U;
      break;
    case FAULT_NOFOLLOW:
      output->descriptor_relative_nofollow = 0U;
      break;
    case FAULT_LOADER_GATE:
      output->platform_loader_gate_expected = 0U;
      break;
    case FAULT_PREFLIGHT_RESERVED:
      output->reserved[0] = 1U;
      break;
    case FAULT_PLATFORM:
      output->platform = output->platform == 1U ? 2U : 1U;
      break;
    case FAULT_ARCHITECTURE:
      output->architecture = output->architecture == 1U ? 2U : 1U;
      break;
    case FAULT_MACHO:
      output->macho_contract_valid = 0U;
      break;
    default:
      break;
  }
  return 1;
}

static void *fake_dlopen(const char *path, int flags, void *context) {
  Fake *fake = (Fake *)context;
  if (atomic_load(&fake->preflight_calls) != 1U) {
    atomic_store(&fake->wrong_order, 1U);
  }
  (void)atomic_fetch_add(&fake->dlopen_calls, 1);
  if (path == NULL || strcmp(path, kCanonicalPath) != 0) {
    atomic_store(&fake->wrong_path, 1U);
  }
  if (flags != (RTLD_NOW | RTLD_LOCAL)) {
    atomic_store(&fake->wrong_flags, 1U);
  }
  return fake->fault == FAULT_DLOPEN ? NULL : (void *)&g_fake_handle;
}

static WinnStageBFrameworkSymbolAddress fake_dlsym(
    void *handle,
    const char *name,
    void *context) {
  Fake *fake = (Fake *)context;
  size_t index;
  if (atomic_load(&fake->dlopen_calls) != 1U) {
    atomic_store(&fake->wrong_order, 1U);
  }
  (void)atomic_fetch_add(&fake->dlsym_calls, 1);
  if (handle != (void *)&g_fake_handle) {
    atomic_store(&fake->wrong_handle, 1U);
    return NULL;
  }
  for (index = 0U;
       index < (size_t)WINN_STAGE_B_FRAMEWORK_REQUIRED_SYMBOL_COUNT;
       ++index) {
    if (name != NULL && strcmp(name, kSymbols[index]) == 0) {
      (void)atomic_fetch_add(&fake->symbol_counts[index], 1);
      if (fake->fault == FAULT_SYMBOL && index == 3U) {
        return NULL;
      }
      return g_addresses[index];
    }
  }
  return NULL;
}

static int fake_postflight(
    void *handle,
    const WinnStageBFrameworkSymbolAddress symbols[6],
    const WinnStageBFrameworkPreflight *preflight,
    WinnStageBFrameworkPostflight *output,
    void *context) {
  Fake *fake = (Fake *)context;
  size_t index;
  if (handle != (void *)&g_fake_handle ||
      atomic_load(&fake->dlsym_calls) != 6U) {
    atomic_store(&fake->wrong_order, 1U);
  }
  for (index = 0U; index < 6U; ++index) {
    if (symbols[index] != g_addresses[index]) {
      atomic_store(&fake->wrong_handle, 1U);
    }
  }
  (void)atomic_fetch_add(&fake->postflight_calls, 1);
  if (fake->fault == FAULT_POSTFLIGHT_CALL) {
    return 0;
  }
  memset(output, 0, sizeof(*output));
  memcpy(output->signed_runtime_sha256,
         preflight->signed_runtime_sha256,
         sizeof(output->signed_runtime_sha256));
  output->device = preflight->device;
  output->inode = preflight->inode;
  output->file_size = preflight->file_size;
  output->every_symbol_same_image = 1U;
  output->canonical_path_unchanged = 1U;
  output->retained_inode_unchanged = 1U;
  output->macho_contract_unchanged = 1U;
  if (fake->fault == FAULT_SYMBOL_IMAGE) {
    output->every_symbol_same_image = 0U;
  } else if (fake->fault == FAULT_POST_PATH) {
    output->canonical_path_unchanged = 0U;
  } else if (fake->fault == FAULT_POST_RETAINED) {
    output->retained_inode_unchanged = 0U;
  } else if (fake->fault == FAULT_POST_MACHO) {
    output->macho_contract_unchanged = 0U;
  } else if (fake->fault == FAULT_POST_RESERVED) {
    output->reserved[0] = 1U;
  } else if (fake->fault == FAULT_REBIND_HASH) {
    output->signed_runtime_sha256[31] ^= 1U;
  } else if (fake->fault == FAULT_REBIND_INODE) {
    ++output->inode;
  }
  return 1;
}

static WinnStageBFrameworkRuntimeBoundary make_boundary(Fake *fake) {
  WinnStageBFrameworkRuntimeBoundary boundary;
  memset(&boundary, 0, sizeof(boundary));
  boundary.preflight = fake_preflight;
  boundary.dlopen_absolute = fake_dlopen;
  boundary.dlsym_handle = fake_dlsym;
  boundary.postflight = fake_postflight;
  boundary.context = fake;
  return boundary;
}

static int assert_load_fault(Fault fault, WinnStageBFrameworkStatus expected) {
  Fake fake;
  WinnStageBFrameworkRuntimeBoundary boundary;
  const WinnStageBFrameworkImage *image = NULL;
  WinnStageBFrameworkStatus status;
  initialize_fake(&fake, fault);
  boundary = make_boundary(&fake);
  status = winn_stage_b_framework_shared_image_for_testing(&boundary, &image);
  CHECK(status == expected);
  CHECK(image == NULL);
  CHECK(atomic_load(&fake.wrong_order) == 0U);
  CHECK(atomic_load(&fake.wrong_path) == 0U);
  CHECK(atomic_load(&fake.wrong_flags) == 0U);
  CHECK(atomic_load(&fake.wrong_handle) == 0U);
  if (expected < WINN_STAGE_B_FRAMEWORK_DLOPEN_FAILED) {
    CHECK(atomic_load(&fake.dlopen_calls) == 0U);
  }
  return 0;
}

static int test_paths(void) {
  char root[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  char engine[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  char manifest[WINN_STAGE_B_FRAMEWORK_MAX_PATH_BYTES];
  const char valid[] =
      "/private/var/containers/Bundle/Application/A/WCF3.app/PlugIns/"
      "PacketTunnel.appex/PacketTunnel";
  CHECK(winn_stage_b_framework_darwin_derive_paths_for_testing(
            valid, root, engine, manifest) == 1);
  CHECK(strcmp(root,
               "/private/var/containers/Bundle/Application/A/WCF3.app") == 0);
  CHECK(strcmp(engine,
               "/private/var/containers/Bundle/Application/A/WCF3.app/"
               "Frameworks/WinsAmneziaWGPacketEngine.framework/"
               "WinsAmneziaWGPacketEngine") == 0);
  CHECK(strcmp(manifest,
               "/private/var/containers/Bundle/Application/A/WCF3.app/"
               "WinnStageBEngineRuntimePin.manifest") == 0);
  CHECK(winn_stage_b_framework_darwin_derive_paths_for_testing(
            "/tmp/WCF3.app/PacketTunnel.appex/PacketTunnel",
            root, engine, manifest) == 0);
  CHECK(winn_stage_b_framework_darwin_derive_paths_for_testing(
            "/tmp/WCF3.app/Plugins/PacketTunnel.appex/PacketTunnel",
            root, engine, manifest) == 0);
  CHECK(winn_stage_b_framework_darwin_derive_paths_for_testing(
            "/tmp/WCF3.app/PlugIns/PacketTunnel.app/PacketTunnel",
            root, engine, manifest) == 0);
  CHECK(winn_stage_b_framework_darwin_derive_paths_for_testing(
            "/tmp/../WCF3.app/PlugIns/P.appex/P",
            root, engine, manifest) == 0);
  CHECK(winn_stage_b_framework_darwin_derive_paths_for_testing(
            "/tmp/WCF3.app//PlugIns/P.appex/P",
            root, engine, manifest) == 0);
  CHECK(winn_stage_b_framework_darwin_derive_paths_for_testing(
            "tmp/WCF3.app/PlugIns/P.appex/P",
            root, engine, manifest) == 0);
  return 0;
}

static int test_expected_pin(int simulator) {
  static const uint8_t device[32] = {
      0xe0, 0xe8, 0x10, 0x03, 0x9d, 0x0e, 0xd4, 0x3b,
      0x1a, 0x59, 0x9b, 0xb6, 0x43, 0x20, 0xb0, 0xee,
      0x4a, 0xb4, 0x90, 0x3c, 0xbd, 0xfd, 0x33, 0xe0,
      0x48, 0xbf, 0x0f, 0xb5, 0xe7, 0xf1, 0x16, 0xcd};
  static const uint8_t simulator_binary[32] = {
      0x00, 0xa1, 0x7d, 0xfd, 0x70, 0x2d, 0xc0, 0x49,
      0x0e, 0xfd, 0x4f, 0x39, 0xbc, 0x22, 0x59, 0xfc,
      0xc3, 0x8f, 0xa4, 0xee, 0x83, 0x11, 0x88, 0x54,
      0x99, 0xb5, 0xf1, 0x61, 0x17, 0x13, 0xfa, 0x03};
  const WinnStageBFrameworkExpected *expected =
      winn_stage_b_framework_expected();
  CHECK(memcmp(expected->source_binary_sha256,
               simulator != 0 ? simulator_binary : device,
               sizeof(device)) == 0);
  CHECK(expected->platform ==
        (simulator != 0
             ? WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONESIMULATOR
             : WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONEOS));
#if defined(__x86_64__)
  CHECK(expected->architecture == WINN_STAGE_B_FRAMEWORK_ARCH_X86_64);
#else
  CHECK(expected->architecture == WINN_STAGE_B_FRAMEWORK_ARCH_ARM64);
#endif
  return 0;
}

static int test_success(void) {
  Fake fake;
  WinnStageBFrameworkRuntimeBoundary boundary;
  const WinnStageBFrameworkImage *image = NULL;
  const WinnStageBFrameworkImage *again = NULL;
  uint8_t digest[32];
  uint8_t expected_digest[32];
  uint64_t attempt = 0U;
  int32_t handle = -1;
  char *config = NULL;
  WinnStageBFrameworkTurnOffObservation stop_observation;
  size_t index;
  initialize_fake(&fake, FAULT_NONE);
  boundary = make_boundary(&fake);
  CHECK(winn_stage_b_framework_shared_image_for_testing(&boundary, &image) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(image != NULL);
  CHECK(winn_stage_b_framework_shared_image_for_testing(&boundary, &again) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(again == image);
  CHECK(atomic_load(&fake.preflight_calls) == 1U);
  CHECK(atomic_load(&fake.dlopen_calls) == 1U);
  CHECK(atomic_load(&fake.dlsym_calls) == 6U);
  CHECK(atomic_load(&fake.postflight_calls) == 1U);
  CHECK(atomic_load(&g_contract_calls) == 1);
  for (index = 0U; index < 6U; ++index) {
    CHECK(atomic_load(&fake.symbol_counts[index]) == 1U);
  }
  fill_runtime_digest(expected_digest);
  CHECK(winn_stage_b_framework_measured_digest(image, digest) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(memcmp(digest, expected_digest, sizeof(digest)) == 0);
  CHECK(winn_stage_b_framework_begin_attempt(&attempt) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(attempt != 0U);
  CHECK(winn_stage_b_framework_turn_on(
            image, attempt, "secret-settings", 9, &handle) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(handle == 7);
  CHECK(winn_stage_b_framework_get_config(image, handle, &config) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(config == g_config);
  CHECK(winn_stage_b_framework_set_config(image, handle, "replace") ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(winn_stage_b_framework_bump_sockets(image, handle) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  memset(&stop_observation, 0xa5, sizeof(stop_observation));
  CHECK(winn_stage_b_framework_turn_off_checked(
            image, handle, &stop_observation) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(stop_observation.invocation_returned == 1U);
  CHECK(memcmp(
            stop_observation.reserved,
            (uint8_t[7]){0},
            sizeof(stop_observation.reserved)) == 0);
  memset(&stop_observation, 0xa5, sizeof(stop_observation));
  CHECK(winn_stage_b_framework_turn_off_checked(
            NULL, handle, &stop_observation) ==
        WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT);
  CHECK(stop_observation.invocation_returned == 0U);
  CHECK(winn_stage_b_framework_turn_off_checked(image, handle, NULL) ==
        WINN_STAGE_B_FRAMEWORK_INVALID_ARGUMENT);
  CHECK(atomic_load(&g_engine_overlap) == 0);
  return 0;
}

typedef struct LoadThread {
  const WinnStageBFrameworkRuntimeBoundary *boundary;
  const WinnStageBFrameworkImage *image;
  WinnStageBFrameworkStatus status;
} LoadThread;

static void *load_thread(void *context) {
  LoadThread *thread = (LoadThread *)context;
  thread->status = winn_stage_b_framework_shared_image_for_testing(
      thread->boundary, &thread->image);
  return NULL;
}

static int test_concurrency(void) {
  enum { THREADS = 24 };
  Fake fake;
  WinnStageBFrameworkRuntimeBoundary boundary;
  LoadThread state[THREADS];
  pthread_t threads[THREADS];
  int index;
  initialize_fake(&fake, FAULT_NONE);
  boundary = make_boundary(&fake);
  memset(state, 0, sizeof(state));
  for (index = 0; index < THREADS; ++index) {
    state[index].boundary = &boundary;
    CHECK(pthread_create(&threads[index], NULL, load_thread, &state[index]) ==
          0);
  }
  for (index = 0; index < THREADS; ++index) {
    CHECK(pthread_join(threads[index], NULL) == 0);
    CHECK(state[index].status == WINN_STAGE_B_FRAMEWORK_OK);
    CHECK(state[index].image != NULL);
    CHECK(state[index].image == state[0].image);
  }
  CHECK(atomic_load(&fake.preflight_calls) == 1U);
  CHECK(atomic_load(&fake.dlopen_calls) == 1U);
  CHECK(atomic_load(&fake.postflight_calls) == 1U);
  CHECK(atomic_load(&g_contract_calls) == 1);
  return 0;
}

typedef struct StartThread {
  const WinnStageBFrameworkImage *image;
  uint64_t attempt;
  WinnStageBFrameworkStatus status;
  int32_t handle;
} StartThread;

static void *start_thread(void *context) {
  StartThread *thread = (StartThread *)context;
  thread->status = winn_stage_b_framework_turn_on(
      thread->image, thread->attempt, "secret-settings", 9, &thread->handle);
  return NULL;
}

typedef struct AbandonThread {
  uint64_t attempt;
  atomic_int started;
  atomic_int done;
  WinnStageBFrameworkStatus status;
} AbandonThread;

static void *abandon_thread(void *context) {
  AbandonThread *thread = (AbandonThread *)context;
  atomic_store(&thread->started, 1);
  thread->status = winn_stage_b_framework_abandon_attempt(thread->attempt);
  atomic_store(&thread->done, 1);
  return NULL;
}

typedef struct BeginThread {
  atomic_int started;
  atomic_int done;
  WinnStageBFrameworkStatus status;
  uint64_t attempt;
} BeginThread;

static void *begin_thread(void *context) {
  BeginThread *thread = (BeginThread *)context;
  atomic_store(&thread->started, 1);
  thread->status = winn_stage_b_framework_begin_attempt(&thread->attempt);
  atomic_store(&thread->done, 1);
  return NULL;
}

static void assert_thread_has_blocked(const atomic_int *started,
                                      const atomic_int *done) {
  unsigned index;
  while (atomic_load(started) == 0) {
    atomic_signal_fence(memory_order_seq_cst);
  }
  for (index = 0U; index < 100000U; ++index) {
    atomic_signal_fence(memory_order_seq_cst);
  }
  if (atomic_load(done) != 0) {
    fprintf(stderr, "attempt transaction escaped the commit gate\n");
    abort();
  }
}

static int test_commit_abandon_linearization(void) {
  Fake fake;
  WinnStageBFrameworkRuntimeBoundary boundary;
  const WinnStageBFrameworkImage *image = NULL;
  uint64_t attempt = 0U;
  StartThread start;
  AbandonThread abandon;
  pthread_t start_worker;
  pthread_t abandon_worker;
  initialize_fake(&fake, FAULT_NONE);
  boundary = make_boundary(&fake);
  CHECK(winn_stage_b_framework_shared_image_for_testing(&boundary, &image) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(winn_stage_b_framework_begin_attempt(&attempt) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  memset(&start, 0, sizeof(start));
  start.image = image;
  start.attempt = attempt;
  start.handle = -1;
  memset(&abandon, 0, sizeof(abandon));
  abandon.attempt = attempt;
  winn_stage_b_framework_commit_pause_enable_for_testing();
  CHECK(pthread_create(&start_worker, NULL, start_thread, &start) == 0);
  while (winn_stage_b_framework_commit_pause_entered_for_testing() == 0) {
    atomic_signal_fence(memory_order_seq_cst);
  }
  CHECK(pthread_create(
            &abandon_worker, NULL, abandon_thread, &abandon) == 0);
  assert_thread_has_blocked(&abandon.started, &abandon.done);
  winn_stage_b_framework_commit_pause_release_for_testing();
  CHECK(pthread_join(start_worker, NULL) == 0);
  CHECK(pthread_join(abandon_worker, NULL) == 0);
  CHECK(start.status == WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(start.handle == 7);
  CHECK(abandon.status == WINN_STAGE_B_FRAMEWORK_ATTEMPT_STALE);
  CHECK(atomic_load(&g_turn_off_calls) == 0);
  CHECK(winn_stage_b_framework_turn_off(image, start.handle) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(atomic_load(&g_turn_off_calls) == 1);
  return 0;
}

static int test_commit_begin_linearization(void) {
  Fake fake;
  WinnStageBFrameworkRuntimeBoundary boundary;
  const WinnStageBFrameworkImage *image = NULL;
  uint64_t first_attempt = 0U;
  StartThread start;
  BeginThread begin;
  pthread_t start_worker;
  pthread_t begin_worker;
  initialize_fake(&fake, FAULT_NONE);
  boundary = make_boundary(&fake);
  CHECK(winn_stage_b_framework_shared_image_for_testing(&boundary, &image) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(winn_stage_b_framework_begin_attempt(&first_attempt) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  memset(&start, 0, sizeof(start));
  start.image = image;
  start.attempt = first_attempt;
  start.handle = -1;
  memset(&begin, 0, sizeof(begin));
  winn_stage_b_framework_commit_pause_enable_for_testing();
  CHECK(pthread_create(&start_worker, NULL, start_thread, &start) == 0);
  while (winn_stage_b_framework_commit_pause_entered_for_testing() == 0) {
    atomic_signal_fence(memory_order_seq_cst);
  }
  CHECK(pthread_create(&begin_worker, NULL, begin_thread, &begin) == 0);
  assert_thread_has_blocked(&begin.started, &begin.done);
  winn_stage_b_framework_commit_pause_release_for_testing();
  CHECK(pthread_join(start_worker, NULL) == 0);
  CHECK(pthread_join(begin_worker, NULL) == 0);
  CHECK(start.status == WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(start.handle == 7);
  CHECK(begin.status == WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(begin.attempt > first_attempt);
  CHECK(winn_stage_b_framework_current_attempt() == begin.attempt);
  CHECK(winn_stage_b_framework_turn_off(image, start.handle) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(atomic_load(&g_turn_off_calls) == 1);
  return 0;
}

static int test_late_poison_cleanup(void) {
  Fake fake;
  WinnStageBFrameworkRuntimeBoundary boundary;
  const WinnStageBFrameworkImage *image = NULL;
  uint64_t attempt = 0U;
  StartThread state;
  pthread_t thread;
  initialize_fake(&fake, FAULT_NONE);
  boundary = make_boundary(&fake);
  CHECK(winn_stage_b_framework_shared_image_for_testing(&boundary, &image) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(winn_stage_b_framework_begin_attempt(&attempt) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  memset(&state, 0, sizeof(state));
  state.image = image;
  state.attempt = attempt;
  state.handle = -1;
  g_late_mode = 1;
  CHECK(pthread_create(&thread, NULL, start_thread, &state) == 0);
  while (atomic_load(&g_late_entered) == 0) {
    atomic_signal_fence(memory_order_seq_cst);
  }
  CHECK(winn_stage_b_framework_abandon_attempt(attempt) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  atomic_store(&g_late_release, 1);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(state.status == WINN_STAGE_B_FRAMEWORK_ATTEMPT_ABANDONED);
  CHECK(state.handle == -1);
  CHECK(atomic_load(&g_turn_off_calls) == 1);
  return 0;
}

static int test_late_supersede_handle_reuse(void) {
  Fake fake;
  WinnStageBFrameworkRuntimeBoundary boundary;
  const WinnStageBFrameworkImage *image = NULL;
  uint64_t first_attempt = 0U;
  uint64_t second_attempt = 0U;
  StartThread first;
  pthread_t worker;
  int32_t reused_handle = -1;
  initialize_fake(&fake, FAULT_NONE);
  boundary = make_boundary(&fake);
  CHECK(winn_stage_b_framework_shared_image_for_testing(&boundary, &image) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(winn_stage_b_framework_begin_attempt(&first_attempt) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  memset(&first, 0, sizeof(first));
  first.image = image;
  first.attempt = first_attempt;
  first.handle = -1;
  g_late_mode = 1;
  CHECK(pthread_create(&worker, NULL, start_thread, &first) == 0);
  while (atomic_load(&g_late_entered) == 0) {
    atomic_signal_fence(memory_order_seq_cst);
  }
  CHECK(winn_stage_b_framework_begin_attempt(&second_attempt) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(second_attempt > first_attempt);
  atomic_store(&g_late_release, 1);
  CHECK(pthread_join(worker, NULL) == 0);
  CHECK(first.status == WINN_STAGE_B_FRAMEWORK_ATTEMPT_ABANDONED);
  CHECK(first.handle == -1);
  CHECK(atomic_load(&g_turn_off_calls) == 1);
  CHECK(winn_stage_b_framework_abandon_attempt(first_attempt) ==
        WINN_STAGE_B_FRAMEWORK_ATTEMPT_STALE);
  CHECK(atomic_load(&g_turn_off_calls) == 1);
  g_late_mode = 0;
  CHECK(winn_stage_b_framework_turn_on(
            image, second_attempt, "secret-settings", 9, &reused_handle) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(reused_handle == 7);
  CHECK(atomic_load(&g_turn_off_calls) == 1);
  CHECK(winn_stage_b_framework_turn_off(image, reused_handle) ==
        WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(atomic_load(&g_turn_off_calls) == 2);
  return 0;
}

static int test_permanent_failure(void) {
  Fake fake;
  WinnStageBFrameworkRuntimeBoundary boundary;
  const WinnStageBFrameworkImage *image = NULL;
  initialize_fake(&fake, FAULT_REBIND_HASH);
  boundary = make_boundary(&fake);
  CHECK(winn_stage_b_framework_shared_image_for_testing(&boundary, &image) ==
        WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND);
  CHECK(winn_stage_b_framework_shared_image_for_testing(&boundary, &image) ==
        WINN_STAGE_B_FRAMEWORK_PERMANENTLY_FAILED);
  CHECK(image == NULL);
  CHECK(atomic_load(&fake.preflight_calls) == 1U);
  CHECK(atomic_load(&fake.dlopen_calls) == 1U);
  CHECK(atomic_load(&fake.postflight_calls) == 1U);
  CHECK(atomic_load(&g_contract_calls) == 0);
  return 0;
}

static int test_concurrent_permanent_failure(void) {
  enum { THREADS = 24 };
  Fake fake;
  WinnStageBFrameworkRuntimeBoundary boundary;
  LoadThread state[THREADS];
  pthread_t threads[THREADS];
  int first_failures = 0;
  int permanent_failures = 0;
  int index;
  initialize_fake(&fake, FAULT_REBIND_HASH);
  boundary = make_boundary(&fake);
  memset(state, 0, sizeof(state));
  for (index = 0; index < THREADS; ++index) {
    state[index].boundary = &boundary;
    CHECK(pthread_create(&threads[index], NULL, load_thread, &state[index]) ==
          0);
  }
  for (index = 0; index < THREADS; ++index) {
    CHECK(pthread_join(threads[index], NULL) == 0);
    CHECK(state[index].image == NULL);
    if (state[index].status == WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND) {
      ++first_failures;
    } else if (state[index].status ==
               WINN_STAGE_B_FRAMEWORK_PERMANENTLY_FAILED) {
      ++permanent_failures;
    } else {
      CHECK(0);
    }
  }
  CHECK(first_failures == 1);
  CHECK(permanent_failures == THREADS - 1);
  CHECK(atomic_load(&fake.preflight_calls) == 1U);
  CHECK(atomic_load(&fake.dlopen_calls) == 1U);
  CHECK(atomic_load(&fake.postflight_calls) == 1U);
  CHECK(atomic_load(&g_contract_calls) == 0);
  return 0;
}

static int test_boundary_change(void) {
  Fake first;
  Fake second;
  WinnStageBFrameworkRuntimeBoundary first_boundary;
  WinnStageBFrameworkRuntimeBoundary second_boundary;
  const WinnStageBFrameworkImage *image = NULL;
  initialize_fake(&first, FAULT_NONE);
  initialize_fake(&second, FAULT_NONE);
  first_boundary = make_boundary(&first);
  second_boundary = make_boundary(&second);
  CHECK(winn_stage_b_framework_shared_image_for_testing(
            &first_boundary, &image) == WINN_STAGE_B_FRAMEWORK_OK);
  CHECK(winn_stage_b_framework_shared_image_for_testing(
            &second_boundary, &image) == WINN_STAGE_B_FRAMEWORK_BOUNDARY_CHANGED);
  return 0;
}

static int test_darwin_preflight(const char *provider, int should_succeed) {
  WinnStageBFrameworkPreflight output;
  const WinnStageBFrameworkExpected *expected =
      winn_stage_b_framework_expected();
  int result;
  memset(&output, 0, sizeof(output));
  winn_stage_b_framework_darwin_reset_for_testing();
  result = winn_stage_b_framework_darwin_preflight_for_testing(
      provider, expected, &output);
  if (should_succeed != 0) {
    CHECK(result == 1);
    CHECK(strcmp(output.canonical_path, kCanonicalPath) != 0);
    CHECK(memcmp(output.source_binary_sha256,
                 expected->source_binary_sha256,
                 sizeof(output.source_binary_sha256)) == 0);
    CHECK(output.manifest_strictly_parsed == 1U);
    CHECK(output.descriptor_relative_nofollow == 1U);
    CHECK(output.macho_contract_valid == 1U);
    CHECK(output.platform_loader_gate_expected == 1U);
    CHECK(output.link_count == 1U);
    CHECK(output.retained_file_token != 0U);
  } else {
    CHECK(result == 0);
  }
  winn_stage_b_framework_darwin_reset_for_testing();
  return 0;
}

static int test_darwin_macho(
    const char *path,
    const char *platform,
    const char *architecture,
    int should_succeed) {
  WinnStageBFrameworkExpected expected;
  int result;
  memset(&expected, 0, sizeof(expected));
  if (strcmp(platform, "iphoneos") == 0) {
    expected.platform = WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONEOS;
  } else if (strcmp(platform, "iphonesimulator") == 0) {
    expected.platform = WINN_STAGE_B_FRAMEWORK_PLATFORM_IPHONESIMULATOR;
  } else {
    return 2;
  }
  if (strcmp(architecture, "arm64") == 0) {
    expected.architecture = WINN_STAGE_B_FRAMEWORK_ARCH_ARM64;
  } else if (strcmp(architecture, "x86_64") == 0) {
    expected.architecture = WINN_STAGE_B_FRAMEWORK_ARCH_X86_64;
  } else {
    return 2;
  }
  result = winn_stage_b_framework_darwin_macho_for_testing(path, &expected);
  CHECK(result == should_succeed);
  return 0;
}

static int parse_fault(const char *name, Fault *fault,
                       WinnStageBFrameworkStatus *status) {
  struct Mapping {
    const char *name;
    Fault fault;
    WinnStageBFrameworkStatus status;
  };
  static const struct Mapping mappings[] = {
      {"preflight", FAULT_PREFLIGHT_CALL, WINN_STAGE_B_FRAMEWORK_PREFLIGHT_FAILED},
      {"path", FAULT_PATH, WINN_STAGE_B_FRAMEWORK_INVALID_PATH},
      {"source", FAULT_SOURCE, WINN_STAGE_B_FRAMEWORK_INVALID_SOURCE_PIN},
      {"runtime-zero", FAULT_RUNTIME_ZERO,
       WINN_STAGE_B_FRAMEWORK_INVALID_RUNTIME_PIN},
      {"runtime-equals-source", FAULT_RUNTIME_EQUALS_SOURCE,
       WINN_STAGE_B_FRAMEWORK_DIGEST_CONFLATED},
      {"identity", FAULT_IDENTITY,
       WINN_STAGE_B_FRAMEWORK_INVALID_FILE_IDENTITY},
      {"manifest", FAULT_MANIFEST, WINN_STAGE_B_FRAMEWORK_INVALID_PREFLIGHT},
      {"nofollow", FAULT_NOFOLLOW, WINN_STAGE_B_FRAMEWORK_INVALID_PREFLIGHT},
      {"loader-gate", FAULT_LOADER_GATE,
       WINN_STAGE_B_FRAMEWORK_INVALID_PREFLIGHT},
      {"preflight-reserved", FAULT_PREFLIGHT_RESERVED,
       WINN_STAGE_B_FRAMEWORK_INVALID_PREFLIGHT},
      {"platform", FAULT_PLATFORM, WINN_STAGE_B_FRAMEWORK_INVALID_MACHO},
      {"architecture", FAULT_ARCHITECTURE, WINN_STAGE_B_FRAMEWORK_INVALID_MACHO},
      {"macho", FAULT_MACHO, WINN_STAGE_B_FRAMEWORK_INVALID_MACHO},
      {"dlopen", FAULT_DLOPEN, WINN_STAGE_B_FRAMEWORK_DLOPEN_FAILED},
      {"symbol", FAULT_SYMBOL, WINN_STAGE_B_FRAMEWORK_SYMBOL_MISSING},
      {"postflight", FAULT_POSTFLIGHT_CALL,
       WINN_STAGE_B_FRAMEWORK_POSTFLIGHT_FAILED},
      {"symbol-image", FAULT_SYMBOL_IMAGE,
       WINN_STAGE_B_FRAMEWORK_SYMBOL_IMAGE_MISMATCH},
      {"post-path", FAULT_POST_PATH,
       WINN_STAGE_B_FRAMEWORK_SYMBOL_IMAGE_MISMATCH},
      {"post-retained", FAULT_POST_RETAINED,
       WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND},
      {"post-macho", FAULT_POST_MACHO,
       WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND},
      {"post-reserved", FAULT_POST_RESERVED,
       WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND},
      {"rebind-hash", FAULT_REBIND_HASH, WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND},
      {"rebind-inode", FAULT_REBIND_INODE,
       WINN_STAGE_B_FRAMEWORK_RUNTIME_REBOUND},
      {"contract", FAULT_CONTRACT,
       WINN_STAGE_B_FRAMEWORK_CONTRACT_VERSION_MISMATCH}};
  size_t index;
  for (index = 0U; index < sizeof(mappings) / sizeof(mappings[0]); ++index) {
    if (strcmp(name, mappings[index].name) == 0) {
      *fault = mappings[index].fault;
      *status = mappings[index].status;
      return 1;
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  Fault fault;
  WinnStageBFrameworkStatus status;
  if (argc == 4 && strcmp(argv[1], "darwin-preflight") == 0) {
    return test_darwin_preflight(argv[2], strcmp(argv[3], "ok") == 0);
  }
  if (argc == 6 && strcmp(argv[1], "darwin-macho") == 0) {
    return test_darwin_macho(
        argv[2], argv[3], argv[4], strcmp(argv[5], "ok") == 0);
  }
  if (argc != 2) {
    fprintf(stderr, "usage: %s CASE\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "paths") == 0) {
    return test_paths();
  }
  if (strcmp(argv[1], "expected-device") == 0) {
    return test_expected_pin(0);
  }
  if (strcmp(argv[1], "expected-simulator") == 0) {
    return test_expected_pin(1);
  }
  if (strcmp(argv[1], "success") == 0) {
    return test_success();
  }
  if (strcmp(argv[1], "concurrency") == 0) {
    return test_concurrency();
  }
  if (strcmp(argv[1], "late-cleanup") == 0) {
    return test_late_poison_cleanup();
  }
  if (strcmp(argv[1], "commit-abandon") == 0) {
    return test_commit_abandon_linearization();
  }
  if (strcmp(argv[1], "commit-begin") == 0) {
    return test_commit_begin_linearization();
  }
  if (strcmp(argv[1], "late-supersede-reuse") == 0) {
    return test_late_supersede_handle_reuse();
  }
  if (strcmp(argv[1], "permanent-failure") == 0) {
    return test_permanent_failure();
  }
  if (strcmp(argv[1], "concurrent-permanent-failure") == 0) {
    return test_concurrent_permanent_failure();
  }
  if (strcmp(argv[1], "boundary-change") == 0) {
    return test_boundary_change();
  }
  if (parse_fault(argv[1], &fault, &status) != 0) {
    return assert_load_fault(fault, status);
  }
  fprintf(stderr, "unknown case: %s\n", argv[1]);
  return 2;
}
