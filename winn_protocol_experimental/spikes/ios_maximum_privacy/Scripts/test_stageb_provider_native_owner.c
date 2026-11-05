#include "WinnStageBProviderNativeOwnerInternal.h"

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct FakeContext {
  atomic_int start_entered;
  atomic_int allow_start_return;
  atomic_int capture_entered;
  atomic_int allow_capture_return;
  atomic_int stop_entered;
  atomic_int allow_stop_return;
  int block_start;
  int block_capture;
  int block_stop;
  int retain_owner_allocation;
  void *retained_owner_allocation;
  size_t retained_owner_allocation_size;
  int owner_allocate_calls;
  int owner_release_calls;
  int load_calls;
  int begin_calls;
  int abandon_calls;
  int create_calls;
  int start_calls;
  int capture_calls;
  int stop_calls;
  int record_calls;
  int destroy_calls;
  int release_calls;
  int release_saw_zero;
  int reentrant_release;
  WinnStageBProviderNativeStatus reentrant_status;
  WinnStageBProviderNativeOwner *reentrant_owner;
  WinnStageBProviderNativeStatus begin_status;
  WinnStageBProviderNativeStatus abandon_status;
  WinnStageBProviderNativeStatus create_status;
  WinnStageBProviderNativeStatus start_status;
  WinnStageBProviderNativeStatus capture_status;
  WinnStageBProviderNativeStatus record_status;
  WinnStageBFrameworkStatus stop_status;
  uint8_t stop_returned;
  uint8_t action_called;
  int record_callback_handle;
  int32_t callback_handle;
  int32_t handle;
} FakeContext;

typedef struct StartThread {
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeStart start;
  WinnStageBProviderNativeStartResult result;
  WinnStageBProviderNativeStatus status;
} StartThread;

typedef struct CaptureThread {
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeGeneration generation;
  WinnStageBProviderNativeCapture capture;
  WinnStageBProviderNativeStatus status;
} CaptureThread;

typedef struct StopThread {
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeGeneration generation;
  int32_t handle;
  WinnStageBProviderNativeStopResult result;
  WinnStageBProviderNativeStatus status;
} StopThread;

typedef struct DestroyThread {
  WinnStageBProviderNativeOwner owner;
  atomic_int *ready;
  atomic_int *go;
  WinnStageBProviderNativeStatus status;
} DestroyThread;

static void fill_bytes(uint8_t *bytes, size_t count, uint8_t seed) {
  size_t index;
  for (index = 0U; index < count; ++index) {
    bytes[index] = (uint8_t)(seed + (uint8_t)index);
  }
}

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

static WinnStageBProviderNativeGeneration generation(uint64_t sequence) {
  WinnStageBProviderNativeGeneration value;
  memset(&value, 0, sizeof(value));
  fill_bytes(value.attempt_nonce, sizeof(value.attempt_nonce), 1U);
  value.attempt_nonce[6] =
      (uint8_t)((value.attempt_nonce[6] & 0x0fU) | 0x40U);
  value.attempt_nonce[8] =
      (uint8_t)((value.attempt_nonce[8] & 0x3fU) | 0x80U);
  value.lifecycle_sequence = sequence;
  return value;
}

static void erase_and_release(
    uint8_t *bytes,
    size_t allocation_size,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  size_t index;
  fake->release_saw_zero = 1;
  for (index = 0U; index < allocation_size; ++index) {
    if (bytes[index] != 0U) {
      fake->release_saw_zero = 0;
    }
  }
  ++fake->release_calls;
  if (fake->reentrant_release != 0) {
    WinnStageBProviderNativeState state;
    fake->reentrant_status =
        winn_stage_b_provider_native_owner_state(
            fake->reentrant_owner, &state);
  }
  free(bytes);
}

static WinnStageBProviderNativeStart make_start(
    FakeContext *fake,
    uint64_t sequence) {
  static const uint8_t config[] =
      "private_key=redacted\npublic_key=peer\n";
  WinnStageBProviderNativeStart start;
  uint8_t *allocation = (uint8_t *)malloc(sizeof(config));
  assert(allocation != NULL);
  memcpy(allocation, config, sizeof(config));
  memset(&start, 0, sizeof(start));
  start.generation = generation(sequence);
  start.config.bytes = allocation;
  start.config.allocation_size = sizeof(config);
  start.config.buffer_length = sizeof(config);
  start.config.erase_and_release = erase_and_release;
  start.config.release_context = fake;
  fill_bytes(start.config_sha256, sizeof(start.config_sha256), 9U);
  fill_bytes(
      start.expected_peer_public_key,
      sizeof(start.expected_peer_public_key),
      41U);
  start.engine_generation = sequence + 10U;
  start.path_generation = sequence + 20U;
  return start;
}

static void initialize_fake(FakeContext *fake) {
  memset(fake, 0, sizeof(*fake));
  atomic_init(&fake->start_entered, 0);
  atomic_init(&fake->allow_start_return, 0);
  atomic_init(&fake->capture_entered, 0);
  atomic_init(&fake->allow_capture_return, 0);
  atomic_init(&fake->stop_entered, 0);
  atomic_init(&fake->allow_stop_return, 0);
  fake->begin_status = WINN_STAGE_B_PROVIDER_NATIVE_OK;
  fake->abandon_status = WINN_STAGE_B_PROVIDER_NATIVE_OK;
  fake->create_status = WINN_STAGE_B_PROVIDER_NATIVE_OK;
  fake->start_status = WINN_STAGE_B_PROVIDER_NATIVE_OK;
  fake->capture_status = WINN_STAGE_B_PROVIDER_NATIVE_OK;
  fake->record_status = WINN_STAGE_B_PROVIDER_NATIVE_OK;
  fake->stop_status = WINN_STAGE_B_FRAMEWORK_OK;
  fake->stop_returned = 1U;
  fake->action_called = 1U;
  fake->record_callback_handle = 1;
  fake->callback_handle = 73;
  fake->handle = 73;
}

static void *fake_allocate_owner(
    size_t allocation_size,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  void *allocation;
  ++fake->owner_allocate_calls;
  if (fake->retained_owner_allocation != NULL) {
    assert(fake->retained_owner_allocation_size == allocation_size);
    allocation = fake->retained_owner_allocation;
    fake->retained_owner_allocation = NULL;
    fake->retained_owner_allocation_size = 0U;
    memset(allocation, 0, allocation_size);
    return allocation;
  }
  return calloc(1U, allocation_size);
}

static void fake_release_owner(
    void *allocation,
    size_t allocation_size,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  ++fake->owner_release_calls;
  if (fake->retain_owner_allocation != 0) {
    assert(fake->retained_owner_allocation == NULL);
    fake->retained_owner_allocation = allocation;
    fake->retained_owner_allocation_size = allocation_size;
  } else {
    free(allocation);
  }
}

static WinnStageBProviderNativeStatus fake_load(
    const void **output_image,
    uint8_t output_runtime_sha256[32],
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  ++fake->load_calls;
  *output_image = fake;
  fill_bytes(output_runtime_sha256, 32U, 51U);
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

static WinnStageBProviderNativeStatus fake_begin(
    uint64_t *output_attempt_id,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  ++fake->begin_calls;
  *output_attempt_id = (uint64_t)fake->begin_calls;
  return fake->begin_status;
}

static WinnStageBProviderNativeStatus fake_abandon(
    uint64_t attempt_id,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  assert(attempt_id != 0U);
  ++fake->abandon_calls;
  return fake->abandon_status;
}

static WinnStageBProviderNativeStatus fake_create_engine(
    void *owner_context,
    void **output_engine,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  (void)owner_context;
  ++fake->create_calls;
  if (fake->create_status == WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    *output_engine = fake;
  }
  return fake->create_status;
}

static WinnStageBProviderNativeStatus fake_start_pinned(
    void *owner_context,
    void *engine,
    const WinnStageBProviderNativeStart *start,
    WinnStageBNativeIdentity *output_identity,
    int32_t *output_handle,
    uint8_t *output_action_was_called,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  (void)owner_context;
  assert(engine == fake);
  assert(start->config.bytes != NULL);
  assert(start->config.buffer_length == start->config.allocation_size);
  assert(start->config.bytes[start->config.buffer_length - 1U] == 0U);
  ++fake->start_calls;
  atomic_store_explicit(
      &fake->start_entered, 1, memory_order_release);
  while (fake->block_start != 0 &&
         atomic_load_explicit(
             &fake->allow_start_return, memory_order_acquire) == 0) {
  }
  memset(output_identity, 0, sizeof(*output_identity));
  output_identity->engine_instance_uuid[6] = 0x40U;
  output_identity->engine_instance_uuid[8] = 0x80U;
  fill_bytes(
      output_identity->winning_interface_token_sha256, 32U, 71U);
  memcpy(
      output_identity->expected_peer_sha256,
      start->expected_peer_public_key,
      32U);
  memcpy(output_identity->config_sha256, start->config_sha256, 32U);
  output_identity->engine_generation = start->engine_generation;
  output_identity->path_generation = start->path_generation;
  *output_handle = fake->handle;
  *output_action_was_called = fake->action_called;
  if (fake->record_callback_handle != 0) {
    winn_stage_b_provider_native_owner_record_callback_for_testing(
        owner_context, fake->callback_handle);
  }
  return fake->start_status;
}

static WinnStageBProviderNativeStatus fake_capture(
    void *engine,
    WinnStageBNativeObservation *output_observation,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  assert(engine == fake);
  ++fake->capture_calls;
  atomic_store_explicit(
      &fake->capture_entered, 1, memory_order_release);
  while (fake->block_capture != 0 &&
         atomic_load_explicit(
             &fake->allow_capture_return, memory_order_acquire) == 0) {
  }
  memset(output_observation, 0, sizeof(*output_observation));
  output_observation->identity.engine_generation =
      (uint64_t)fake->capture_calls;
  return fake->capture_status;
}

static WinnStageBFrameworkStatus fake_stop(
    const void *image,
    int32_t handle,
    WinnStageBFrameworkTurnOffObservation *output_observation,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  assert(image == fake);
  assert(handle == fake->handle);
  ++fake->stop_calls;
  atomic_store_explicit(
      &fake->stop_entered, 1, memory_order_release);
  while (fake->block_stop != 0 &&
         atomic_load_explicit(
             &fake->allow_stop_return, memory_order_acquire) == 0) {
  }
  memset(output_observation, 0, sizeof(*output_observation));
  output_observation->invocation_returned = fake->stop_returned;
  return fake->stop_status;
}

static WinnStageBProviderNativeStatus fake_record(
    void *engine,
    int32_t handle,
    void *context) {
  FakeContext *fake = (FakeContext *)context;
  assert(engine == fake);
  assert(handle == fake->handle);
  ++fake->record_calls;
  return fake->record_status;
}

static void fake_destroy(void **engine, void *context) {
  FakeContext *fake = (FakeContext *)context;
  assert(*engine == fake);
  ++fake->destroy_calls;
  *engine = NULL;
}

static WinnStageBProviderNativeOwnerDependencies dependencies_for(
    FakeContext *fake) {
  WinnStageBProviderNativeOwnerDependencies dependencies;
  memset(&dependencies, 0, sizeof(dependencies));
  dependencies.allocate_owner = fake_allocate_owner;
  dependencies.release_owner = fake_release_owner;
  dependencies.load_framework = fake_load;
  dependencies.begin_attempt = fake_begin;
  dependencies.abandon_attempt = fake_abandon;
  dependencies.create_engine = fake_create_engine;
  dependencies.start_pinned = fake_start_pinned;
  dependencies.capture = fake_capture;
  dependencies.turn_off_checked = fake_stop;
  dependencies.record_external_stop = fake_record;
  dependencies.destroy_engine = fake_destroy;
  dependencies.context = fake;
  return dependencies;
}

static WinnStageBProviderNativeOwner *create_owner(FakeContext *fake) {
  static unsigned create_sequence;
  WinnStageBProviderNativeOwnerDependencies dependencies =
      dependencies_for(fake);
  WinnStageBProviderNativeOwner *owner =
      (WinnStageBProviderNativeOwner *)calloc(1U, sizeof(*owner));
  WinnStageBProviderNativeStatus status;
  assert(owner != NULL);
  status = winn_stage_b_provider_native_owner_create_for_testing(
      &dependencies, owner);
  ++create_sequence;
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    fprintf(
        stderr,
        "create_owner sequence=%u status=%d\n",
        create_sequence,
        (int)status);
  }
  assert(status == WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(owner->storage_address != (uintptr_t)0);
  assert(owner->lifecycle_token != 0U);
  return owner;
}

static WinnStageBProviderNativeStatus destroy_owner(
    WinnStageBProviderNativeOwner **owner_pointer) {
  WinnStageBProviderNativeStatus status;
  assert(owner_pointer != NULL);
  assert(*owner_pointer != NULL);
  status = winn_stage_b_provider_native_owner_destroy(*owner_pointer);
  if (status == WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    assert((*owner_pointer)->storage_address == (uintptr_t)0);
    assert((*owner_pointer)->lifecycle_token == 0U);
    free(*owner_pointer);
    *owner_pointer = NULL;
  }
  return status;
}

static WinnStageBProviderNativeStartResult start_owner(
    WinnStageBProviderNativeOwner *owner,
    FakeContext *fake,
    uint64_t sequence) {
  int release_calls_before = fake->release_calls;
  WinnStageBProviderNativeStart start = make_start(fake, sequence);
  WinnStageBProviderNativeStartResult result;
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(start.config.bytes == NULL);
  assert(fake->release_calls == release_calls_before + 1);
  assert(fake->release_saw_zero == 1);
  assert(result.lifecycle_handle == fake->handle);
  return result;
}

static void stop_owner(
    WinnStageBProviderNativeOwner *owner,
    const WinnStageBProviderNativeGeneration *value,
    int32_t handle) {
  WinnStageBProviderNativeStopResult result;
  assert(winn_stage_b_provider_native_owner_stop(
             owner, value, handle, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(result.invocation ==
         WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED);
  assert(result.lifecycle_acknowledgement_permitted == 1U);
  assert(result.owner_poisoned_after_invocation == 0U);
}

static void test_success_and_validation(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeStartResult result;
  WinnStageBProviderNativeCapture capture;
  WinnStageBProviderNativeStopResult stop;
  WinnStageBProviderNativeGeneration expected = generation(1U);
  WinnStageBProviderNativeGeneration wrong = generation(2U);
  unsigned index;
  initialize_fake(&fake);
  owner = create_owner(&fake);
  result = start_owner(owner, &fake, 1U);
  assert(fake.begin_calls == 1);
  assert(fake.start_calls == 1);
  for (index = 1U; index <= 7U; ++index) {
    memset(&capture, 0xff, sizeof(capture));
    assert(winn_stage_b_provider_native_owner_capture(
               owner, &expected, &capture) ==
           WINN_STAGE_B_PROVIDER_NATIVE_OK);
    assert(capture.capture_ordinal == (uint64_t)index);
  }
  memset(&capture, 0xff, sizeof(capture));
  assert(winn_stage_b_provider_native_owner_capture(
             owner, &wrong, &capture) ==
         WINN_STAGE_B_PROVIDER_NATIVE_GENERATION_MISMATCH);
  assert(capture.capture_ordinal == 0U);
  memset(&stop, 0xff, sizeof(stop));
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &wrong, result.lifecycle_handle, &stop) ==
         WINN_STAGE_B_PROVIDER_NATIVE_GENERATION_MISMATCH);
  assert(stop.invocation == WINN_STAGE_B_PROVIDER_STOP_NOT_INVOKED);
  assert(stop.lifecycle_handle == -1);
  memset(&stop, 0xff, sizeof(stop));
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &expected, result.lifecycle_handle + 1, &stop) ==
         WINN_STAGE_B_PROVIDER_NATIVE_HANDLE_MISMATCH);
  assert(stop.invocation == WINN_STAGE_B_PROVIDER_STOP_NOT_INVOKED);
  assert(fake.stop_calls == 0);
  stop_owner(owner, &expected, result.lifecycle_handle);
  assert(fake.stop_calls == 1);
  assert(fake.record_calls == 1);
  assert(fake.destroy_calls == 1);
  assert(destroy_owner(&owner) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

static void test_retryable_stop(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeStartResult start_result;
  WinnStageBProviderNativeStopResult stop;
  WinnStageBProviderNativeState state;
  WinnStageBProviderNativeGeneration expected = generation(3U);
  initialize_fake(&fake);
  owner = create_owner(&fake);
  start_result = start_owner(owner, &fake, 3U);
  fake.stop_returned = 0U;
  fake.stop_status = WINN_STAGE_B_FRAMEWORK_LOCK_FAILED;
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &expected, start_result.lifecycle_handle, &stop) ==
         WINN_STAGE_B_PROVIDER_NATIVE_STOP_NOT_INVOKED);
  assert(stop.invocation == WINN_STAGE_B_PROVIDER_STOP_NOT_INVOKED);
  assert(stop.lifecycle_acknowledgement_permitted == 0U);
  assert(fake.record_calls == 0);
  assert(winn_stage_b_provider_native_owner_state(owner, &state) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(state ==
         WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOP_PENDING_NOT_INVOKED);
  fake.stop_returned = 1U;
  fake.stop_status = WINN_STAGE_B_FRAMEWORK_OK;
  stop_owner(owner, &expected, start_result.lifecycle_handle);
  assert(fake.stop_calls == 2);
  assert(destroy_owner(&owner) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

static void test_poison_after_return(void) {
  FakeContext fake;
  FakeContext second_fake;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeOwner *second;
  WinnStageBProviderNativeStartResult result;
  WinnStageBProviderNativeStart second_start;
  WinnStageBProviderNativeStartResult second_result;
  WinnStageBProviderNativeStopResult stop;
  WinnStageBProviderNativeState state;
  WinnStageBProviderNativeGeneration expected = generation(4U);
  initialize_fake(&fake);
  owner = create_owner(&fake);
  result = start_owner(owner, &fake, 4U);
  fake.stop_status = WINN_STAGE_B_FRAMEWORK_LOCK_FAILED;
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &expected, result.lifecycle_handle, &stop) ==
         WINN_STAGE_B_PROVIDER_NATIVE_POISONED);
  assert(stop.invocation ==
         WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED);
  assert(stop.lifecycle_acknowledgement_permitted == 1U);
  assert(stop.owner_poisoned_after_invocation == 1U);
  assert(fake.record_calls == 1);
  assert(winn_stage_b_provider_native_owner_state(owner, &state) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(state ==
         WINN_STAGE_B_PROVIDER_NATIVE_STATE_POISONED_AFTER_STOP_INVOCATION);
  assert(destroy_owner(&owner) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);

  initialize_fake(&second_fake);
  second = create_owner(&second_fake);
  second_start = make_start(&second_fake, 5U);
  assert(winn_stage_b_provider_native_owner_start(
             second, &second_start, &second_result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_POISONED);
  assert(second_fake.release_calls == 1);
  assert(destroy_owner(&second) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(winn_stage_b_provider_native_owner_reset_registry_for_testing() ==
         1);
}

static void *start_thread_main(void *context) {
  StartThread *thread = (StartThread *)context;
  thread->status = winn_stage_b_provider_native_owner_start(
      thread->owner, &thread->start, &thread->result);
  return NULL;
}

static void *capture_thread_main(void *context) {
  CaptureThread *thread = (CaptureThread *)context;
  thread->status = winn_stage_b_provider_native_owner_capture(
      thread->owner, &thread->generation, &thread->capture);
  return NULL;
}

static void *stop_thread_main(void *context) {
  StopThread *thread = (StopThread *)context;
  thread->status = winn_stage_b_provider_native_owner_stop(
      thread->owner,
      &thread->generation,
      thread->handle,
      &thread->result);
  return NULL;
}

static void *destroy_thread_main(void *context) {
  DestroyThread *thread = (DestroyThread *)context;
  atomic_fetch_add_explicit(thread->ready, 1, memory_order_release);
  while (atomic_load_explicit(thread->go, memory_order_acquire) == 0) {
  }
  thread->status =
      winn_stage_b_provider_native_owner_destroy(&thread->owner);
  return NULL;
}

static void test_concurrent_abandon(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwner *owner;
  StartThread start_thread;
  pthread_t thread;
  WinnStageBProviderNativeGeneration expected = generation(6U);
  initialize_fake(&fake);
  fake.block_start = 1;
  owner = create_owner(&fake);
  memset(&start_thread, 0, sizeof(start_thread));
  start_thread.owner = owner;
  start_thread.start = make_start(&fake, 6U);
  assert(pthread_create(
             &thread, NULL, start_thread_main, &start_thread) == 0);
  while (atomic_load_explicit(
             &fake.start_entered, memory_order_acquire) == 0) {
  }
  assert(winn_stage_b_provider_native_owner_abandon(
             owner, &expected) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  atomic_store_explicit(
      &fake.allow_start_return, 1, memory_order_release);
  assert(pthread_join(thread, NULL) == 0);
  assert(start_thread.status == WINN_STAGE_B_PROVIDER_NATIVE_ABANDONED);
  assert(fake.stop_calls == 1);
  assert(fake.record_calls == 1);
  assert(fake.destroy_calls == 1);
  assert(fake.abandon_calls >= 1);
  assert(destroy_owner(&owner) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

static void test_single_active_and_reentrancy(void) {
  FakeContext first_fake;
  FakeContext second_fake;
  WinnStageBProviderNativeOwner *first;
  WinnStageBProviderNativeOwner *second;
  WinnStageBProviderNativeStartResult result;
  WinnStageBProviderNativeStart same_owner_rejected;
  WinnStageBProviderNativeStartResult same_owner_rejected_result;
  WinnStageBProviderNativeStart rejected;
  WinnStageBProviderNativeStartResult rejected_result;
  WinnStageBProviderNativeGeneration expected = generation(7U);
  initialize_fake(&first_fake);
  initialize_fake(&second_fake);
  first = create_owner(&first_fake);
  second = create_owner(&second_fake);
  result = start_owner(first, &first_fake, 7U);
  same_owner_rejected = make_start(&first_fake, 11U);
  assert(winn_stage_b_provider_native_owner_start(
             first,
             &same_owner_rejected,
             &same_owner_rejected_result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_BUSY);
  assert(first_fake.release_calls == 2);
  rejected = make_start(&second_fake, 8U);
  second_fake.reentrant_release = 1;
  second_fake.reentrant_owner = second;
  assert(winn_stage_b_provider_native_owner_start(
             second, &rejected, &rejected_result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_BUSY);
  assert(second_fake.release_calls == 1);
  assert(second_fake.reentrant_status ==
         WINN_STAGE_B_PROVIDER_NATIVE_REENTRANT);
  stop_owner(first, &expected, result.lifecycle_handle);
  assert(destroy_owner(&first) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  result = start_owner(second, &second_fake, 9U);
  expected = generation(9U);
  stop_owner(second, &expected, result.lifecycle_handle);
  assert(destroy_owner(&second) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

static void test_start_failure_cleanup(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeStart start;
  WinnStageBProviderNativeStartResult result;
  initialize_fake(&fake);
  fake.start_status = WINN_STAGE_B_PROVIDER_NATIVE_UTUN_FAILED;
  owner = create_owner(&fake);
  start = make_start(&fake, 10U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_UTUN_FAILED);
  assert(result.lifecycle_handle == -1);
  assert(fake.release_calls == 1);
  assert(fake.stop_calls == 1);
  assert(fake.record_calls == 1);
  assert(fake.destroy_calls == 1);
  assert(destroy_owner(&owner) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

static void test_start_failure_exposes_retryable_stop_handle(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeStart start;
  WinnStageBProviderNativeStartResult result;
  WinnStageBProviderNativeStopResult stop;
  WinnStageBProviderNativeState state;
  WinnStageBProviderNativeGeneration expected = generation(12U);
  initialize_fake(&fake);
  fake.start_status = WINN_STAGE_B_PROVIDER_NATIVE_UTUN_FAILED;
  fake.stop_returned = 0U;
  fake.stop_status = WINN_STAGE_B_FRAMEWORK_LOCK_FAILED;
  owner = create_owner(&fake);
  start = make_start(&fake, 12U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_STOP_NOT_INVOKED);
  assert(result.lifecycle_handle == fake.handle);
  assert(fake.stop_calls == 1);
  assert(fake.record_calls == 0);
  assert(fake.destroy_calls == 0);
  assert(winn_stage_b_provider_native_owner_state(owner, &state) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(state ==
         WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOP_PENDING_NOT_INVOKED);

  fake.stop_returned = 1U;
  fake.stop_status = WINN_STAGE_B_FRAMEWORK_OK;
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &expected, result.lifecycle_handle, &stop) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(stop.invocation ==
         WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED);
  assert(fake.stop_calls == 2);
  assert(fake.record_calls == 1);
  assert(fake.destroy_calls == 1);
  assert(destroy_owner(&owner) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

static void test_capture_failure_ordinal_and_capture_stop(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeStartResult start_result;
  WinnStageBProviderNativeCapture capture;
  WinnStageBProviderNativeStopResult stop;
  WinnStageBProviderNativeGeneration expected = generation(20U);
  CaptureThread capture_thread;
  pthread_t thread;
  initialize_fake(&fake);
  owner = create_owner(&fake);
  start_result = start_owner(owner, &fake, 20U);

  fake.capture_status = WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
  memset(&capture, 0xff, sizeof(capture));
  assert(winn_stage_b_provider_native_owner_capture(
             owner, &expected, &capture) ==
         WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED);
  assert(bytes_are_zero(&capture, sizeof(capture)) == 1);

  fake.capture_status = WINN_STAGE_B_PROVIDER_NATIVE_OK;
  assert(winn_stage_b_provider_native_owner_capture(
             owner, &expected, &capture) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(capture.capture_ordinal == 1U);

  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_OWNER_UNLOCK,
             2U) == 1);
  memset(&capture, 0xff, sizeof(capture));
  assert(winn_stage_b_provider_native_owner_capture(
             owner, &expected, &capture) ==
         WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED);
  assert(bytes_are_zero(&capture, sizeof(capture)) == 1);
  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_NONE, 0U) == 1);
  assert(winn_stage_b_provider_native_owner_capture(
             owner, &expected, &capture) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(capture.capture_ordinal == 3U);

  fake.block_capture = 1;
  atomic_store_explicit(
      &fake.capture_entered, 0, memory_order_release);
  atomic_store_explicit(
      &fake.allow_capture_return, 0, memory_order_release);
  memset(&capture_thread, 0, sizeof(capture_thread));
  capture_thread.owner = owner;
  capture_thread.generation = expected;
  assert(pthread_create(
             &thread, NULL, capture_thread_main, &capture_thread) == 0);
  while (atomic_load_explicit(
             &fake.capture_entered, memory_order_acquire) == 0) {
  }
  memset(&stop, 0xff, sizeof(stop));
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &expected, start_result.lifecycle_handle, &stop) ==
         WINN_STAGE_B_PROVIDER_NATIVE_BUSY);
  assert(stop.invocation == WINN_STAGE_B_PROVIDER_STOP_NOT_INVOKED);
  assert(stop.lifecycle_handle == -1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_BUSY);
  atomic_store_explicit(
      &fake.allow_capture_return, 1, memory_order_release);
  assert(pthread_join(thread, NULL) == 0);
  assert(capture_thread.status == WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(capture_thread.capture.capture_ordinal == 4U);
  stop_owner(owner, &expected, start_result.lifecycle_handle);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

static void test_stop_stop_serialization(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeStartResult start_result;
  WinnStageBProviderNativeStopResult second;
  WinnStageBProviderNativeGeneration expected = generation(21U);
  StopThread first;
  pthread_t thread;
  initialize_fake(&fake);
  fake.block_stop = 1;
  owner = create_owner(&fake);
  start_result = start_owner(owner, &fake, 21U);
  memset(&first, 0, sizeof(first));
  first.owner = owner;
  first.generation = expected;
  first.handle = start_result.lifecycle_handle;
  assert(pthread_create(
             &thread, NULL, stop_thread_main, &first) == 0);
  while (atomic_load_explicit(
             &fake.stop_entered, memory_order_acquire) == 0) {
  }
  memset(&second, 0xff, sizeof(second));
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &expected, start_result.lifecycle_handle, &second) ==
         WINN_STAGE_B_PROVIDER_NATIVE_BUSY);
  assert(second.invocation == WINN_STAGE_B_PROVIDER_STOP_NOT_INVOKED);
  assert(second.lifecycle_handle == -1);
  atomic_store_explicit(
      &fake.allow_stop_return, 1, memory_order_release);
  assert(pthread_join(thread, NULL) == 0);
  assert(first.status == WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(first.result.invocation ==
         WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED);
  assert(fake.stop_calls == 1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

static void test_concurrent_destroy_and_aba(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwner *owner;
  DestroyThread first;
  DestroyThread second;
  pthread_t first_thread;
  pthread_t second_thread;
  atomic_int ready;
  atomic_int go;
  unsigned successes;
  WinnStageBProviderNativeOwner stale;
  WinnStageBProviderNativeOwner *replacement;
  WinnStageBProviderNativeState state;
  uintptr_t first_address;
  uint64_t first_token;

  initialize_fake(&fake);
  owner = create_owner(&fake);
  memset(&first, 0, sizeof(first));
  memset(&second, 0, sizeof(second));
  atomic_init(&ready, 0);
  atomic_init(&go, 0);
  first.owner = *owner;
  second.owner = *owner;
  first.ready = &ready;
  second.ready = &ready;
  first.go = &go;
  second.go = &go;
  assert(pthread_create(
             &first_thread, NULL, destroy_thread_main, &first) == 0);
  assert(pthread_create(
             &second_thread, NULL, destroy_thread_main, &second) == 0);
  while (atomic_load_explicit(&ready, memory_order_acquire) != 2) {
  }
  atomic_store_explicit(&go, 1, memory_order_release);
  assert(pthread_join(first_thread, NULL) == 0);
  assert(pthread_join(second_thread, NULL) == 0);
  successes =
      (first.status == WINN_STAGE_B_PROVIDER_NATIVE_OK ? 1U : 0U) +
      (second.status == WINN_STAGE_B_PROVIDER_NATIVE_OK ? 1U : 0U);
  assert(successes == 1U);
  assert(
      first.status == WINN_STAGE_B_PROVIDER_NATIVE_OK ||
      first.status == WINN_STAGE_B_PROVIDER_NATIVE_BUSY ||
      first.status == WINN_STAGE_B_PROVIDER_NATIVE_INVALID_STATE);
  assert(
      second.status == WINN_STAGE_B_PROVIDER_NATIVE_OK ||
      second.status == WINN_STAGE_B_PROVIDER_NATIVE_BUSY ||
      second.status == WINN_STAGE_B_PROVIDER_NATIVE_INVALID_STATE);
  assert(fake.owner_release_calls == 1);
  free(owner);

  initialize_fake(&fake);
  fake.retain_owner_allocation = 1;
  owner = create_owner(&fake);
  stale = *owner;
  first_address = owner->storage_address;
  first_token = owner->lifecycle_token;
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(fake.retained_owner_allocation != NULL);
  replacement = create_owner(&fake);
  assert(replacement->storage_address == first_address);
  assert(replacement->lifecycle_token != first_token);
  assert(winn_stage_b_provider_native_owner_state(&stale, &state) ==
         WINN_STAGE_B_PROVIDER_NATIVE_INVALID_STATE);
  assert(winn_stage_b_provider_native_owner_state(replacement, &state) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  fake.retain_owner_allocation = 0;
  assert(destroy_owner(&replacement) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(fake.retained_owner_allocation == NULL);
}

static void assert_start_result_not_connected(
    const WinnStageBProviderNativeStartResult *result,
    int32_t expected_cleanup_handle) {
  assert(bytes_are_zero(&result->identity, sizeof(result->identity)) == 1);
  assert(bytes_are_zero(
             result->signed_runtime_sha256,
             sizeof(result->signed_runtime_sha256)) == 1);
  assert(result->lifecycle_handle == expected_cleanup_handle);
}

static void test_start_fault_matrix(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeStart start;
  WinnStageBProviderNativeStartResult result;

  initialize_fake(&fake);
  fake.begin_status = WINN_STAGE_B_PROVIDER_NATIVE_ATTEMPT_FAILED;
  owner = create_owner(&fake);
  start = make_start(&fake, 22U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_ATTEMPT_FAILED);
  assert_start_result_not_connected(&result, -1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);

  initialize_fake(&fake);
  fake.create_status = WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
  owner = create_owner(&fake);
  start = make_start(&fake, 23U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED);
  assert_start_result_not_connected(&result, -1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);

  initialize_fake(&fake);
  fake.create_status = WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
  fake.abandon_status = WINN_STAGE_B_PROVIDER_NATIVE_ATTEMPT_FAILED;
  owner = create_owner(&fake);
  start = make_start(&fake, 231U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_ATTEMPT_FAILED);
  assert_start_result_not_connected(&result, -1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(winn_stage_b_provider_native_owner_reset_registry_for_testing() ==
         1);

  initialize_fake(&fake);
  fake.action_called = 0U;
  fake.handle = -1;
  fake.callback_handle = -1;
  owner = create_owner(&fake);
  start = make_start(&fake, 24U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED);
  assert_start_result_not_connected(&result, -1);
  assert(fake.stop_calls == 0);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);

  initialize_fake(&fake);
  fake.record_callback_handle = 0;
  owner = create_owner(&fake);
  start = make_start(&fake, 25U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED);
  assert_start_result_not_connected(&result, -1);
  assert(fake.stop_calls == 1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);

  initialize_fake(&fake);
  fake.callback_handle = fake.handle + 1;
  owner = create_owner(&fake);
  start = make_start(&fake, 26U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED);
  assert_start_result_not_connected(&result, -1);
  assert(fake.stop_calls == 1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

static void test_publication_and_unlock_faults(void) {
  FakeContext fake;
  WinnStageBProviderNativeOwnerDependencies dependencies;
  WinnStageBProviderNativeOwner failed_owner;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeStart start;
  WinnStageBProviderNativeStartResult start_result;
  WinnStageBProviderNativeStopResult stop;
  WinnStageBProviderNativeState state;
  WinnStageBProviderNativeGeneration expected;

  initialize_fake(&fake);
  dependencies = dependencies_for(&fake);
  memset(&failed_owner, 0xff, sizeof(failed_owner));
  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_REGISTER_PUBLICATION,
             1U) == 1);
  assert(winn_stage_b_provider_native_owner_create_for_testing(
             &dependencies, &failed_owner) ==
         WINN_STAGE_B_PROVIDER_NATIVE_POISONED);
  assert(failed_owner.storage_address == (uintptr_t)0);
  assert(failed_owner.lifecycle_token == 0U);
  assert(fake.owner_allocate_calls == 1);
  assert(fake.owner_release_calls == 1);
  assert(winn_stage_b_provider_native_owner_reset_registry_for_testing() ==
         1);

  initialize_fake(&fake);
  owner = create_owner(&fake);
  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_CALL_RELEASE_PUBLICATION,
             1U) == 1);
  state = WINN_STAGE_B_PROVIDER_NATIVE_STATE_RUNNING;
  assert(winn_stage_b_provider_native_owner_state(owner, &state) ==
         WINN_STAGE_B_PROVIDER_NATIVE_POISONED);
  assert(state == WINN_STAGE_B_PROVIDER_NATIVE_STATE_READY);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(winn_stage_b_provider_native_owner_reset_registry_for_testing() ==
         1);

  initialize_fake(&fake);
  owner = create_owner(&fake);
  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_CALL_RELEASE_PUBLICATION,
             1U) == 1);
  start = make_start(&fake, 27U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &start_result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_POISONED);
  assert_start_result_not_connected(&start_result, fake.handle);
  expected = generation(27U);
  stop_owner(owner, &expected, start_result.lifecycle_handle);
  assert(fake.stop_calls == 1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(winn_stage_b_provider_native_owner_reset_registry_for_testing() ==
         1);

  initialize_fake(&fake);
  owner = create_owner(&fake);
  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_OWNER_UNLOCK,
             4U) == 1);
  start = make_start(&fake, 28U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &start_result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED);
  assert_start_result_not_connected(&start_result, fake.handle);
  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_NONE, 0U) == 1);
  expected = generation(28U);
  stop_owner(owner, &expected, start_result.lifecycle_handle);
  assert(fake.stop_calls == 1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);

  initialize_fake(&fake);
  owner = create_owner(&fake);
  start_result = start_owner(owner, &fake, 29U);
  expected = generation(29U);
  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_OWNER_UNLOCK,
             2U) == 1);
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &expected, start_result.lifecycle_handle, &stop) ==
         WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED);
  assert(stop.invocation ==
         WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED);
  assert(stop.lifecycle_acknowledgement_permitted == 1U);
  assert(stop.owner_poisoned_after_invocation == 1U);
  assert(fake.stop_calls == 1);
  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_NONE, 0U) == 1);
  memset(&stop, 0xff, sizeof(stop));
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &expected, start_result.lifecycle_handle, &stop) ==
         WINN_STAGE_B_PROVIDER_NATIVE_HANDLE_MISMATCH);
  assert(stop.invocation == WINN_STAGE_B_PROVIDER_STOP_NOT_INVOKED);
  assert(stop.lifecycle_handle == -1);
  assert(fake.stop_calls == 1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(winn_stage_b_provider_native_owner_reset_registry_for_testing() ==
         1);

  initialize_fake(&fake);
  owner = create_owner(&fake);
  start_result = start_owner(owner, &fake, 30U);
  expected = generation(30U);
  assert(winn_stage_b_provider_native_owner_set_fault_for_testing(
             WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_ACTIVE_RELEASE_PUBLICATION,
             1U) == 1);
  assert(winn_stage_b_provider_native_owner_stop(
             owner, &expected, start_result.lifecycle_handle, &stop) ==
         WINN_STAGE_B_PROVIDER_NATIVE_POISONED);
  assert(stop.invocation ==
         WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED);
  assert(stop.lifecycle_acknowledgement_permitted == 1U);
  assert(stop.owner_poisoned_after_invocation == 1U);
  assert(fake.stop_calls == 1);
  assert(destroy_owner(&owner) == WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(winn_stage_b_provider_native_owner_reset_registry_for_testing() ==
         1);
}

static void test_start_cleanup_poison_is_not_retryable(void) {
  FakeContext fake;
  FakeContext second_fake;
  WinnStageBProviderNativeOwner *owner;
  WinnStageBProviderNativeOwner *second;
  WinnStageBProviderNativeStart start;
  WinnStageBProviderNativeStart second_start;
  WinnStageBProviderNativeStartResult result;
  WinnStageBProviderNativeStartResult second_result;
  WinnStageBProviderNativeState state;
  initialize_fake(&fake);
  fake.start_status = WINN_STAGE_B_PROVIDER_NATIVE_UTUN_FAILED;
  fake.record_status = WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
  owner = create_owner(&fake);
  start = make_start(&fake, 13U);
  assert(winn_stage_b_provider_native_owner_start(
             owner, &start, &result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_POISONED);
  assert(result.lifecycle_handle == -1);
  assert(fake.stop_calls == 1);
  assert(fake.record_calls == 1);
  assert(fake.destroy_calls == 0);
  assert(winn_stage_b_provider_native_owner_state(owner, &state) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
  assert(state ==
         WINN_STAGE_B_PROVIDER_NATIVE_STATE_POISONED_AFTER_STOP_INVOCATION);
  assert(destroy_owner(&owner) ==
         WINN_STAGE_B_PROVIDER_NATIVE_BUSY);
  free(owner);
  owner = NULL;

  initialize_fake(&second_fake);
  second = create_owner(&second_fake);
  second_start = make_start(&second_fake, 14U);
  assert(winn_stage_b_provider_native_owner_start(
             second, &second_start, &second_result) ==
         WINN_STAGE_B_PROVIDER_NATIVE_POISONED);
  assert(second_fake.release_calls == 1);
  assert(destroy_owner(&second) ==
         WINN_STAGE_B_PROVIDER_NATIVE_OK);
}

int main(void) {
  assert(winn_stage_b_provider_native_owner_reset_registry_for_testing() ==
         1);
  test_success_and_validation();
  test_retryable_stop();
  test_poison_after_return();
  test_concurrent_abandon();
  test_single_active_and_reentrancy();
  test_start_failure_cleanup();
  test_start_failure_exposes_retryable_stop_handle();
  test_capture_failure_ordinal_and_capture_stop();
  test_stop_stop_serialization();
  test_concurrent_destroy_and_aba();
  test_start_fault_matrix();
  test_publication_and_unlock_faults();
  test_start_cleanup_poison_is_not_retryable();
  puts("WINN_STAGE_B_PROVIDER_NATIVE_OWNER_TEST_PASS");
  return 0;
}
