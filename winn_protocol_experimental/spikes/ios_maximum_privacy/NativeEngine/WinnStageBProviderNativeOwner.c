#include "WinnStageBProviderNativeOwner.h"

#include "WinnStageBDarwinUtun.h"
#include "WinnStageBFrameworkLoader.h"

#if defined(WINN_STAGE_B_PROVIDER_NATIVE_OWNER_TESTING)
#include "WinnStageBProviderNativeOwnerInternal.h"
#else
typedef struct WinnStageBProviderNativeOwnerDependencies {
  void *(*allocate_owner)(size_t, void *);
  void (*release_owner)(void *, size_t, void *);
  WinnStageBProviderNativeStatus (*load_framework)(
      const void **, uint8_t[32], void *);
  WinnStageBProviderNativeStatus (*begin_attempt)(uint64_t *, void *);
  WinnStageBProviderNativeStatus (*abandon_attempt)(uint64_t, void *);
  WinnStageBProviderNativeStatus (*create_engine)(void *, void **, void *);
  WinnStageBProviderNativeStatus (*start_pinned)(
      void *, void *, const WinnStageBProviderNativeStart *,
      WinnStageBNativeIdentity *, int32_t *, uint8_t *, void *);
  WinnStageBProviderNativeStatus (*capture)(
      void *, WinnStageBNativeObservation *, void *);
  WinnStageBFrameworkStatus (*turn_off_checked)(
      const void *, int32_t, WinnStageBFrameworkTurnOffObservation *, void *);
  WinnStageBProviderNativeStatus (*record_external_stop)(
      void *, int32_t, void *);
  void (*destroy_engine)(void **, void *);
  void *context;
} WinnStageBProviderNativeOwnerDependencies;
#endif

#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc/malloc.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

_Static_assert(
    sizeof(WinnStageBProviderNativeGeneration) == 24U,
    "native-owner generation ABI changed");
_Static_assert(
    sizeof(WinnStageBProviderNativeStopResult) == 12U,
    "native-owner stop-result ABI changed");

typedef struct WinnStageBProviderNativeOwnerStorage {
  pthread_mutex_t mutex;
  struct WinnStageBProviderNativeOwnerStorage *registry_next;
  uint64_t registry_call_references;
  uint64_t lifecycle_token;
  bool registry_destroying;
  WinnStageBProviderNativeOwnerDependencies dependencies;
  const void *image;
  uint8_t signed_runtime_sha256[32];
  WinnStageBProviderNativeState state;
  WinnStageBProviderNativeGeneration generation;
  uint64_t loader_attempt_id;
  void *engine;
  int32_t owned_handle;
  uint64_t capture_ordinal;
  bool cancel_requested;
  bool operation_in_flight;
  int32_t callback_handle;
} WinnStageBProviderNativeOwnerStorage;

static pthread_mutex_t winn_owner_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static WinnStageBProviderNativeOwnerStorage *winn_owner_registry_head;
static WinnStageBProviderNativeOwnerStorage *winn_active_owner;
static bool winn_owner_registry_poisoned;
static atomic_bool winn_owner_registry_catastrophic_poison =
    ATOMIC_VAR_INIT(false);
static _Atomic(uint64_t) winn_owner_next_lifecycle_token =
    ATOMIC_VAR_INIT(1U);
static _Thread_local unsigned winn_owner_public_depth;

enum {
  WINN_OWNER_FAULT_OWNER_UNLOCK = 1,
  WINN_OWNER_FAULT_REGISTER_PUBLICATION = 2,
  WINN_OWNER_FAULT_ACTIVE_RELEASE_PUBLICATION = 3,
  WINN_OWNER_FAULT_CALL_RELEASE_PUBLICATION = 4,
  WINN_OWNER_FAULT_COUNT = 5
};

#if defined(WINN_STAGE_B_PROVIDER_NATIVE_OWNER_TESTING)
static _Atomic(uint64_t)
    winn_owner_fault_target[WINN_OWNER_FAULT_COUNT];
static _Atomic(uint64_t)
    winn_owner_fault_seen[WINN_OWNER_FAULT_COUNT];

static bool winn_owner_fault_should_fail(unsigned point) {
  uint64_t ordinal;
  uint64_t target;
  if (point == 0U || point >= WINN_OWNER_FAULT_COUNT) {
    return false;
  }
  ordinal = atomic_fetch_add_explicit(
                &winn_owner_fault_seen[point],
                1U,
                memory_order_relaxed) +
            1U;
  target = atomic_load_explicit(
      &winn_owner_fault_target[point], memory_order_relaxed);
  return target != 0U && ordinal == target;
}
#else
static bool winn_owner_fault_should_fail(unsigned point) {
  (void)point;
  return false;
}
#endif

static WinnStageBProviderNativeStatus winn_next_lifecycle_token(
    uint64_t *output_token) {
  uint64_t current = atomic_load_explicit(
      &winn_owner_next_lifecycle_token, memory_order_relaxed);
  for (;;) {
    if (current == 0U || current == UINT64_MAX) {
      atomic_store_explicit(
          &winn_owner_registry_catastrophic_poison,
          true,
          memory_order_release);
      return WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
    }
    if (atomic_compare_exchange_weak_explicit(
            &winn_owner_next_lifecycle_token,
            &current,
            current + 1U,
            memory_order_relaxed,
            memory_order_relaxed)) {
      *output_token = current;
      return WINN_STAGE_B_PROVIDER_NATIVE_OK;
    }
  }
}

static pthread_mutex_t winn_descriptor_gate = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local unsigned winn_descriptor_gate_depth;

static void winn_secure_zero(void *bytes, size_t count) {
  volatile uint8_t *cursor = (volatile uint8_t *)bytes;
  while (count != 0U) {
    *cursor = 0U;
    ++cursor;
    --count;
  }
}

static bool winn_nonzero(const uint8_t *bytes, size_t count) {
  uint8_t aggregate = 0U;
  size_t index;
  for (index = 0U; index < count; ++index) {
    aggregate = (uint8_t)(aggregate | bytes[index]);
  }
  return aggregate != 0U;
}

static bool winn_generation_valid(
    const WinnStageBProviderNativeGeneration *generation) {
  return generation != NULL &&
         generation->lifecycle_sequence != 0U &&
         winn_nonzero(generation->attempt_nonce, 16U) &&
         (generation->attempt_nonce[6] & 0xf0U) == 0x40U &&
         (generation->attempt_nonce[8] & 0xc0U) == 0x80U;
}

static bool winn_generation_equal(
    const WinnStageBProviderNativeGeneration *first,
    const WinnStageBProviderNativeGeneration *second) {
  uint8_t difference = 0U;
  size_t index;
  if (first->lifecycle_sequence != second->lifecycle_sequence) {
    return false;
  }
  for (index = 0U; index < 16U; ++index) {
    difference = (uint8_t)(
        difference |
        (uint8_t)(first->attempt_nonce[index] ^ second->attempt_nonce[index]));
  }
  return difference == 0U;
}

static bool winn_enter_public(void) {
  if (winn_owner_public_depth != 0U) {
    return false;
  }
  winn_owner_public_depth = 1U;
  return true;
}

static void winn_leave_public(void) {
  winn_owner_public_depth = 0U;
}

static WinnStageBProviderNativeStatus winn_owner_lock(
    WinnStageBProviderNativeOwnerStorage *owner) {
  return pthread_mutex_lock(&owner->mutex) == 0
             ? WINN_STAGE_B_PROVIDER_NATIVE_OK
             : WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED;
}

static WinnStageBProviderNativeStatus winn_owner_unlock(
    WinnStageBProviderNativeOwnerStorage *owner) {
  int result = pthread_mutex_unlock(&owner->mutex);
  if (result != 0 ||
      winn_owner_fault_should_fail(WINN_OWNER_FAULT_OWNER_UNLOCK)) {
    return WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED;
  }
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

static WinnStageBProviderNativeStatus winn_registry_lock(void) {
  if (pthread_mutex_lock(&winn_owner_registry_mutex) != 0) {
    atomic_store_explicit(
        &winn_owner_registry_catastrophic_poison,
        true,
        memory_order_release);
    return WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED;
  }
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

static WinnStageBProviderNativeStatus winn_registry_unlock(void) {
  if (pthread_mutex_unlock(&winn_owner_registry_mutex) != 0) {
    atomic_store_explicit(
        &winn_owner_registry_catastrophic_poison,
        true,
        memory_order_release);
    return WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED;
  }
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

static bool winn_registry_is_poisoned_unlocked(void) {
  return winn_owner_registry_poisoned ||
         atomic_load_explicit(
             &winn_owner_registry_catastrophic_poison,
             memory_order_acquire);
}

static WinnStageBProviderNativeOwnerStorage *
winn_registry_find_handle_unlocked(
    const WinnStageBProviderNativeOwner *handle) {
  WinnStageBProviderNativeOwnerStorage *cursor =
      winn_owner_registry_head;
  if (handle == NULL || handle->storage_address == (uintptr_t)0 ||
      handle->lifecycle_token == 0U) {
    return NULL;
  }
  while (cursor != NULL) {
    if ((uintptr_t)cursor == handle->storage_address &&
        cursor->lifecycle_token == handle->lifecycle_token) {
      return cursor;
    }
    cursor = cursor->registry_next;
  }
  return NULL;
}

static WinnStageBProviderNativeOwnerStorage *
winn_registry_find_storage_unlocked(
    const WinnStageBProviderNativeOwnerStorage *owner) {
  WinnStageBProviderNativeOwnerStorage *cursor =
      winn_owner_registry_head;
  while (cursor != NULL) {
    if (cursor == owner) {
      return cursor;
    }
    cursor = cursor->registry_next;
  }
  return NULL;
}

static WinnStageBProviderNativeStatus winn_registry_register(
    WinnStageBProviderNativeOwnerStorage *owner,
    bool *output_registered) {
  WinnStageBProviderNativeStatus status = winn_registry_lock();
  WinnStageBProviderNativeStatus unlock_status;
  *output_registered = false;
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  if (winn_owner_fault_should_fail(
          WINN_OWNER_FAULT_REGISTER_PUBLICATION)) {
    winn_owner_registry_poisoned = true;
    status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  } else {
    owner->registry_next = winn_owner_registry_head;
    winn_owner_registry_head = owner;
    *output_registered = true;
  }
  unlock_status = winn_registry_unlock();
  return unlock_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
             ? status
             : unlock_status;
}

static WinnStageBProviderNativeStatus winn_registry_admit_call(
    const WinnStageBProviderNativeOwner *handle,
    WinnStageBProviderNativeOwnerStorage **output_owner) {
  WinnStageBProviderNativeOwnerStorage *registered;
  WinnStageBProviderNativeStatus status = winn_registry_lock();
  WinnStageBProviderNativeStatus unlock_status;
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  *output_owner = NULL;
  registered = winn_registry_find_handle_unlocked(handle);
  if (registered == NULL) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_INVALID_STATE;
  } else if (registered->registry_destroying) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_BUSY;
  } else if (registered->registry_call_references == UINT64_MAX) {
    winn_owner_registry_poisoned = true;
    status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  } else {
    ++registered->registry_call_references;
    *output_owner = registered;
  }
  unlock_status = winn_registry_unlock();
  if (unlock_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return unlock_status;
  }
  return status;
}

static WinnStageBProviderNativeStatus winn_registry_release_call(
    WinnStageBProviderNativeOwnerStorage *owner) {
  WinnStageBProviderNativeOwnerStorage *registered;
  WinnStageBProviderNativeStatus status = winn_registry_lock();
  WinnStageBProviderNativeStatus unlock_status;
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  registered = winn_registry_find_storage_unlocked(owner);
  if (registered == NULL || registered->registry_call_references == 0U) {
    winn_owner_registry_poisoned = true;
    status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  } else {
    --registered->registry_call_references;
    if (winn_owner_fault_should_fail(
            WINN_OWNER_FAULT_CALL_RELEASE_PUBLICATION)) {
      winn_owner_registry_poisoned = true;
      status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
    }
  }
  unlock_status = winn_registry_unlock();
  return unlock_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
             ? status
             : unlock_status;
}

static WinnStageBProviderNativeStatus winn_registry_reserve_active(
    WinnStageBProviderNativeOwnerStorage *owner) {
  WinnStageBProviderNativeStatus status = winn_registry_lock();
  WinnStageBProviderNativeStatus unlock_status;
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  if (winn_registry_is_poisoned_unlocked()) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  } else if (winn_active_owner != NULL) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_BUSY;
  } else if (winn_registry_find_storage_unlocked(owner) != owner ||
             owner->registry_destroying ||
             owner->registry_call_references == 0U) {
    winn_owner_registry_poisoned = true;
    status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  } else {
    winn_active_owner = owner;
  }
  unlock_status = winn_registry_unlock();
  return unlock_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
             ? status
             : unlock_status;
}

static WinnStageBProviderNativeStatus winn_registry_release_active(
    WinnStageBProviderNativeOwnerStorage *owner,
    bool poison) {
  WinnStageBProviderNativeStatus status = winn_registry_lock();
  WinnStageBProviderNativeStatus unlock_status;
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  if (winn_active_owner != owner) {
    winn_owner_registry_poisoned = true;
    status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  } else if (winn_owner_fault_should_fail(
                 WINN_OWNER_FAULT_ACTIVE_RELEASE_PUBLICATION)) {
    winn_active_owner = NULL;
    winn_owner_registry_poisoned = true;
    status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  } else {
    winn_active_owner = NULL;
    winn_owner_registry_poisoned =
        winn_owner_registry_poisoned || poison;
  }
  unlock_status = winn_registry_unlock();
  return unlock_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
             ? status
             : unlock_status;
}

static WinnStageBProviderNativeStatus winn_registry_mark_destroying(
    const WinnStageBProviderNativeOwner *handle,
    WinnStageBProviderNativeOwnerStorage **output_owner) {
  WinnStageBProviderNativeOwnerStorage *registered;
  WinnStageBProviderNativeStatus status = winn_registry_lock();
  WinnStageBProviderNativeStatus unlock_status;
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  *output_owner = NULL;
  registered = winn_registry_find_handle_unlocked(handle);
  if (registered == NULL) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_INVALID_STATE;
  } else if (registered->registry_destroying ||
             registered->registry_call_references != 0U ||
             winn_active_owner == registered) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_BUSY;
  } else {
    registered->registry_destroying = true;
    *output_owner = registered;
  }
  unlock_status = winn_registry_unlock();
  return unlock_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
             ? status
             : unlock_status;
}

static WinnStageBProviderNativeStatus winn_registry_unmark_destroying(
    WinnStageBProviderNativeOwnerStorage *owner) {
  WinnStageBProviderNativeOwnerStorage *registered;
  WinnStageBProviderNativeStatus status = winn_registry_lock();
  WinnStageBProviderNativeStatus unlock_status;
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  registered = winn_registry_find_storage_unlocked(owner);
  if (registered == NULL || !registered->registry_destroying ||
      registered->registry_call_references != 0U) {
    winn_owner_registry_poisoned = true;
    status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  } else {
    registered->registry_destroying = false;
  }
  unlock_status = winn_registry_unlock();
  return unlock_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
             ? status
             : unlock_status;
}

static WinnStageBProviderNativeStatus winn_registry_remove_destroying(
    WinnStageBProviderNativeOwnerStorage *owner) {
  WinnStageBProviderNativeOwnerStorage **link;
  WinnStageBProviderNativeStatus status = winn_registry_lock();
  WinnStageBProviderNativeStatus unlock_status;
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  link = &winn_owner_registry_head;
  while (*link != NULL && *link != owner) {
    link = &(*link)->registry_next;
  }
  if (*link == NULL || !owner->registry_destroying ||
      owner->registry_call_references != 0U ||
      winn_active_owner == owner) {
    winn_owner_registry_poisoned = true;
    status = WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  } else {
    *link = owner->registry_next;
    owner->registry_next = NULL;
  }
  unlock_status = winn_registry_unlock();
  return unlock_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
             ? status
             : unlock_status;
}

static WinnStageBProviderNativeStatus winn_enter_owner_public(
    const WinnStageBProviderNativeOwner *handle,
    WinnStageBProviderNativeOwnerStorage **output_owner) {
  WinnStageBProviderNativeStatus status;
  if (!winn_enter_public()) {
    return WINN_STAGE_B_PROVIDER_NATIVE_REENTRANT;
  }
  *output_owner = NULL;
  if (handle == NULL) {
    winn_leave_public();
    return WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT;
  }
  status = winn_registry_admit_call(handle, output_owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    winn_leave_public();
  }
  return status;
}

static WinnStageBProviderNativeStatus winn_leave_owner_public(
    WinnStageBProviderNativeOwnerStorage *owner,
    WinnStageBProviderNativeStatus status) {
  WinnStageBProviderNativeStatus release_status =
      winn_registry_release_call(owner);
  winn_leave_public();
  return release_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
             ? status
             : release_status;
}

static WinnStageBProviderOwnedSecretBuffer winn_consume_secret(
    WinnStageBProviderNativeStart *start) {
  WinnStageBProviderOwnedSecretBuffer secret;
  memset(&secret, 0, sizeof(secret));
  if (start != NULL) {
    secret = start->config;
    memset(&start->config, 0, sizeof(start->config));
  }
  return secret;
}

static bool winn_secret_valid(
    const WinnStageBProviderOwnedSecretBuffer *secret) {
  return secret->bytes != NULL &&
         secret->erase_and_release != NULL &&
         secret->buffer_length >= 2U &&
         secret->buffer_length == secret->allocation_size &&
         secret->buffer_length <=
             (size_t)WINN_STAGE_B_MAX_CONFIG_BYTES + 1U;
}

static void winn_release_secret(
    WinnStageBProviderOwnedSecretBuffer *secret) {
  if (secret->bytes != NULL && secret->erase_and_release != NULL) {
    winn_secure_zero(secret->bytes, secret->allocation_size);
    secret->erase_and_release(
        secret->bytes, secret->allocation_size, secret->release_context);
  }
  memset(secret, 0, sizeof(*secret));
}

static bool winn_dependencies_valid(
    const WinnStageBProviderNativeOwnerDependencies *dependencies) {
  return dependencies != NULL &&
         dependencies->allocate_owner != NULL &&
         dependencies->release_owner != NULL &&
         dependencies->load_framework != NULL &&
         dependencies->begin_attempt != NULL &&
         dependencies->abandon_attempt != NULL &&
         dependencies->create_engine != NULL &&
         dependencies->start_pinned != NULL &&
         dependencies->capture != NULL &&
         dependencies->turn_off_checked != NULL &&
         dependencies->record_external_stop != NULL &&
         dependencies->destroy_engine != NULL;
}

static WinnStageBProviderNativeStatus winn_create_with_dependencies(
    const WinnStageBProviderNativeOwnerDependencies *dependencies,
    WinnStageBProviderNativeOwner *output_owner) {
  WinnStageBProviderNativeOwnerStorage *owner;
  WinnStageBProviderNativeStatus status;
  bool registered = false;
  int mutex_status;
  if (output_owner != NULL) {
    memset(output_owner, 0, sizeof(*output_owner));
  }
  if (!winn_dependencies_valid(dependencies) || output_owner == NULL) {
    return WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT;
  }
  owner = (WinnStageBProviderNativeOwnerStorage *)
      dependencies->allocate_owner(
          sizeof(*owner), dependencies->context);
  if (owner == NULL) {
    return WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
  }
  memset(owner, 0, sizeof(*owner));
  status = winn_next_lifecycle_token(&owner->lifecycle_token);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    dependencies->release_owner(
        owner, sizeof(*owner), dependencies->context);
    return status;
  }
  mutex_status = pthread_mutex_init(&owner->mutex, NULL);
  if (mutex_status != 0) {
    winn_secure_zero(owner, sizeof(*owner));
    dependencies->release_owner(
        owner, sizeof(*owner), dependencies->context);
    return WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED;
  }
  owner->dependencies = *dependencies;
  owner->state = WINN_STAGE_B_PROVIDER_NATIVE_STATE_READY;
  owner->owned_handle = -1;
  owner->callback_handle = -1;
  status = owner->dependencies.load_framework(
      &owner->image,
      owner->signed_runtime_sha256,
      owner->dependencies.context);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK ||
      owner->image == NULL ||
      !winn_nonzero(owner->signed_runtime_sha256, 32U)) {
    (void)pthread_mutex_destroy(&owner->mutex);
    winn_secure_zero(owner, sizeof(*owner));
    dependencies->release_owner(
        owner, sizeof(*owner), dependencies->context);
    return status == WINN_STAGE_B_PROVIDER_NATIVE_OK
               ? WINN_STAGE_B_PROVIDER_NATIVE_FRAMEWORK_FAILED
               : status;
  }
  status = winn_registry_register(owner, &registered);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    /*
     * An unlock failure after insertion makes publication unknowable. Keep
     * the allocation alive and registered rather than risk a dangling
     * registry entry. The registry is poisoned, so no evidence can proceed.
     */
    if (!registered) {
      (void)pthread_mutex_destroy(&owner->mutex);
      winn_secure_zero(owner, sizeof(*owner));
      dependencies->release_owner(
          owner, sizeof(*owner), dependencies->context);
    }
    return status;
  }
  output_owner->storage_address = (uintptr_t)owner;
  output_owner->lifecycle_token = owner->lifecycle_token;
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

static WinnStageBProviderNativeStatus winn_stop_engine_unlocked(
    WinnStageBProviderNativeOwnerStorage *owner,
    WinnStageBProviderNativeStopResult *output_result,
    bool *output_poison) {
  WinnStageBFrameworkTurnOffObservation observation;
  WinnStageBFrameworkStatus framework_status;
  WinnStageBProviderNativeStatus record_status;
  memset(&observation, 0, sizeof(observation));
  framework_status = owner->dependencies.turn_off_checked(
      owner->image,
      owner->owned_handle,
      &observation,
      owner->dependencies.context);
  output_result->lifecycle_handle = owner->owned_handle;
  if (observation.invocation_returned != 1U) {
    return WINN_STAGE_B_PROVIDER_NATIVE_STOP_NOT_INVOKED;
  }
  output_result->invocation =
      WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED;
  output_result->lifecycle_acknowledgement_permitted = 1U;
  record_status = owner->dependencies.record_external_stop(
      owner->engine,
      owner->owned_handle,
      owner->dependencies.context);
  if (record_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    output_result->owner_poisoned_after_invocation = 1U;
    *output_poison = true;
    return WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  }
  owner->dependencies.destroy_engine(
      &owner->engine, owner->dependencies.context);
  owner->owned_handle = -1;
  if (framework_status != WINN_STAGE_B_FRAMEWORK_OK) {
    output_result->owner_poisoned_after_invocation = 1U;
    *output_poison = true;
    return WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  }
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

/* Production dependency implementation. */

static void *winn_production_allocate_owner(
    size_t allocation_size,
    void *context) {
  (void)context;
  return calloc(1U, allocation_size);
}

static void winn_production_release_owner(
    void *allocation,
    size_t allocation_size,
    void *context) {
  (void)allocation_size;
  (void)context;
  free(allocation);
}

static WinnStageBProviderNativeStatus winn_production_load_framework(
    const void **output_image,
    uint8_t output_runtime_sha256[32],
    void *context) {
  const WinnStageBFrameworkImage *image = NULL;
  (void)context;
  if (winn_stage_b_framework_shared_image(&image) !=
          WINN_STAGE_B_FRAMEWORK_OK ||
      winn_stage_b_framework_measured_digest(
          image, output_runtime_sha256) != WINN_STAGE_B_FRAMEWORK_OK) {
    return WINN_STAGE_B_PROVIDER_NATIVE_FRAMEWORK_FAILED;
  }
  *output_image = image;
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

static WinnStageBProviderNativeStatus winn_production_begin_attempt(
    uint64_t *output_attempt_id,
    void *context) {
  (void)context;
  return winn_stage_b_framework_begin_attempt(output_attempt_id) ==
                 WINN_STAGE_B_FRAMEWORK_OK
             ? WINN_STAGE_B_PROVIDER_NATIVE_OK
             : WINN_STAGE_B_PROVIDER_NATIVE_ATTEMPT_FAILED;
}

static WinnStageBProviderNativeStatus winn_production_abandon_attempt(
    uint64_t attempt_id,
    void *context) {
  WinnStageBFrameworkStatus status;
  (void)context;
  status = winn_stage_b_framework_abandon_attempt(attempt_id);
  return status == WINN_STAGE_B_FRAMEWORK_OK ||
                 status == WINN_STAGE_B_FRAMEWORK_ATTEMPT_STALE
             ? WINN_STAGE_B_PROVIDER_NATIVE_OK
             : WINN_STAGE_B_PROVIDER_NATIVE_ATTEMPT_FAILED;
}

static int32_t winn_production_turn_on(
    const char *settings,
    int32_t file_descriptor,
    void *context) {
  WinnStageBProviderNativeOwnerStorage *owner =
      (WinnStageBProviderNativeOwnerStorage *)context;
  int32_t handle = -1;
  if (winn_stage_b_framework_turn_on(
          (const WinnStageBFrameworkImage *)owner->image,
          owner->loader_attempt_id,
          settings,
          file_descriptor,
          &handle) != WINN_STAGE_B_FRAMEWORK_OK) {
    return -1;
  }
  owner->callback_handle = handle;
  return handle;
}

static void winn_production_turn_off_fallback(
    int32_t handle,
    void *context) {
  WinnStageBProviderNativeOwnerStorage *owner =
      (WinnStageBProviderNativeOwnerStorage *)context;
  (void)winn_stage_b_framework_turn_off(
      (const WinnStageBFrameworkImage *)owner->image, handle);
}

static char *winn_production_get_config(
    int32_t handle,
    void *context) {
  WinnStageBProviderNativeOwnerStorage *owner =
      (WinnStageBProviderNativeOwnerStorage *)context;
  char *result = NULL;
  if (winn_stage_b_framework_get_config(
          (const WinnStageBFrameworkImage *)owner->image,
          handle,
          &result) != WINN_STAGE_B_FRAMEWORK_OK) {
    return NULL;
  }
  return result;
}

static size_t winn_production_raw_allocation_size(
    const char *allocation,
    void *context) {
  (void)context;
  return allocation == NULL ? 0U : malloc_size(allocation);
}

static void winn_production_raw_free(
    char *allocation,
    void *context) {
  size_t allocation_size;
  (void)context;
  if (allocation == NULL) {
    return;
  }
  allocation_size = malloc_size(allocation);
  if (allocation_size != 0U) {
    winn_secure_zero(allocation, allocation_size);
  }
  free(allocation);
}

static int winn_production_csprng(
    uint8_t *output,
    size_t output_length,
    void *context) {
  (void)context;
  return SecRandomCopyBytes(
             kSecRandomDefault, output_length, output) == errSecSuccess
             ? 1
             : 0;
}

static int winn_production_sha256(
    const uint8_t *input,
    size_t input_length,
    uint8_t output[32],
    void *context) {
  (void)context;
  if (input_length > (size_t)UINT32_MAX) {
    return 0;
  }
  return CC_SHA256(
             input, (CC_LONG)input_length, output) != NULL
             ? 1
             : 0;
}

static WinnStageBProviderNativeStatus winn_production_create_engine(
    void *owner_context,
    void **output_engine,
    void *context) {
  WinnStageBNativeFunctions functions;
  WinnStageBNativeEngine *engine = NULL;
  (void)context;
  memset(&functions, 0, sizeof(functions));
  functions.wg_turn_on = winn_production_turn_on;
  functions.wg_turn_off = winn_production_turn_off_fallback;
  functions.wg_get_config = winn_production_get_config;
  functions.raw_allocation_size = winn_production_raw_allocation_size;
  functions.raw_free = winn_production_raw_free;
  functions.csprng = winn_production_csprng;
  functions.sha256 = winn_production_sha256;
  functions.context = owner_context;
  if (winn_stage_b_native_engine_create(&functions, &engine) !=
      WINN_STAGE_B_NATIVE_OK) {
    return WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
  }
  *output_engine = engine;
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

static int winn_descriptor_gate_acquire(void *context) {
  int result;
  (void)context;
  if (winn_descriptor_gate_depth != 0U) {
    return -1;
  }
  result = pthread_mutex_lock(&winn_descriptor_gate);
  if (result == 0) {
    winn_descriptor_gate_depth = 1U;
  }
  return result;
}

static int winn_descriptor_gate_release(void *context) {
  int result;
  (void)context;
  if (winn_descriptor_gate_depth != 1U) {
    return -1;
  }
  winn_descriptor_gate_depth = 0U;
  result = pthread_mutex_unlock(&winn_descriptor_gate);
  return result;
}

static int winn_get_process_fd_ceiling(
    uint64_t *output,
    void *context) {
  int ceiling = 0;
  size_t length = sizeof(ceiling);
  (void)context;
  if (sysctlbyname(
          "kern.maxfilesperproc", &ceiling, &length, NULL, 0U) != 0 ||
      length != sizeof(ceiling) || ceiling <= 0) {
    return -1;
  }
  *output = (uint64_t)(unsigned)ceiling;
  return 0;
}

static int winn_fcntl_getfd(
    int32_t fd,
    int32_t *output_flags,
    int32_t *output_errno,
    void *context) {
  int result;
  (void)context;
  errno = 0;
  result = fcntl(fd, F_GETFD);
  if (result < 0) {
    *output_errno = errno;
    return -1;
  }
  *output_flags = result;
  *output_errno = 0;
  return 0;
}

static int winn_getpeername(
    int32_t fd,
    struct sockaddr_storage *address,
    socklen_t *address_length,
    int32_t *output_errno,
    void *context) {
  int result;
  (void)context;
  errno = 0;
  result = getpeername(
      fd, (struct sockaddr *)address, address_length);
  *output_errno = result == 0 ? 0 : errno;
  return result;
}

#define WINN_STAGE_B_CTLIOCGINFO \
  _IOWR('N', 3, WinnStageBDarwinCtlInfo)

static int winn_ctl_iocginfo(
    int32_t fd,
    WinnStageBDarwinCtlInfo *control_info,
    void *context) {
  (void)context;
  return ioctl(fd, WINN_STAGE_B_CTLIOCGINFO, control_info);
}

static int winn_getsockopt(
    int32_t fd,
    int32_t level,
    int32_t option_name,
    void *option_value,
    socklen_t *option_length,
    void *context) {
  (void)context;
  return getsockopt(fd, level, option_name, option_value, option_length);
}

static int32_t winn_dupfd_cloexec(
    int32_t fd,
    int32_t minimum,
    void *context) {
  (void)context;
  return fcntl(fd, F_DUPFD_CLOEXEC, minimum);
}

static int winn_close_fd(int32_t fd, void *context) {
  (void)context;
  return close(fd);
}

typedef struct WinnProductionPinnedAction {
  WinnStageBProviderNativeOwnerStorage *owner;
  void *engine;
  const WinnStageBProviderNativeStart *start;
  WinnStageBNativeIdentity *identity;
  WinnStageBNativeStatus native_status;
} WinnProductionPinnedAction;

static int32_t winn_production_pinned_action(
    const WinnStageBUtunCandidate *candidate,
    void *context) {
  WinnProductionPinnedAction *action =
      (WinnProductionPinnedAction *)context;
  WinnStageBNativeStart start;
  memset(&start, 0, sizeof(start));
  start.config = action->start->config.bytes;
  start.config_buffer_length = action->start->config.buffer_length;
  start.utun_candidates = candidate;
  start.utun_candidate_count = 1U;
  memcpy(
      start.expected_peer_public_key,
      action->start->expected_peer_public_key,
      sizeof(start.expected_peer_public_key));
  memcpy(
      start.config_sha256,
      action->start->config_sha256,
      sizeof(start.config_sha256));
  start.engine_generation = action->start->engine_generation;
  start.path_generation = action->start->path_generation;
  action->native_status = winn_stage_b_native_engine_start(
      (WinnStageBNativeEngine *)action->engine,
      &start,
      action->identity);
  winn_secure_zero(&start, sizeof(start));
  return (int32_t)action->native_status;
}

static WinnStageBProviderNativeStatus winn_production_start_pinned(
    void *owner_context,
    void *engine,
    const WinnStageBProviderNativeStart *start,
    WinnStageBNativeIdentity *output_identity,
    int32_t *output_handle,
    uint8_t *output_action_was_called,
    void *context) {
  WinnStageBProviderNativeOwnerStorage *owner =
      (WinnStageBProviderNativeOwnerStorage *)owner_context;
  WinnStageBDarwinUtunSyscalls syscalls;
  WinnStageBDarwinActionResult result;
  WinnProductionPinnedAction action;
  WinnStageBDarwinUtunStatus status;
  (void)context;
  memset(&syscalls, 0, sizeof(syscalls));
  syscalls.acquire_descriptor_gate = winn_descriptor_gate_acquire;
  syscalls.release_descriptor_gate = winn_descriptor_gate_release;
  syscalls.get_process_fd_ceiling = winn_get_process_fd_ceiling;
  syscalls.fcntl_getfd = winn_fcntl_getfd;
  syscalls.getpeername = winn_getpeername;
  syscalls.ctl_iocginfo = winn_ctl_iocginfo;
  syscalls.getsockopt = winn_getsockopt;
  syscalls.fcntl_dupfd_cloexec = winn_dupfd_cloexec;
  syscalls.close_fd = winn_close_fd;
  memset(&result, 0, sizeof(result));
  memset(&action, 0, sizeof(action));
  action.owner = owner;
  action.engine = engine;
  action.start = start;
  action.identity = output_identity;
  action.native_status = WINN_STAGE_B_NATIVE_INVALID_STATE;
  owner->callback_handle = -1;
  status = winn_stage_b_darwin_utun_with_pinned(
      &syscalls, winn_production_pinned_action, &action, &result);
  *output_action_was_called = result.action_was_called;
  *output_handle = owner->callback_handle;
  if (status != WINN_STAGE_B_DARWIN_UTUN_OK) {
    return WINN_STAGE_B_PROVIDER_NATIVE_UTUN_FAILED;
  }
  if (result.action_was_called != 1U ||
      action.native_status != WINN_STAGE_B_NATIVE_OK ||
      result.action_status != (int32_t)WINN_STAGE_B_NATIVE_OK ||
      *output_handle < 0) {
    return WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
  }
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

static WinnStageBProviderNativeStatus winn_production_capture(
    void *engine,
    WinnStageBNativeObservation *output_observation,
    void *context) {
  WinnAWGUAPIStatus detail;
  (void)context;
  return winn_stage_b_native_engine_capture(
             (WinnStageBNativeEngine *)engine,
             output_observation,
             &detail) == WINN_STAGE_B_NATIVE_OK
             ? WINN_STAGE_B_PROVIDER_NATIVE_OK
             : WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
}

static WinnStageBFrameworkStatus winn_production_turn_off_checked(
    const void *image,
    int32_t handle,
    WinnStageBFrameworkTurnOffObservation *output,
    void *context) {
  (void)context;
  return winn_stage_b_framework_turn_off_checked(
      (const WinnStageBFrameworkImage *)image, handle, output);
}

static WinnStageBProviderNativeStatus winn_production_record_external_stop(
    void *engine,
    int32_t handle,
    void *context) {
  (void)context;
  return winn_stage_b_native_engine_record_external_stop(
             (WinnStageBNativeEngine *)engine, handle) ==
                 WINN_STAGE_B_NATIVE_OK
             ? WINN_STAGE_B_PROVIDER_NATIVE_OK
             : WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
}

static void winn_production_destroy_engine(
    void **engine,
    void *context) {
  WinnStageBNativeEngine *typed =
      (WinnStageBNativeEngine *)*engine;
  (void)context;
  winn_stage_b_native_engine_destroy(&typed);
  *engine = NULL;
}

static WinnStageBProviderNativeOwnerDependencies
winn_production_dependencies(void) {
  WinnStageBProviderNativeOwnerDependencies result;
  memset(&result, 0, sizeof(result));
  result.allocate_owner = winn_production_allocate_owner;
  result.release_owner = winn_production_release_owner;
  result.load_framework = winn_production_load_framework;
  result.begin_attempt = winn_production_begin_attempt;
  result.abandon_attempt = winn_production_abandon_attempt;
  result.create_engine = winn_production_create_engine;
  result.start_pinned = winn_production_start_pinned;
  result.capture = winn_production_capture;
  result.turn_off_checked = winn_production_turn_off_checked;
  result.record_external_stop = winn_production_record_external_stop;
  result.destroy_engine = winn_production_destroy_engine;
  return result;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_create(
    WinnStageBProviderNativeOwner *output_owner) {
  WinnStageBProviderNativeOwnerDependencies dependencies;
  WinnStageBProviderNativeStatus status;
  if (!winn_enter_public()) {
    if (output_owner != NULL) {
      memset(output_owner, 0, sizeof(*output_owner));
    }
    return WINN_STAGE_B_PROVIDER_NATIVE_REENTRANT;
  }
  dependencies = winn_production_dependencies();
  status = winn_create_with_dependencies(&dependencies, output_owner);
  winn_leave_public();
  return status;
}

#if defined(WINN_STAGE_B_PROVIDER_NATIVE_OWNER_TESTING)
WinnStageBProviderNativeStatus
winn_stage_b_provider_native_owner_create_for_testing(
    const WinnStageBProviderNativeOwnerDependencies *dependencies,
    WinnStageBProviderNativeOwner *output_owner) {
  WinnStageBProviderNativeStatus status;
  if (!winn_enter_public()) {
    if (output_owner != NULL) {
      memset(output_owner, 0, sizeof(*output_owner));
    }
    return WINN_STAGE_B_PROVIDER_NATIVE_REENTRANT;
  }
  status = winn_create_with_dependencies(dependencies, output_owner);
  winn_leave_public();
  return status;
}

int winn_stage_b_provider_native_owner_reset_registry_for_testing(void) {
  int result = 0;
  unsigned point;
  if (winn_registry_lock() != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return 0;
  }
  if (winn_active_owner == NULL && winn_owner_registry_head == NULL) {
    winn_owner_registry_poisoned = false;
    atomic_store_explicit(
        &winn_owner_registry_catastrophic_poison,
        false,
        memory_order_release);
    for (point = 0U; point < WINN_OWNER_FAULT_COUNT; ++point) {
      atomic_store_explicit(
          &winn_owner_fault_target[point], 0U, memory_order_relaxed);
      atomic_store_explicit(
          &winn_owner_fault_seen[point], 0U, memory_order_relaxed);
    }
    result = 1;
  }
  return winn_registry_unlock() == WINN_STAGE_B_PROVIDER_NATIVE_OK
             ? result
             : 0;
}

int winn_stage_b_provider_native_owner_set_fault_for_testing(
    WinnStageBProviderNativeOwnerFaultPoint point,
    uint64_t fail_ordinal) {
  unsigned index;
  if (point == WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_NONE &&
      fail_ordinal == 0U) {
    for (index = 0U; index < WINN_OWNER_FAULT_COUNT; ++index) {
      atomic_store_explicit(
          &winn_owner_fault_target[index], 0U, memory_order_relaxed);
      atomic_store_explicit(
          &winn_owner_fault_seen[index], 0U, memory_order_relaxed);
    }
    return 1;
  }
  if ((unsigned)point == 0U ||
      (unsigned)point >= WINN_OWNER_FAULT_COUNT ||
      fail_ordinal == 0U) {
    return 0;
  }
  atomic_store_explicit(
      &winn_owner_fault_seen[(unsigned)point],
      0U,
      memory_order_relaxed);
  atomic_store_explicit(
      &winn_owner_fault_target[(unsigned)point],
      fail_ordinal,
      memory_order_release);
  return 1;
}

void winn_stage_b_provider_native_owner_record_callback_for_testing(
    void *owner_context,
    int32_t callback_handle) {
  WinnStageBProviderNativeOwnerStorage *owner =
      (WinnStageBProviderNativeOwnerStorage *)owner_context;
  if (owner != NULL) {
    owner->callback_handle = callback_handle;
  }
}
#endif

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_start(
    const WinnStageBProviderNativeOwner *owner_handle,
    WinnStageBProviderNativeStart *consumed_start,
    WinnStageBProviderNativeStartResult *output_result) {
  WinnStageBProviderNativeOwnerStorage *owner = NULL;
  WinnStageBProviderNativeStart local_start;
  WinnStageBProviderOwnedSecretBuffer secret =
      winn_consume_secret(consumed_start);
  WinnStageBProviderNativeStatus status =
      WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT;
  WinnStageBProviderNativeStatus cleanup_status;
  WinnStageBProviderNativeStatus final_status;
  WinnStageBProviderNativeStatus start_status;
  WinnStageBNativeIdentity identity;
  uint64_t attempt_id = 0U;
  int32_t handle = -1;
  int32_t cleanup_handle = -1;
  uint8_t action_was_called = 0U;
  bool cancel_requested = false;
  bool poison = false;
  bool active_reserved = false;
  bool cleanup_invocation_returned = false;
  WinnStageBProviderNativeStopResult cleanup_stop;
  memset(&local_start, 0, sizeof(local_start));
  if (consumed_start != NULL) {
    local_start = *consumed_start;
    local_start.config = secret;
  }
  if (output_result != NULL) {
    memset(output_result, 0, sizeof(*output_result));
    output_result->lifecycle_handle = -1;
  }
  memset(&identity, 0, sizeof(identity));
  memset(&cleanup_stop, 0, sizeof(cleanup_stop));
  cleanup_stop.lifecycle_handle = -1;

  status = winn_enter_owner_public(owner_handle, &owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    winn_release_secret(&secret);
    return status;
  }
  if (consumed_start == NULL || output_result == NULL ||
      !winn_secret_valid(&secret) ||
      !winn_generation_valid(&local_start.generation) ||
      !winn_nonzero(local_start.config_sha256, 32U) ||
      !winn_nonzero(local_start.expected_peer_public_key, 32U) ||
      local_start.engine_generation == 0U ||
      local_start.path_generation == 0U) {
    status = winn_secret_valid(&secret)
                 ? WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT
                 : WINN_STAGE_B_PROVIDER_NATIVE_SECRET_BUFFER_INVALID;
    goto finish;
  }

  status = winn_registry_reserve_active(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    goto finish;
  }
  active_reserved = true;
  status = winn_owner_lock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    goto unrecoverable;
  }
  if (owner->state != WINN_STAGE_B_PROVIDER_NATIVE_STATE_READY &&
      owner->state != WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOPPED) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_INVALID_STATE;
    cleanup_status = winn_owner_unlock(owner);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = cleanup_status;
      poison = true;
    }
    cleanup_status = winn_registry_release_active(owner, poison);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = cleanup_status;
    }
    goto finish;
  }
  owner->state = WINN_STAGE_B_PROVIDER_NATIVE_STATE_STARTING;
  owner->generation = local_start.generation;
  owner->loader_attempt_id = 0U;
  owner->owned_handle = -1;
  owner->capture_ordinal = 0U;
  owner->cancel_requested = false;
  owner->operation_in_flight = true;
  status = winn_owner_unlock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    poison = true;
    goto unrecoverable;
  }

  status = owner->dependencies.begin_attempt(
      &attempt_id, owner->dependencies.context);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK || attempt_id == 0U) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_ATTEMPT_FAILED;
    goto reconcile_failure_without_handle;
  }
  status = winn_owner_lock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    poison = true;
    goto unrecoverable;
  }
  owner->loader_attempt_id = attempt_id;
  cancel_requested = owner->cancel_requested;
  status = winn_owner_unlock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    poison = true;
    goto reconcile_failure_without_handle;
  }
  if (cancel_requested) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_ABANDONED;
    goto reconcile_failure_without_handle;
  }

  status = owner->dependencies.create_engine(
      owner, &owner->engine, owner->dependencies.context);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK ||
      owner->engine == NULL) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
    goto reconcile_failure_without_handle;
  }
  start_status = owner->dependencies.start_pinned(
      owner,
      owner->engine,
      &local_start,
      &identity,
      &handle,
      &action_was_called,
      owner->dependencies.context);
  winn_release_secret(&secret);
  status = winn_owner_lock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    poison = true;
    goto reconcile_failure_with_possible_handle;
  }
  cancel_requested = owner->cancel_requested;
  status = winn_owner_unlock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    poison = true;
    goto reconcile_failure_with_possible_handle;
  }
  if (start_status != WINN_STAGE_B_PROVIDER_NATIVE_OK ||
      action_was_called != 1U || handle < 0 ||
      owner->callback_handle != handle) {
    status = start_status == WINN_STAGE_B_PROVIDER_NATIVE_UTUN_FAILED
                 ? start_status
                 : WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
    goto reconcile_failure_with_possible_handle;
  }
  if (cancel_requested) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_ABANDONED;
    goto reconcile_failure_with_possible_handle;
  }
  status = winn_owner_lock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    poison = true;
    goto reconcile_failure_with_possible_handle;
  }
  owner->owned_handle = handle;
  owner->state = WINN_STAGE_B_PROVIDER_NATIVE_STATE_RUNNING;
  owner->operation_in_flight = false;
  output_result->identity = identity;
  memcpy(
      output_result->signed_runtime_sha256,
      owner->signed_runtime_sha256,
      sizeof(output_result->signed_runtime_sha256));
  output_result->lifecycle_handle = handle;
  status = winn_owner_unlock(owner);
  goto finish;

reconcile_failure_with_possible_handle:
  if (handle >= 0 && owner->engine != NULL) {
    owner->owned_handle = handle;
    start_status = winn_stop_engine_unlocked(
        owner, &cleanup_stop, &poison);
    if (cleanup_stop.invocation !=
        WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED) {
      output_result->lifecycle_handle = handle;
      status = WINN_STAGE_B_PROVIDER_NATIVE_STOP_NOT_INVOKED;
    } else {
      cleanup_invocation_returned = true;
      if (start_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
        status = start_status;
      }
    }
  }

reconcile_failure_without_handle:
  if (attempt_id != 0U) {
    cleanup_status = owner->dependencies.abandon_attempt(
        attempt_id, owner->dependencies.context);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      poison = true;
      status = cleanup_status;
    }
  }
  if (owner->engine != NULL && owner->owned_handle < 0) {
    owner->dependencies.destroy_engine(
        &owner->engine, owner->dependencies.context);
  }
  cleanup_status = winn_owner_lock(owner);
  if (cleanup_status == WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    owner->operation_in_flight = false;
    if (cleanup_invocation_returned) {
      owner->state =
          poison
              ? WINN_STAGE_B_PROVIDER_NATIVE_STATE_POISONED_AFTER_STOP_INVOCATION
              : WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOPPED;
    } else if (owner->owned_handle >= 0) {
      owner->state =
          WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOP_PENDING_NOT_INVOKED;
    } else if (poison) {
      owner->state =
          WINN_STAGE_B_PROVIDER_NATIVE_STATE_POISONED_AFTER_STOP_INVOCATION;
    } else {
      owner->state = WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOPPED;
    }
    cleanup_status = winn_owner_unlock(owner);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      poison = true;
      status = cleanup_status;
    }
  } else {
    poison = true;
    status = cleanup_status;
  }
  if (cleanup_invocation_returned || owner->owned_handle < 0) {
    cleanup_status = winn_registry_release_active(owner, poison);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = cleanup_status;
    }
  }
  goto finish;

unrecoverable:
  if (active_reserved) {
    cleanup_status = winn_registry_release_active(owner, true);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = cleanup_status;
    }
  }

finish:
  winn_release_secret(&secret);
  winn_secure_zero(&local_start, sizeof(local_start));
  winn_secure_zero(&identity, sizeof(identity));
  if (output_result != NULL && handle >= 0 &&
      !cleanup_invocation_returned) {
    cleanup_handle = handle;
  }
  final_status = winn_leave_owner_public(owner, status);
  if (final_status != WINN_STAGE_B_PROVIDER_NATIVE_OK &&
      output_result != NULL) {
    memset(output_result, 0, sizeof(*output_result));
    output_result->lifecycle_handle = cleanup_handle;
  }
  return final_status;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_abandon(
    const WinnStageBProviderNativeOwner *owner_handle,
    const WinnStageBProviderNativeGeneration *generation) {
  WinnStageBProviderNativeOwnerStorage *owner = NULL;
  WinnStageBProviderNativeStatus status;
  WinnStageBProviderNativeStatus unlock_status;
  uint64_t attempt_id = 0U;
  status = winn_enter_owner_public(owner_handle, &owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  if (!winn_generation_valid(generation)) {
    return winn_leave_owner_public(
        owner, WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT);
  }
  status = winn_owner_lock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return winn_leave_owner_public(owner, status);
  }
  if (!winn_generation_equal(&owner->generation, generation)) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_GENERATION_MISMATCH;
  } else if (
      owner->state != WINN_STAGE_B_PROVIDER_NATIVE_STATE_STARTING &&
      owner->state !=
          WINN_STAGE_B_PROVIDER_NATIVE_STATE_ABANDON_REQUESTED) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_INVALID_STATE;
  } else {
    owner->cancel_requested = true;
    owner->state =
        WINN_STAGE_B_PROVIDER_NATIVE_STATE_ABANDON_REQUESTED;
    attempt_id = owner->loader_attempt_id;
    status = WINN_STAGE_B_PROVIDER_NATIVE_OK;
  }
  unlock_status = winn_owner_unlock(owner);
  if (unlock_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    status = unlock_status;
  } else if (status == WINN_STAGE_B_PROVIDER_NATIVE_OK &&
             attempt_id != 0U) {
    status = owner->dependencies.abandon_attempt(
        attempt_id, owner->dependencies.context);
  }
  return winn_leave_owner_public(owner, status);
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_capture(
    const WinnStageBProviderNativeOwner *owner_handle,
    const WinnStageBProviderNativeGeneration *generation,
    WinnStageBProviderNativeCapture *output_capture) {
  WinnStageBProviderNativeOwnerStorage *owner = NULL;
  WinnStageBProviderNativeStatus status;
  WinnStageBProviderNativeStatus final_status;
  WinnStageBProviderNativeStatus unlock_status;
  WinnStageBNativeObservation observation;
  uint64_t ordinal;
  if (output_capture != NULL) {
    memset(output_capture, 0, sizeof(*output_capture));
  }
  memset(&observation, 0, sizeof(observation));
  status = winn_enter_owner_public(owner_handle, &owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  if (!winn_generation_valid(generation) || output_capture == NULL) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT;
    goto finish;
  }
  status = winn_owner_lock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    goto finish;
  }
  if (!winn_generation_equal(&owner->generation, generation)) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_GENERATION_MISMATCH;
    unlock_status = winn_owner_unlock(owner);
    if (unlock_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = unlock_status;
    }
    goto finish;
  }
  if (owner->state != WINN_STAGE_B_PROVIDER_NATIVE_STATE_RUNNING ||
      owner->operation_in_flight) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_BUSY;
    unlock_status = winn_owner_unlock(owner);
    if (unlock_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = unlock_status;
    }
    goto finish;
  }
  if (owner->capture_ordinal == UINT64_MAX) {
    status =
        WINN_STAGE_B_PROVIDER_NATIVE_CAPTURE_COUNTER_EXHAUSTED;
    unlock_status = winn_owner_unlock(owner);
    if (unlock_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = unlock_status;
    }
    goto finish;
  }
  owner->operation_in_flight = true;
  ordinal = owner->capture_ordinal + 1U;
  unlock_status = winn_owner_unlock(owner);
  if (unlock_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    status = unlock_status;
    goto finish;
  }
  status = owner->dependencies.capture(
      owner->engine, &observation, owner->dependencies.context);
  if (winn_owner_lock(owner) != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED;
    goto finish;
  }
  owner->operation_in_flight = false;
  if (status == WINN_STAGE_B_PROVIDER_NATIVE_OK &&
      owner->state == WINN_STAGE_B_PROVIDER_NATIVE_STATE_RUNNING) {
    owner->capture_ordinal = ordinal;
    output_capture->capture_ordinal = ordinal;
    output_capture->observation = observation;
  } else if (status == WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_INVALID_STATE;
  }
  unlock_status = winn_owner_unlock(owner);
  if (unlock_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    status = unlock_status;
  }

finish:
  winn_secure_zero(&observation, sizeof(observation));
  final_status = winn_leave_owner_public(owner, status);
  if (final_status != WINN_STAGE_B_PROVIDER_NATIVE_OK &&
      output_capture != NULL) {
    memset(output_capture, 0, sizeof(*output_capture));
  }
  return final_status;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_stop(
    const WinnStageBProviderNativeOwner *owner_handle,
    const WinnStageBProviderNativeGeneration *generation,
    int32_t expected_handle,
    WinnStageBProviderNativeStopResult *output_result) {
  WinnStageBProviderNativeOwnerStorage *owner = NULL;
  WinnStageBProviderNativeStatus status;
  WinnStageBProviderNativeStatus final_status;
  WinnStageBProviderNativeStatus cleanup_status;
  bool poison = false;
  bool invocation_returned = false;
  if (output_result != NULL) {
    memset(output_result, 0, sizeof(*output_result));
    output_result->lifecycle_handle = -1;
  }
  status = winn_enter_owner_public(owner_handle, &owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  if (!winn_generation_valid(generation) ||
      expected_handle < 0 || output_result == NULL) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT;
    goto finish;
  }
  status = winn_owner_lock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    goto finish;
  }
  if (!winn_generation_equal(&owner->generation, generation)) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_GENERATION_MISMATCH;
    cleanup_status = winn_owner_unlock(owner);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = cleanup_status;
    }
    goto finish;
  }
  if (owner->owned_handle != expected_handle) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_HANDLE_MISMATCH;
    cleanup_status = winn_owner_unlock(owner);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = cleanup_status;
    }
    goto finish;
  }
  if ((owner->state != WINN_STAGE_B_PROVIDER_NATIVE_STATE_RUNNING &&
       owner->state !=
           WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOP_PENDING_NOT_INVOKED) ||
      owner->operation_in_flight) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_BUSY;
    cleanup_status = winn_owner_unlock(owner);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = cleanup_status;
    }
    goto finish;
  }
  owner->state = WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOPPING;
  owner->operation_in_flight = true;
  status = winn_owner_unlock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    goto finish;
  }
  status = winn_stop_engine_unlocked(owner, output_result, &poison);
  invocation_returned =
      output_result->invocation ==
      WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED;
  if (winn_owner_lock(owner) != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    status = WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED;
    poison = true;
  } else {
    owner->operation_in_flight = false;
    if (invocation_returned) {
      owner->state =
          poison
              ? WINN_STAGE_B_PROVIDER_NATIVE_STATE_POISONED_AFTER_STOP_INVOCATION
              : WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOPPED;
    } else {
      owner->state =
          WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOP_PENDING_NOT_INVOKED;
    }
    cleanup_status = winn_owner_unlock(owner);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = cleanup_status;
      poison = true;
    }
  }
  if (invocation_returned) {
    output_result->owner_poisoned_after_invocation =
        poison ? 1U : output_result->owner_poisoned_after_invocation;
    cleanup_status = winn_registry_release_active(owner, poison);
    if (cleanup_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      status = cleanup_status;
      output_result->owner_poisoned_after_invocation = 1U;
    }
  }

finish:
  final_status = winn_leave_owner_public(owner, status);
  if (final_status != WINN_STAGE_B_PROVIDER_NATIVE_OK &&
      output_result != NULL) {
    if (invocation_returned) {
      output_result->invocation =
          WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED;
      output_result->lifecycle_handle = expected_handle;
      output_result->lifecycle_acknowledgement_permitted = 1U;
      output_result->owner_poisoned_after_invocation = 1U;
    } else {
      memset(output_result, 0, sizeof(*output_result));
      output_result->lifecycle_handle = -1;
    }
  }
  return final_status;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_state(
    const WinnStageBProviderNativeOwner *owner_handle,
    WinnStageBProviderNativeState *output_state) {
  WinnStageBProviderNativeOwnerStorage *owner = NULL;
  WinnStageBProviderNativeStatus status;
  WinnStageBProviderNativeStatus final_status;
  if (output_state != NULL) {
    *output_state = WINN_STAGE_B_PROVIDER_NATIVE_STATE_READY;
  }
  status = winn_enter_owner_public(owner_handle, &owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    return status;
  }
  if (output_state == NULL) {
    return winn_leave_owner_public(
        owner, WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT);
  }
  status = winn_owner_lock(owner);
  if (status == WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    *output_state = owner->state;
    status = winn_owner_unlock(owner);
  }
  final_status = winn_leave_owner_public(owner, status);
  if (final_status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    *output_state = WINN_STAGE_B_PROVIDER_NATIVE_STATE_READY;
  }
  return final_status;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_destroy(
    WinnStageBProviderNativeOwner *owner_handle) {
  WinnStageBProviderNativeOwnerStorage *owner = NULL;
  WinnStageBProviderNativeOwnerDependencies dependencies;
  WinnStageBProviderNativeStatus status;
  WinnStageBProviderNativeStatus cleanup_status;
  if (!winn_enter_public()) {
    return WINN_STAGE_B_PROVIDER_NATIVE_REENTRANT;
  }
  if (owner_handle == NULL) {
    winn_leave_public();
    return WINN_STAGE_B_PROVIDER_NATIVE_INVALID_ARGUMENT;
  }
  if (owner_handle->storage_address == (uintptr_t)0 &&
      owner_handle->lifecycle_token == 0U) {
    winn_leave_public();
    return WINN_STAGE_B_PROVIDER_NATIVE_OK;
  }
  status = winn_registry_mark_destroying(owner_handle, &owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    winn_leave_public();
    return status;
  }
  status = winn_owner_lock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    cleanup_status = winn_registry_unmark_destroying(owner);
    winn_leave_public();
    return cleanup_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
               ? status
               : cleanup_status;
  }
  if (owner->operation_in_flight || owner->engine != NULL ||
      (owner->state != WINN_STAGE_B_PROVIDER_NATIVE_STATE_READY &&
       owner->state != WINN_STAGE_B_PROVIDER_NATIVE_STATE_STOPPED &&
       owner->state !=
           WINN_STAGE_B_PROVIDER_NATIVE_STATE_POISONED_AFTER_STOP_INVOCATION)) {
    status = winn_owner_unlock(owner);
    cleanup_status = winn_registry_unmark_destroying(owner);
    winn_leave_public();
    if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
      return status;
    }
    return cleanup_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
               ? WINN_STAGE_B_PROVIDER_NATIVE_BUSY
               : cleanup_status;
  }
  status = winn_owner_unlock(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    cleanup_status = winn_registry_unmark_destroying(owner);
    winn_leave_public();
    return cleanup_status == WINN_STAGE_B_PROVIDER_NATIVE_OK
               ? status
               : cleanup_status;
  }
  dependencies = owner->dependencies;
  status = winn_registry_remove_destroying(owner);
  if (status != WINN_STAGE_B_PROVIDER_NATIVE_OK) {
    winn_leave_public();
    return status;
  }
  memset(owner_handle, 0, sizeof(*owner_handle));
  if (pthread_mutex_destroy(&owner->mutex) != 0) {
    winn_leave_public();
    return WINN_STAGE_B_PROVIDER_NATIVE_LOCK_FAILED;
  }
  winn_secure_zero(owner, sizeof(*owner));
  dependencies.release_owner(
      owner, sizeof(*owner), dependencies.context);
  winn_leave_public();
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}
