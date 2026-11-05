#ifndef WINN_STAGE_B_PROVIDER_NATIVE_OWNER_INTERNAL_H
#define WINN_STAGE_B_PROVIDER_NATIVE_OWNER_INTERNAL_H

#include "WinnStageBFrameworkLoader.h"
#include "WinnStageBProviderNativeOwner.h"

#if !defined(WINN_STAGE_B_PROVIDER_NATIVE_OWNER_TESTING)
#error "native-owner internal seam is test-only"
#endif

typedef struct WinnStageBProviderNativeOwnerDependencies {
  void *(*allocate_owner)(size_t allocation_size, void *context);
  void (*release_owner)(
      void *allocation,
      size_t allocation_size,
      void *context);
  WinnStageBProviderNativeStatus (*load_framework)(
      const void **output_image,
      uint8_t output_runtime_sha256[32],
      void *context);
  WinnStageBProviderNativeStatus (*begin_attempt)(
      uint64_t *output_attempt_id,
      void *context);
  WinnStageBProviderNativeStatus (*abandon_attempt)(
      uint64_t attempt_id,
      void *context);
  WinnStageBProviderNativeStatus (*create_engine)(
      void *owner_context,
      void **output_engine,
      void *context);
  WinnStageBProviderNativeStatus (*start_pinned)(
      void *owner_context,
      void *engine,
      const WinnStageBProviderNativeStart *start,
      WinnStageBNativeIdentity *output_identity,
      int32_t *output_handle,
      uint8_t *output_action_was_called,
      void *context);
  WinnStageBProviderNativeStatus (*capture)(
      void *engine,
      WinnStageBNativeObservation *output_observation,
      void *context);
  WinnStageBFrameworkStatus (*turn_off_checked)(
      const void *image,
      int32_t handle,
      WinnStageBFrameworkTurnOffObservation *output_observation,
      void *context);
  WinnStageBProviderNativeStatus (*record_external_stop)(
      void *engine,
      int32_t handle,
      void *context);
  void (*destroy_engine)(void **engine, void *context);
  void *context;
} WinnStageBProviderNativeOwnerDependencies;

typedef enum WinnStageBProviderNativeOwnerFaultPoint {
  WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_NONE = 0,
  WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_OWNER_UNLOCK = 1,
  WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_REGISTER_PUBLICATION = 2,
  WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_ACTIVE_RELEASE_PUBLICATION = 3,
  WINN_STAGE_B_PROVIDER_NATIVE_OWNER_FAULT_CALL_RELEASE_PUBLICATION = 4
} WinnStageBProviderNativeOwnerFaultPoint;

WinnStageBProviderNativeStatus
winn_stage_b_provider_native_owner_create_for_testing(
    const WinnStageBProviderNativeOwnerDependencies *dependencies,
    WinnStageBProviderNativeOwner *output_owner);

int winn_stage_b_provider_native_owner_reset_registry_for_testing(void);

int winn_stage_b_provider_native_owner_set_fault_for_testing(
    WinnStageBProviderNativeOwnerFaultPoint point,
    uint64_t fail_ordinal);

void winn_stage_b_provider_native_owner_record_callback_for_testing(
    void *owner_context,
    int32_t callback_handle);

#endif
