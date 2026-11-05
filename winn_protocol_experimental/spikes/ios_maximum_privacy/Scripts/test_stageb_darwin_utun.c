#include "../NativeEngine/WinnStageBDarwinUtun.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/un.h>

#define CHECK(expression)                                                   \
  do {                                                                      \
    if (!(expression)) {                                                    \
      fprintf(stderr, "check failed at line %d\n", __LINE__);               \
      return 1;                                                             \
    }                                                                       \
  } while (0)

_Static_assert(
    sizeof(struct sockaddr_ctl) == sizeof(WinnStageBDarwinSockaddrCtl),
    "sockaddr_ctl ABI mirror size mismatch");
_Static_assert(
    _Alignof(struct sockaddr_ctl) ==
        _Alignof(WinnStageBDarwinSockaddrCtl),
    "sockaddr_ctl ABI mirror alignment mismatch");
_Static_assert(
    offsetof(struct sockaddr_ctl, sc_len) ==
        offsetof(WinnStageBDarwinSockaddrCtl, length) &&
        offsetof(struct sockaddr_ctl, sc_family) ==
            offsetof(WinnStageBDarwinSockaddrCtl, family) &&
        offsetof(struct sockaddr_ctl, ss_sysaddr) ==
            offsetof(WinnStageBDarwinSockaddrCtl, system_address) &&
        offsetof(struct sockaddr_ctl, sc_id) ==
            offsetof(WinnStageBDarwinSockaddrCtl, control_id) &&
        offsetof(struct sockaddr_ctl, sc_unit) ==
            offsetof(WinnStageBDarwinSockaddrCtl, unit) &&
        offsetof(struct sockaddr_ctl, sc_reserved) ==
            offsetof(WinnStageBDarwinSockaddrCtl, reserved),
    "sockaddr_ctl ABI mirror offsets mismatch");
_Static_assert(
    sizeof(struct ctl_info) == sizeof(WinnStageBDarwinCtlInfo),
    "ctl_info ABI mirror size mismatch");
_Static_assert(
    _Alignof(struct ctl_info) == _Alignof(WinnStageBDarwinCtlInfo),
    "ctl_info ABI mirror alignment mismatch");
_Static_assert(
    offsetof(struct ctl_info, ctl_id) ==
        offsetof(WinnStageBDarwinCtlInfo, control_id) &&
        offsetof(struct ctl_info, ctl_name) ==
            offsetof(WinnStageBDarwinCtlInfo, control_name),
    "ctl_info ABI mirror offsets mismatch");
_Static_assert(
    AF_SYSTEM == WINN_STAGE_B_DARWIN_AF_SYSTEM &&
        AF_SYS_CONTROL == WINN_STAGE_B_DARWIN_AF_SYS_CONTROL &&
        SYSPROTO_CONTROL == WINN_STAGE_B_DARWIN_SYSPROTO_CONTROL &&
        UTUN_OPT_IFNAME == WINN_STAGE_B_DARWIN_UTUN_OPT_IFNAME,
    "Darwin control constant mismatch");

enum {
  TEST_FD_CEILING = 32,
  TEST_ORIGINAL_FD = 5,
  TEST_SECOND_FD = 7,
  TEST_DUPLICATE_FD = 20
};

typedef enum Fault {
  FAULT_NONE = 0,
  FAULT_GATE_ACQUIRE,
  FAULT_GATE_RELEASE,
  FAULT_CEILING_FAILURE,
  FAULT_CEILING_ZERO,
  FAULT_CEILING_OVERSIZE,
  FAULT_CEILING_UNBOUNDED,
  FAULT_CEILING_CHANGE_SECOND,
  FAULT_CEILING_CHANGE_THIRD,
  FAULT_FCNTL_SCAN_ERROR,
  FAULT_ZERO,
  FAULT_INITIAL_MULTIPLE,
  FAULT_HIDDEN_SECOND_ABOVE_LOWERED_SOFT,
  FAULT_ORDINARY_UNEXPECTED_EINTR,
  FAULT_ORDINARY_UNEXPECTED_EBADF,
  FAULT_ORDINARY_OVERSIZE_ADDRESS,
  FAULT_PEER_LENGTH,
  FAULT_PEER_OVERSIZE,
  FAULT_PEER_SC_LENGTH,
  FAULT_PEER_SYSADDR,
  FAULT_CONTROL_INFO_FAILURE,
  FAULT_CONTROL_NAME_MUTATION,
  FAULT_CONTROL_NAME_TAIL_MUTATION,
  FAULT_CONTROL_ZERO_ID,
  FAULT_CONTROL_ID_MISMATCH,
  FAULT_ZERO_UNIT,
  FAULT_RESERVED,
  FAULT_GETSOCKOPT_FAILURE,
  FAULT_BAD_IFNAME,
  FAULT_BAD_IFNAME_LENGTH,
  FAULT_OVERSIZE_IFNAME_LENGTH,
  FAULT_DUP_FAILURE,
  FAULT_DUP_RETURNS_ORIGINAL,
  FAULT_DUP_OUTSIDE_LIMIT,
  FAULT_DUP_INITIAL_FCNTL_FAILURE,
  FAULT_DUP_NO_CLOEXEC,
  FAULT_DUP_BEFORE_FCNTL_FAILURE,
  FAULT_DUP_BEFORE_GETPEER_FAILURE,
  FAULT_DUP_BEFORE_PEER_MUTATION,
  FAULT_DUP_BEFORE_CONTROL_MUTATION,
  FAULT_DUP_BEFORE_IFNAME_MUTATION,
  FAULT_RESCAN_ADD_SECOND,
  FAULT_RESCAN_REMOVE_ORIGINAL,
  FAULT_RESCAN_ORIGINAL_MUTATION,
  FAULT_DUP_AFTER_FCNTL_FAILURE,
  FAULT_DUP_AFTER_GETPEER_FAILURE,
  FAULT_DUP_AFTER_PEER_MUTATION,
  FAULT_DUP_AFTER_CONTROL_MUTATION,
  FAULT_DUP_AFTER_IFNAME_MUTATION,
  FAULT_CLOSE_FAILURE
} Fault;

typedef struct Fake {
  Fault fault;
  uint64_t fd_ceiling;
  uint64_t advisory_soft_limit;
  int32_t original_fd;
  uint32_t unit;
  unsigned gate_acquire_count;
  unsigned gate_release_count;
  unsigned ceiling_count;
  int gate_held;
  int gate_violation;
  unsigned duplicate_fcntl_count;
  unsigned duplicate_getpeer_count;
  unsigned duplicate_control_count;
  unsigned duplicate_ifname_count;
  unsigned dup_count;
  unsigned close_count;
  int32_t closed_fd;
  int close_while_gate_held;
  int observed_wrong_getsockopt_arguments;
} Fake;

static int in_rescan(const Fake *fake) {
  return fake->duplicate_getpeer_count >= 1U;
}

static int fake_acquire_gate(void *context) {
  Fake *fake = (Fake *)context;
  ++fake->gate_acquire_count;
  if (fake->fault == FAULT_GATE_ACQUIRE || fake->gate_held != 0) {
    return -1;
  }
  fake->gate_held = 1;
  return 0;
}

static int fake_release_gate(void *context) {
  Fake *fake = (Fake *)context;
  ++fake->gate_release_count;
  if (fake->gate_held == 0) {
    fake->gate_violation = 1;
    return -1;
  }
  fake->gate_held = 0;
  return fake->fault == FAULT_GATE_RELEASE ? -1 : 0;
}

static int fake_get_process_fd_ceiling(
    uint64_t *output_fd_ceiling,
    void *context) {
  Fake *fake = (Fake *)context;
  ++fake->ceiling_count;
  if (fake->gate_held == 0) {
    fake->gate_violation = 1;
  }
  if (fake->fault == FAULT_CEILING_FAILURE) {
    return -1;
  }
  *output_fd_ceiling = fake->fd_ceiling;
  if (fake->fault == FAULT_CEILING_ZERO) {
    *output_fd_ceiling = 0U;
  } else if (fake->fault == FAULT_CEILING_OVERSIZE) {
    *output_fd_ceiling =
        (uint64_t)WINN_STAGE_B_DARWIN_MAX_FD_CEILING + 1U;
  } else if (fake->fault == FAULT_CEILING_UNBOUNDED) {
    *output_fd_ceiling = UINT64_MAX;
  } else if (fake->fault == FAULT_CEILING_CHANGE_SECOND &&
             fake->ceiling_count == 2U) {
    *output_fd_ceiling = fake->fd_ceiling - 1U;
  } else if (fake->fault == FAULT_CEILING_CHANGE_THIRD &&
             fake->ceiling_count == 3U) {
    *output_fd_ceiling = fake->fd_ceiling - 1U;
  }
  return 0;
}

static int fake_fcntl_getfd(
    int32_t fd,
    int32_t *output_flags,
    int32_t *output_errno,
    void *context) {
  Fake *fake = (Fake *)context;
  int live = 0;
  if (fake->gate_held == 0) {
    fake->gate_violation = 1;
  }
  *output_flags = 0;
  *output_errno = 0;

  if (fd == TEST_DUPLICATE_FD && fake->dup_count != 0U) {
    ++fake->duplicate_fcntl_count;
    if ((fake->fault == FAULT_DUP_INITIAL_FCNTL_FAILURE &&
         fake->duplicate_fcntl_count == 1U) ||
        (fake->fault == FAULT_DUP_BEFORE_FCNTL_FAILURE &&
         fake->duplicate_fcntl_count == 2U) ||
        (fake->fault == FAULT_DUP_AFTER_FCNTL_FAILURE &&
         fake->duplicate_fcntl_count == 3U)) {
      *output_errno = EIO;
      return -1;
    }
    *output_flags =
        fake->fault == FAULT_DUP_NO_CLOEXEC ? 0 : FD_CLOEXEC;
    return 0;
  }
  if (fd == 6 && fake->fault == FAULT_FCNTL_SCAN_ERROR) {
    *output_errno = EIO;
    return -1;
  }
  if (fd >= 0 && fd <= 4) {
    live = 1;
  }
  if (fd == fake->original_fd &&
      fake->fault != FAULT_ZERO &&
      !(in_rescan(fake) &&
        fake->fault == FAULT_RESCAN_REMOVE_ORIGINAL)) {
    live = 1;
  }
  if (fd == TEST_SECOND_FD &&
      (fake->fault == FAULT_INITIAL_MULTIPLE ||
       (in_rescan(fake) &&
        fake->fault == FAULT_RESCAN_ADD_SECOND))) {
    live = 1;
  }
  if (fd == 12 &&
      fake->fault == FAULT_HIDDEN_SECOND_ABOVE_LOWERED_SOFT) {
    live = 1;
  }
  if (live != 0) {
    return 0;
  }
  *output_errno = EBADF;
  return -1;
}

static void fill_noncandidate_address(
    int32_t fd,
    struct sockaddr_storage *storage,
    socklen_t *address_length) {
  if (fd == 2) {
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_len = (uint8_t)sizeof(address);
    address.sin_family = AF_INET;
    memcpy(storage, &address, sizeof(address));
    *address_length = (socklen_t)sizeof(address);
  } else if (fd == 3) {
    struct sockaddr_in6 address;
    memset(&address, 0, sizeof(address));
    address.sin6_len = (uint8_t)sizeof(address);
    address.sin6_family = AF_INET6;
    memcpy(storage, &address, sizeof(address));
    *address_length = (socklen_t)sizeof(address);
  } else {
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_len = (uint8_t)sizeof(address);
    address.sun_family = AF_UNIX;
    memcpy(storage, &address, sizeof(address));
    *address_length = (socklen_t)sizeof(address);
  }
}

static int fake_getpeername(
    int32_t fd,
    struct sockaddr_storage *storage,
    socklen_t *address_length,
    int32_t *output_errno,
    void *context) {
  Fake *fake = (Fake *)context;
  WinnStageBDarwinSockaddrCtl address;
  int duplicate_before;
  int duplicate_after;

  *output_errno = 0;
  memset(storage, 0, sizeof(*storage));
  if (fd == 0) {
    *output_errno =
        fake->fault == FAULT_ORDINARY_UNEXPECTED_EINTR
            ? EINTR
            : (fake->fault == FAULT_ORDINARY_UNEXPECTED_EBADF
                   ? EBADF
                   : ENOTSOCK);
    return -1;
  }
  if (fd == 1) {
    *output_errno = ENOTCONN;
    return -1;
  }
  if (fd >= 2 && fd <= 4) {
    fill_noncandidate_address(fd, storage, address_length);
    if (fake->fault == FAULT_ORDINARY_OVERSIZE_ADDRESS &&
        fd == 2) {
      *address_length =
          (socklen_t)(sizeof(*storage) + 1U);
    }
    return 0;
  }

  duplicate_before = fd == TEST_DUPLICATE_FD &&
                     fake->duplicate_getpeer_count == 0U;
  duplicate_after = fd == TEST_DUPLICATE_FD &&
                    fake->duplicate_getpeer_count == 1U;
  if (fd == TEST_DUPLICATE_FD) {
    ++fake->duplicate_getpeer_count;
  }
  if ((fake->fault == FAULT_DUP_BEFORE_GETPEER_FAILURE &&
       duplicate_before != 0) ||
      (fake->fault == FAULT_DUP_AFTER_GETPEER_FAILURE &&
       duplicate_after != 0)) {
    *output_errno = EINTR;
    return -1;
  }

  memset(&address, 0, sizeof(address));
  address.length = (uint8_t)sizeof(address);
  address.family = (uint8_t)WINN_STAGE_B_DARWIN_AF_SYSTEM;
  address.system_address =
      (uint16_t)WINN_STAGE_B_DARWIN_AF_SYS_CONTROL;
  address.control_id = 42U;
  address.unit =
      (fd == TEST_SECOND_FD || fd == 12) ? 4U : fake->unit;
  *address_length = (socklen_t)sizeof(address);

  if (fd == fake->original_fd && !in_rescan(fake)) {
    if (fake->fault == FAULT_PEER_LENGTH) {
      *address_length -= 1U;
    } else if (fake->fault == FAULT_PEER_OVERSIZE) {
      *address_length =
          (socklen_t)(sizeof(*storage) + 1U);
    } else if (fake->fault == FAULT_PEER_SC_LENGTH) {
      address.length -= 1U;
    } else if (fake->fault == FAULT_PEER_SYSADDR) {
      address.system_address = 99U;
    } else if (fake->fault == FAULT_CONTROL_ID_MISMATCH) {
      address.control_id = 41U;
    } else if (fake->fault == FAULT_ZERO_UNIT) {
      address.unit = 0U;
    } else if (fake->fault == FAULT_RESERVED) {
      address.reserved[2] = 1U;
    }
  }
  if (fake->fault == FAULT_RESCAN_ORIGINAL_MUTATION &&
      fd == fake->original_fd && in_rescan(fake)) {
    address.unit = 9U;
  }
  if (fake->fault == FAULT_DUP_BEFORE_PEER_MUTATION &&
      duplicate_before != 0) {
    address.unit = 10U;
  }
  if (fake->fault == FAULT_DUP_AFTER_PEER_MUTATION &&
      duplicate_after != 0) {
    address.unit = 11U;
  }
  memcpy(storage, &address, sizeof(address));
  return 0;
}

static int fake_ctl_iocginfo(
    int32_t fd,
    WinnStageBDarwinCtlInfo *control_info,
    void *context) {
  Fake *fake = (Fake *)context;
  int duplicate_before = 0;
  int duplicate_after = 0;
  if (memcmp(
          control_info->control_name,
          WINN_STAGE_B_DARWIN_UTUN_CONTROL_NAME,
          sizeof(WINN_STAGE_B_DARWIN_UTUN_CONTROL_NAME)) != 0) {
    return -1;
  }
  if (fd == TEST_DUPLICATE_FD) {
    ++fake->duplicate_control_count;
    duplicate_before = fake->duplicate_control_count == 1U;
    duplicate_after = fake->duplicate_control_count == 2U;
  }
  if (fake->fault == FAULT_CONTROL_INFO_FAILURE &&
      fd == fake->original_fd && !in_rescan(fake)) {
    return -1;
  }
  control_info->control_id = 42U;
  if (fake->fault == FAULT_CONTROL_NAME_MUTATION &&
      fd == fake->original_fd && !in_rescan(fake)) {
    control_info->control_name[0] = 'X';
  }
  if (fake->fault == FAULT_CONTROL_NAME_TAIL_MUTATION &&
      fd == fake->original_fd && !in_rescan(fake)) {
    control_info->control_name[
        WINN_STAGE_B_DARWIN_MAX_KCTL_NAME - 1] = 'X';
  }
  if (fake->fault == FAULT_CONTROL_ZERO_ID &&
      fd == fake->original_fd && !in_rescan(fake)) {
    control_info->control_id = 0U;
  }
  if ((fake->fault == FAULT_DUP_BEFORE_CONTROL_MUTATION &&
       duplicate_before != 0) ||
      (fake->fault == FAULT_DUP_AFTER_CONTROL_MUTATION &&
       duplicate_after != 0)) {
    control_info->control_id = 99U;
  }
  return 0;
}

static const char *expected_ifname(const Fake *fake, int32_t fd) {
  if (fd == TEST_SECOND_FD || fd == 12) {
    return "utun3";
  }
  if (fake->unit == UINT32_MAX) {
    return "utun4294967294";
  }
  return "utun2";
}

static int fake_getsockopt(
    int32_t fd,
    int32_t level,
    int32_t option_name,
    void *option_value,
    socklen_t *option_length,
    void *context) {
  Fake *fake = (Fake *)context;
  const char *name = expected_ifname(fake, fd);
  size_t length = strlen(name) + 1U;
  int duplicate_before = 0;
  int duplicate_after = 0;
  if (level != WINN_STAGE_B_DARWIN_SYSPROTO_CONTROL ||
      option_name != WINN_STAGE_B_DARWIN_UTUN_OPT_IFNAME) {
    fake->observed_wrong_getsockopt_arguments = 1;
    return -1;
  }
  if (fd == TEST_DUPLICATE_FD) {
    ++fake->duplicate_ifname_count;
    duplicate_before = fake->duplicate_ifname_count == 1U;
    duplicate_after = fake->duplicate_ifname_count == 2U;
  }
  if (fake->fault == FAULT_GETSOCKOPT_FAILURE &&
      fd == fake->original_fd && !in_rescan(fake)) {
    return -1;
  }
  if (fake->fault == FAULT_BAD_IFNAME &&
      fd == fake->original_fd && !in_rescan(fake)) {
    name = "utun03";
    length = strlen(name) + 1U;
  }
  if ((fake->fault == FAULT_DUP_BEFORE_IFNAME_MUTATION &&
       duplicate_before != 0) ||
      (fake->fault == FAULT_DUP_AFTER_IFNAME_MUTATION &&
       duplicate_after != 0)) {
    name = "utun12";
    length = strlen(name) + 1U;
  }
  if (*option_length < (socklen_t)length) {
    return -1;
  }
  memcpy(option_value, name, length);
  *option_length = (socklen_t)length;
  if (fake->fault == FAULT_BAD_IFNAME_LENGTH &&
      fd == fake->original_fd && !in_rescan(fake)) {
    *option_length -= 1U;
  }
  if (fake->fault == FAULT_OVERSIZE_IFNAME_LENGTH &&
      fd == fake->original_fd && !in_rescan(fake)) {
    *option_length =
        (socklen_t)(WINN_STAGE_B_DARWIN_IFNAME_CAPACITY + 1);
  }
  return 0;
}

static int32_t fake_dupfd_cloexec(
    int32_t fd,
    int32_t minimum_fd,
    void *context) {
  Fake *fake = (Fake *)context;
  ++fake->dup_count;
  if (fd != fake->original_fd || minimum_fd != 0) {
    return -1;
  }
  if (fake->fault == FAULT_DUP_FAILURE) {
    return -1;
  }
  if (fake->fault == FAULT_DUP_RETURNS_ORIGINAL) {
    return fake->original_fd;
  }
  if (fake->fault == FAULT_DUP_OUTSIDE_LIMIT) {
    return (int32_t)fake->fd_ceiling;
  }
  return TEST_DUPLICATE_FD;
}

static int fake_close(int32_t fd, void *context) {
  Fake *fake = (Fake *)context;
  ++fake->close_count;
  fake->closed_fd = fd;
  fake->close_while_gate_held = fake->gate_held;
  return fake->fault == FAULT_CLOSE_FAILURE ? -1 : 0;
}

static Fake make_fake(void) {
  Fake fake;
  memset(&fake, 0, sizeof(fake));
  fake.fd_ceiling = TEST_FD_CEILING;
  fake.advisory_soft_limit = 8U;
  fake.original_fd = TEST_ORIGINAL_FD;
  fake.unit = 3U;
  fake.closed_fd = -1;
  return fake;
}

static WinnStageBDarwinUtunSyscalls make_syscalls(Fake *fake) {
  WinnStageBDarwinUtunSyscalls result;
  memset(&result, 0, sizeof(result));
  result.acquire_descriptor_gate = fake_acquire_gate;
  result.release_descriptor_gate = fake_release_gate;
  result.get_process_fd_ceiling = fake_get_process_fd_ceiling;
  result.fcntl_getfd = fake_fcntl_getfd;
  result.getpeername = fake_getpeername;
  result.ctl_iocginfo = fake_ctl_iocginfo;
  result.getsockopt = fake_getsockopt;
  result.fcntl_dupfd_cloexec = fake_dupfd_cloexec;
  result.close_fd = fake_close;
  result.context = fake;
  return result;
}

typedef struct ActionProbe {
  Fake *fake;
  unsigned call_count;
  int32_t return_status;
  WinnStageBUtunCandidate observed;
  int gate_was_held;
  int duplicate_was_open;
  int concurrent_close_dup2_was_blocked;
} ActionProbe;

typedef struct ConcurrentHarness {
  Fake fake;
  pthread_mutex_t descriptor_gate;
  pthread_mutex_t state_lock;
  pthread_cond_t state_changed;
  pthread_t worker;
  int worker_created;
  int worker_attempting;
  int worker_acquired;
  int gate_trylock_was_blocked;
} ConcurrentHarness;

static int32_t fake_action(
    const WinnStageBUtunCandidate *candidate,
    void *context) {
  ActionProbe *probe = (ActionProbe *)context;
  ++probe->call_count;
  probe->observed = *candidate;
  probe->gate_was_held = probe->fake->gate_held;
  probe->duplicate_was_open =
      probe->fake->dup_count == 1U &&
      probe->fake->close_count == 0U &&
      candidate->file_descriptor == TEST_DUPLICATE_FD;
  /*
   * Models concurrent close/dup2/closefrom users sharing the mandatory gate.
   * They cannot mutate descriptor state while this synchronous action owns it.
   */
  probe->concurrent_close_dup2_was_blocked =
      probe->fake->gate_held != 0;
  return probe->return_status;
}

static int concurrent_acquire_gate(void *context) {
  ConcurrentHarness *harness = (ConcurrentHarness *)context;
  if (pthread_mutex_lock(&harness->descriptor_gate) != 0) {
    return -1;
  }
  ++harness->fake.gate_acquire_count;
  harness->fake.gate_held = 1;
  return 0;
}

static int concurrent_release_gate(void *context) {
  ConcurrentHarness *harness = (ConcurrentHarness *)context;
  ++harness->fake.gate_release_count;
  harness->fake.gate_held = 0;
  return pthread_mutex_unlock(&harness->descriptor_gate);
}

static void *concurrent_worker(void *context) {
  ConcurrentHarness *harness = (ConcurrentHarness *)context;
  (void)pthread_mutex_lock(&harness->state_lock);
  harness->worker_attempting = 1;
  (void)pthread_cond_signal(&harness->state_changed);
  (void)pthread_mutex_unlock(&harness->state_lock);
  if (concurrent_acquire_gate(harness) == 0) {
    (void)pthread_mutex_lock(&harness->state_lock);
    harness->worker_acquired = 1;
    (void)pthread_cond_signal(&harness->state_changed);
    (void)pthread_mutex_unlock(&harness->state_lock);
    (void)concurrent_release_gate(harness);
  }
  return NULL;
}

static int32_t concurrent_action(
    const WinnStageBUtunCandidate *candidate,
    void *context) {
  ConcurrentHarness *harness = (ConcurrentHarness *)context;
  int trylock_result;
  if (candidate->file_descriptor != TEST_DUPLICATE_FD ||
      harness->fake.gate_held == 0) {
    return -1;
  }
  if (pthread_create(
          &harness->worker,
          NULL,
          concurrent_worker,
          harness) != 0) {
    return -2;
  }
  harness->worker_created = 1;
  (void)pthread_mutex_lock(&harness->state_lock);
  while (harness->worker_attempting == 0) {
    (void)pthread_cond_wait(
        &harness->state_changed, &harness->state_lock);
  }
  (void)pthread_mutex_unlock(&harness->state_lock);
  trylock_result = pthread_mutex_trylock(
      &harness->descriptor_gate);
  harness->gate_trylock_was_blocked = trylock_result == EBUSY;
  if (trylock_result == 0) {
    (void)pthread_mutex_unlock(&harness->descriptor_gate);
  }
  return harness->gate_trylock_was_blocked != 0 ? 91 : -3;
}

static WinnStageBDarwinUtunStatus run_with_action(
    Fake *fake,
    ActionProbe *probe,
    WinnStageBDarwinActionResult *result) {
  WinnStageBDarwinUtunSyscalls syscalls = make_syscalls(fake);
  memset(probe, 0, sizeof(*probe));
  probe->fake = fake;
  probe->return_status = 77;
  return winn_stage_b_darwin_utun_with_pinned(
      &syscalls, fake_action, probe, result);
}

static int test_success_gate_lifetime(void) {
  Fake fake = make_fake();
  ActionProbe probe;
  WinnStageBDarwinActionResult result;
  memset(&result, 0xa5, sizeof(result));
  CHECK(run_with_action(&fake, &probe, &result) ==
        WINN_STAGE_B_DARWIN_UTUN_OK);
  CHECK(result.action_was_called == 1U);
  CHECK(result.action_status == 77);
  CHECK(result.reserved[0] == 0U && result.reserved[1] == 0U &&
        result.reserved[2] == 0U);
  CHECK(probe.call_count == 1U);
  CHECK(probe.gate_was_held != 0);
  CHECK(probe.duplicate_was_open != 0);
  CHECK(probe.concurrent_close_dup2_was_blocked != 0);
  CHECK(probe.observed.file_descriptor == TEST_DUPLICATE_FD);
  CHECK(probe.observed.peer_control_id == 42U);
  CHECK(probe.observed.utun_control_id == 42U);
  CHECK(probe.observed.unit == 3U);
  CHECK(probe.observed.peer_address_family ==
        (uint32_t)WINN_STAGE_B_DARWIN_AF_SYSTEM);
  CHECK(probe.observed.expected_system_address_family ==
        (uint32_t)WINN_STAGE_B_DARWIN_AF_SYSTEM);
  CHECK(probe.observed.peer_address_length_valid == 1U);
  CHECK(fake.ceiling_count == 3U);
  CHECK(fake.duplicate_fcntl_count == 3U);
  CHECK(fake.duplicate_getpeer_count == 2U);
  CHECK(fake.dup_count == 1U);
  CHECK(fake.close_count == 1U);
  CHECK(fake.closed_fd == TEST_DUPLICATE_FD);
  CHECK(fake.close_while_gate_held != 0);
  CHECK(fake.gate_acquire_count == 1U);
  CHECK(fake.gate_release_count == 1U);
  CHECK(fake.gate_held == 0);
  CHECK(fake.gate_violation == 0);
  CHECK(fake.observed_wrong_getsockopt_arguments == 0);
  return 0;
}

static int test_full_range_and_max_unit(void) {
  Fake fake = make_fake();
  ActionProbe probe;
  WinnStageBDarwinActionResult result;
  fake.original_fd = TEST_FD_CEILING - 1;
  fake.unit = UINT32_MAX;
  CHECK(run_with_action(&fake, &probe, &result) ==
        WINN_STAGE_B_DARWIN_UTUN_OK);
  CHECK(probe.observed.unit == UINT32_MAX);
  return 0;
}

static int test_concurrent_gate_spans_action_and_close(void) {
  ConcurrentHarness harness;
  WinnStageBDarwinUtunSyscalls syscalls;
  WinnStageBDarwinActionResult result;
  memset(&harness, 0, sizeof(harness));
  harness.fake = make_fake();
  CHECK(pthread_mutex_init(&harness.descriptor_gate, NULL) == 0);
  CHECK(pthread_mutex_init(&harness.state_lock, NULL) == 0);
  CHECK(pthread_cond_init(&harness.state_changed, NULL) == 0);
  syscalls = make_syscalls(&harness.fake);
  syscalls.acquire_descriptor_gate = concurrent_acquire_gate;
  syscalls.release_descriptor_gate = concurrent_release_gate;
  syscalls.context = &harness;

  CHECK(winn_stage_b_darwin_utun_with_pinned(
            &syscalls,
            concurrent_action,
            &harness,
            &result) == WINN_STAGE_B_DARWIN_UTUN_OK);
  CHECK(result.action_was_called == 1U);
  CHECK(result.action_status == 91);
  CHECK(harness.gate_trylock_was_blocked != 0);
  CHECK(harness.fake.close_count == 1U);
  CHECK(harness.fake.close_while_gate_held != 0);
  CHECK(harness.worker_created != 0);
  CHECK(pthread_join(harness.worker, NULL) == 0);
  CHECK(harness.worker_acquired != 0);
  CHECK(harness.fake.gate_acquire_count == 2U);
  CHECK(harness.fake.gate_release_count == 2U);
  CHECK(pthread_cond_destroy(&harness.state_changed) == 0);
  CHECK(pthread_mutex_destroy(&harness.state_lock) == 0);
  CHECK(pthread_mutex_destroy(&harness.descriptor_gate) == 0);
  return 0;
}

static int test_argument_rejection(void) {
  Fake fake = make_fake();
  WinnStageBDarwinUtunSyscalls syscalls = make_syscalls(&fake);
  WinnStageBDarwinUtunSyscalls incomplete = syscalls;
  ActionProbe probe;
  WinnStageBDarwinActionResult result;
  memset(&probe, 0, sizeof(probe));
  incomplete.acquire_descriptor_gate = NULL;
  CHECK(winn_stage_b_darwin_utun_with_pinned(
            NULL, fake_action, &probe, &result) ==
        WINN_STAGE_B_DARWIN_UTUN_INVALID_ARGUMENT);
  CHECK(winn_stage_b_darwin_utun_with_pinned(
            &incomplete, fake_action, &probe, &result) ==
        WINN_STAGE_B_DARWIN_UTUN_INVALID_ARGUMENT);
  CHECK(winn_stage_b_darwin_utun_with_pinned(
            &syscalls, NULL, &probe, &result) ==
        WINN_STAGE_B_DARWIN_UTUN_INVALID_ARGUMENT);
  CHECK(winn_stage_b_darwin_utun_with_pinned(
            &syscalls, fake_action, &probe, NULL) ==
        WINN_STAGE_B_DARWIN_UTUN_INVALID_ARGUMENT);
  return 0;
}

typedef struct FaultCase {
  Fault fault;
  WinnStageBDarwinUtunStatus expected;
  unsigned expected_close_count;
  unsigned expected_action_count;
} FaultCase;

static int test_mutation_matrix(void) {
  static const FaultCase cases[] = {
      {FAULT_GATE_ACQUIRE,
       WINN_STAGE_B_DARWIN_UTUN_GATE_ACQUIRE_FAILED, 0U, 0U},
      {FAULT_GATE_RELEASE,
       WINN_STAGE_B_DARWIN_UTUN_GATE_RELEASE_FAILED, 1U, 1U},
      {FAULT_CEILING_FAILURE,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_CEILING_ZERO,
       WINN_STAGE_B_DARWIN_UTUN_INVALID_SCAN_RANGE, 0U, 0U},
      {FAULT_CEILING_OVERSIZE,
       WINN_STAGE_B_DARWIN_UTUN_INVALID_SCAN_RANGE, 0U, 0U},
      {FAULT_CEILING_UNBOUNDED,
       WINN_STAGE_B_DARWIN_UTUN_INVALID_SCAN_RANGE, 0U, 0U},
      {FAULT_CEILING_CHANGE_SECOND,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U},
      {FAULT_CEILING_CHANGE_THIRD,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U},
      {FAULT_FCNTL_SCAN_ERROR,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_ZERO, WINN_STAGE_B_DARWIN_UTUN_ZERO_CANDIDATES, 0U, 0U},
      {FAULT_INITIAL_MULTIPLE,
       WINN_STAGE_B_DARWIN_UTUN_MULTIPLE_CANDIDATES, 0U, 0U},
      {FAULT_HIDDEN_SECOND_ABOVE_LOWERED_SOFT,
       WINN_STAGE_B_DARWIN_UTUN_MULTIPLE_CANDIDATES, 0U, 0U},
      {FAULT_ORDINARY_UNEXPECTED_EINTR,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_ORDINARY_UNEXPECTED_EBADF,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_ORDINARY_OVERSIZE_ADDRESS,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_PEER_LENGTH, WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_PEER_OVERSIZE, WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_PEER_SC_LENGTH, WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_PEER_SYSADDR, WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_CONTROL_INFO_FAILURE,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_CONTROL_NAME_MUTATION,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_CONTROL_NAME_TAIL_MUTATION,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_CONTROL_ZERO_ID, WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_CONTROL_ID_MISMATCH,
       WINN_STAGE_B_DARWIN_UTUN_ZERO_CANDIDATES, 0U, 0U},
      {FAULT_ZERO_UNIT, WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_RESERVED, WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_GETSOCKOPT_FAILURE,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_BAD_IFNAME, WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_BAD_IFNAME_LENGTH,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_OVERSIZE_IFNAME_LENGTH,
       WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED, 0U, 0U},
      {FAULT_DUP_FAILURE, WINN_STAGE_B_DARWIN_UTUN_DUP_FAILED, 0U, 0U},
      {FAULT_DUP_RETURNS_ORIGINAL,
       WINN_STAGE_B_DARWIN_UTUN_DUP_FAILED, 0U, 0U},
      {FAULT_DUP_OUTSIDE_LIMIT,
       WINN_STAGE_B_DARWIN_UTUN_DUP_FAILED, 1U, 0U},
      {FAULT_DUP_INITIAL_FCNTL_FAILURE,
       WINN_STAGE_B_DARWIN_UTUN_DUP_NOT_CLOEXEC, 1U, 0U},
      {FAULT_DUP_NO_CLOEXEC,
       WINN_STAGE_B_DARWIN_UTUN_DUP_NOT_CLOEXEC, 1U, 0U},
      {FAULT_DUP_BEFORE_FCNTL_FAILURE,
       WINN_STAGE_B_DARWIN_UTUN_DESCRIPTOR_REUSED, 1U, 0U},
      {FAULT_DUP_BEFORE_GETPEER_FAILURE,
       WINN_STAGE_B_DARWIN_UTUN_DESCRIPTOR_REUSED, 1U, 0U},
      {FAULT_DUP_BEFORE_PEER_MUTATION,
       WINN_STAGE_B_DARWIN_UTUN_DESCRIPTOR_REUSED, 1U, 0U},
      {FAULT_DUP_BEFORE_CONTROL_MUTATION,
       WINN_STAGE_B_DARWIN_UTUN_DESCRIPTOR_REUSED, 1U, 0U},
      {FAULT_DUP_BEFORE_IFNAME_MUTATION,
       WINN_STAGE_B_DARWIN_UTUN_DESCRIPTOR_REUSED, 1U, 0U},
      {FAULT_RESCAN_ADD_SECOND,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U},
      {FAULT_RESCAN_REMOVE_ORIGINAL,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U},
      {FAULT_RESCAN_ORIGINAL_MUTATION,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U},
      {FAULT_DUP_AFTER_FCNTL_FAILURE,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U},
      {FAULT_DUP_AFTER_GETPEER_FAILURE,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U},
      {FAULT_DUP_AFTER_PEER_MUTATION,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U},
      {FAULT_DUP_AFTER_CONTROL_MUTATION,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U},
      {FAULT_DUP_AFTER_IFNAME_MUTATION,
       WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED, 1U, 0U}};
  size_t index;
  for (index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    Fake fake = make_fake();
    WinnStageBDarwinUtunSyscalls syscalls;
    ActionProbe probe;
    WinnStageBDarwinActionResult result;
    WinnStageBDarwinUtunStatus status;
    fake.fault = cases[index].fault;
    if (fake.fault == FAULT_HIDDEN_SECOND_ABOVE_LOWERED_SOFT) {
      CHECK(UINT64_C(12) > fake.advisory_soft_limit);
      CHECK(UINT64_C(12) < fake.fd_ceiling);
    }
    syscalls = make_syscalls(&fake);
    memset(&result, 0xa5, sizeof(result));
    memset(&probe, 0, sizeof(probe));
    probe.fake = &fake;
    probe.return_status = 77;
    status = winn_stage_b_darwin_utun_with_pinned(
        &syscalls, fake_action, &probe, &result);
    if (status != cases[index].expected) {
      fprintf(
          stderr,
          "fault %d: expected status %d, got %d\n",
          (int)cases[index].fault,
          (int)cases[index].expected,
          (int)status);
      return 1;
    }
    CHECK(fake.close_count == cases[index].expected_close_count);
    CHECK(probe.call_count == cases[index].expected_action_count);
    CHECK(result.action_was_called ==
          (uint8_t)cases[index].expected_action_count);
    CHECK(fake.gate_held == 0);
    CHECK(fake.gate_release_count ==
          (cases[index].fault == FAULT_GATE_ACQUIRE ? 0U : 1U));
    CHECK(fake.gate_violation == 0);
  }
  return 0;
}

static int test_close_failure_after_action(void) {
  Fake fake = make_fake();
  fake.fault = FAULT_CLOSE_FAILURE;
  ActionProbe probe;
  WinnStageBDarwinActionResult result;
  CHECK(run_with_action(&fake, &probe, &result) ==
        WINN_STAGE_B_DARWIN_UTUN_CLOSE_FAILED);
  CHECK(fake.close_count == 1U);
  CHECK(fake.close_while_gate_held != 0);
  CHECK(fake.gate_release_count == 1U);
  CHECK(probe.call_count == 1U);
  CHECK(result.action_was_called == 1U);
  return 0;
}

int main(void) {
  CHECK(test_success_gate_lifetime() == 0);
  CHECK(test_full_range_and_max_unit() == 0);
  CHECK(test_concurrent_gate_spans_action_and_close() == 0);
  CHECK(test_argument_rejection() == 0);
  CHECK(test_mutation_matrix() == 0);
  CHECK(test_close_failure_after_action() == 0);
  puts("WINN_STAGE_B_DARWIN_UTUN_TESTS_PASS");
  return 0;
}
