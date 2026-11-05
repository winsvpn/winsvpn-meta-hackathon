#include "WinnStageBDarwinUtun.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct WinnStageBDarwinDiscoveredUtun {
  WinnStageBUtunCandidate candidate;
} WinnStageBDarwinDiscoveredUtun;

typedef struct WinnStageBDarwinPinnedUtun {
  WinnStageBUtunCandidate candidate;
  bool owns_duplicate;
} WinnStageBDarwinPinnedUtun;

typedef enum WinnStageBDarwinProbeResult {
  WINN_STAGE_B_DARWIN_PROBE_NOT_UTUN = 0,
  WINN_STAGE_B_DARWIN_PROBE_VALID_UTUN,
  WINN_STAGE_B_DARWIN_PROBE_INVALID
} WinnStageBDarwinProbeResult;

_Static_assert(
    sizeof(WinnStageBDarwinCtlInfo) == 100U,
    "WinnStageBDarwinCtlInfo ABI size changed");
_Static_assert(
    _Alignof(WinnStageBDarwinCtlInfo) == 4U,
    "WinnStageBDarwinCtlInfo ABI alignment changed");
_Static_assert(
    offsetof(WinnStageBDarwinCtlInfo, control_id) == 0U,
    "WinnStageBDarwinCtlInfo control-id offset changed");
_Static_assert(
    offsetof(WinnStageBDarwinCtlInfo, control_name) == 4U,
    "WinnStageBDarwinCtlInfo control-name offset changed");

_Static_assert(
    sizeof(WinnStageBDarwinSockaddrCtl) == 32U,
    "WinnStageBDarwinSockaddrCtl ABI size changed");
_Static_assert(
    _Alignof(WinnStageBDarwinSockaddrCtl) == 4U,
    "WinnStageBDarwinSockaddrCtl ABI alignment changed");
_Static_assert(
    offsetof(WinnStageBDarwinSockaddrCtl, length) == 0U,
    "WinnStageBDarwinSockaddrCtl length offset changed");
_Static_assert(
    offsetof(WinnStageBDarwinSockaddrCtl, family) == 1U,
    "WinnStageBDarwinSockaddrCtl family offset changed");
_Static_assert(
    offsetof(WinnStageBDarwinSockaddrCtl, system_address) == 2U,
    "WinnStageBDarwinSockaddrCtl system-address offset changed");
_Static_assert(
    offsetof(WinnStageBDarwinSockaddrCtl, control_id) == 4U,
    "WinnStageBDarwinSockaddrCtl control-id offset changed");
_Static_assert(
    offsetof(WinnStageBDarwinSockaddrCtl, unit) == 8U,
    "WinnStageBDarwinSockaddrCtl unit offset changed");
_Static_assert(
    offsetof(WinnStageBDarwinSockaddrCtl, reserved) == 12U,
    "WinnStageBDarwinSockaddrCtl reserved offset changed");

_Static_assert(
    sizeof(WinnStageBUtunCandidate) == 28U,
    "WinnStageBUtunCandidate ABI size changed");
_Static_assert(
    _Alignof(WinnStageBUtunCandidate) == 4U,
    "WinnStageBUtunCandidate ABI alignment changed");
_Static_assert(
    offsetof(WinnStageBUtunCandidate, file_descriptor) == 0U &&
        offsetof(WinnStageBUtunCandidate, peer_control_id) == 4U &&
        offsetof(WinnStageBUtunCandidate, utun_control_id) == 8U &&
        offsetof(WinnStageBUtunCandidate, unit) == 12U &&
        offsetof(WinnStageBUtunCandidate, peer_address_family) == 16U &&
        offsetof(
            WinnStageBUtunCandidate,
            expected_system_address_family) == 20U &&
        offsetof(
            WinnStageBUtunCandidate,
            peer_address_length_valid) == 24U &&
        offsetof(WinnStageBUtunCandidate, reserved) == 25U,
    "WinnStageBUtunCandidate ABI offsets changed");

_Static_assert(
    sizeof(WinnStageBDarwinActionResult) == 8U,
    "WinnStageBDarwinActionResult ABI size changed");
_Static_assert(
    _Alignof(WinnStageBDarwinActionResult) == 4U,
    "WinnStageBDarwinActionResult ABI alignment changed");
_Static_assert(
    offsetof(WinnStageBDarwinActionResult, action_status) == 0U &&
        offsetof(WinnStageBDarwinActionResult, action_was_called) == 4U &&
        offsetof(WinnStageBDarwinActionResult, reserved) == 5U,
    "WinnStageBDarwinActionResult ABI offsets changed");

_Static_assert(
    sizeof(WinnStageBDarwinUtunStatus) == 4U,
    "WinnStageBDarwinUtunStatus ABI size changed");
_Static_assert(
    _Alignof(WinnStageBDarwinUtunSyscalls) == _Alignof(void *),
    "WinnStageBDarwinUtunSyscalls ABI alignment changed");
_Static_assert(
    sizeof(WinnStageBDarwinUtunSyscalls) == 10U * sizeof(void *),
    "WinnStageBDarwinUtunSyscalls ABI size changed");
_Static_assert(
    offsetof(
            WinnStageBDarwinUtunSyscalls,
            acquire_descriptor_gate) ==
            0U * sizeof(void *) &&
        offsetof(
            WinnStageBDarwinUtunSyscalls,
            release_descriptor_gate) ==
            1U * sizeof(void *) &&
        offsetof(
            WinnStageBDarwinUtunSyscalls,
            get_process_fd_ceiling) ==
            2U * sizeof(void *) &&
        offsetof(WinnStageBDarwinUtunSyscalls, fcntl_getfd) ==
            3U * sizeof(void *) &&
        offsetof(WinnStageBDarwinUtunSyscalls, getpeername) ==
            4U * sizeof(void *) &&
        offsetof(WinnStageBDarwinUtunSyscalls, ctl_iocginfo) ==
            5U * sizeof(void *) &&
        offsetof(WinnStageBDarwinUtunSyscalls, getsockopt) ==
            6U * sizeof(void *) &&
        offsetof(WinnStageBDarwinUtunSyscalls, fcntl_dupfd_cloexec) ==
            7U * sizeof(void *) &&
        offsetof(WinnStageBDarwinUtunSyscalls, close_fd) ==
            8U * sizeof(void *) &&
        offsetof(WinnStageBDarwinUtunSyscalls, context) ==
            9U * sizeof(void *),
    "WinnStageBDarwinUtunSyscalls ABI offsets changed");

static void winn_secure_zero(void *bytes, size_t count) {
  volatile uint8_t *cursor = (volatile uint8_t *)bytes;
  while (count != 0U) {
    *cursor = 0U;
    ++cursor;
    --count;
  }
}

static bool winn_syscalls_valid(
    const WinnStageBDarwinUtunSyscalls *syscalls) {
  return syscalls != NULL &&
         syscalls->acquire_descriptor_gate != NULL &&
         syscalls->release_descriptor_gate != NULL &&
         syscalls->get_process_fd_ceiling != NULL &&
         syscalls->fcntl_getfd != NULL &&
         syscalls->getpeername != NULL &&
         syscalls->ctl_iocginfo != NULL &&
         syscalls->getsockopt != NULL &&
         syscalls->fcntl_dupfd_cloexec != NULL &&
         syscalls->close_fd != NULL;
}

static bool winn_reserved_is_zero(
    const WinnStageBDarwinSockaddrCtl *address) {
  size_t index;
  for (index = 0U;
       index < sizeof(address->reserved) /
                   sizeof(address->reserved[0]);
       ++index) {
    if (address->reserved[index] != 0U) {
      return false;
    }
  }
  return true;
}

static size_t winn_decimal_u32(uint32_t value, char output[11]) {
  char reversed[10];
  size_t count = 0U;
  size_t index;
  do {
    reversed[count] = (char)('0' + (char)(value % 10U));
    ++count;
    value /= 10U;
  } while (value != 0U);
  for (index = 0U; index < count; ++index) {
    output[index] = reversed[count - index - 1U];
  }
  output[count] = '\0';
  return count;
}

static bool winn_ifname_matches_unit(
    const char *interface_name,
    socklen_t interface_name_length,
    uint32_t unit) {
  char expected[WINN_STAGE_B_DARWIN_IFNAME_CAPACITY];
  char decimal[11];
  size_t decimal_length;
  size_t expected_length;

  if (unit == 0U ||
      interface_name_length >
          (socklen_t)WINN_STAGE_B_DARWIN_IFNAME_CAPACITY) {
    return false;
  }
  memset(expected, 0, sizeof(expected));
  memset(decimal, 0, sizeof(decimal));
  decimal_length = winn_decimal_u32(unit - 1U, decimal);
  expected_length = 4U + decimal_length;
  if (expected_length + 1U > sizeof(expected) ||
      interface_name_length != (socklen_t)(expected_length + 1U)) {
    return false;
  }
  memcpy(expected, "utun", 4U);
  memcpy(expected + 4U, decimal, decimal_length);
  return memcmp(interface_name, expected, expected_length + 1U) == 0;
}

static bool winn_control_name_is_canonical(
    const char name[WINN_STAGE_B_DARWIN_MAX_KCTL_NAME]) {
  size_t literal_length =
      sizeof(WINN_STAGE_B_DARWIN_UTUN_CONTROL_NAME);
  size_t index;
  if (memcmp(
          name,
          WINN_STAGE_B_DARWIN_UTUN_CONTROL_NAME,
          literal_length) != 0) {
    return false;
  }
  for (index = literal_length;
       index < (size_t)WINN_STAGE_B_DARWIN_MAX_KCTL_NAME;
       ++index) {
    if (name[index] != '\0') {
      return false;
    }
  }
  return true;
}

static bool winn_candidate_equal(
    const WinnStageBUtunCandidate *first,
    const WinnStageBUtunCandidate *second,
    bool compare_file_descriptor) {
  return (!compare_file_descriptor ||
          first->file_descriptor == second->file_descriptor) &&
         first->peer_control_id == second->peer_control_id &&
         first->utun_control_id == second->utun_control_id &&
         first->unit == second->unit &&
         first->peer_address_family == second->peer_address_family &&
         first->expected_system_address_family ==
             second->expected_system_address_family &&
         first->peer_address_length_valid ==
             second->peer_address_length_valid &&
         first->reserved[0] == second->reserved[0] &&
         first->reserved[1] == second->reserved[1] &&
         first->reserved[2] == second->reserved[2];
}

static WinnStageBDarwinProbeResult winn_probe_fd(
    const WinnStageBDarwinUtunSyscalls *syscalls,
    int32_t file_descriptor,
    bool require_utun,
    WinnStageBDarwinDiscoveredUtun *output) {
  struct sockaddr_storage peer_storage;
  WinnStageBDarwinSockaddrCtl peer_address;
  WinnStageBDarwinCtlInfo control_info;
  char interface_name[WINN_STAGE_B_DARWIN_IFNAME_CAPACITY];
  socklen_t peer_address_length;
  socklen_t interface_name_length;
  int32_t descriptor_flags = 0;
  int32_t descriptor_errno = 0;
  int32_t peer_errno = 0;

  memset(output, 0, sizeof(*output));
  memset(&peer_storage, 0, sizeof(peer_storage));
  memset(&peer_address, 0, sizeof(peer_address));
  memset(&control_info, 0, sizeof(control_info));
  memset(interface_name, 0, sizeof(interface_name));

  if (syscalls->fcntl_getfd(
          file_descriptor,
          &descriptor_flags,
          &descriptor_errno,
          syscalls->context) != 0) {
    if (!require_utun && descriptor_errno == EBADF) {
      return WINN_STAGE_B_DARWIN_PROBE_NOT_UTUN;
    }
    return WINN_STAGE_B_DARWIN_PROBE_INVALID;
  }
  (void)descriptor_flags;

  peer_address_length = (socklen_t)sizeof(peer_storage);
  if (syscalls->getpeername(
          file_descriptor,
          &peer_storage,
          &peer_address_length,
          &peer_errno,
          syscalls->context) != 0) {
    if (!require_utun &&
        (peer_errno == ENOTSOCK || peer_errno == ENOTCONN)) {
      return WINN_STAGE_B_DARWIN_PROBE_NOT_UTUN;
    }
    return WINN_STAGE_B_DARWIN_PROBE_INVALID;
  }
  if (peer_address_length >
          (socklen_t)sizeof(peer_storage) ||
      peer_address_length <
          (socklen_t)(offsetof(struct sockaddr_storage, ss_family) +
                      sizeof(peer_storage.ss_family))) {
    return WINN_STAGE_B_DARWIN_PROBE_INVALID;
  }
  /*
   * Family classification deliberately precedes the sockaddr_ctl exact-size
   * requirement. Valid IPv4, IPv6, and Unix sockets are ordinary live
   * descriptors, not malformed utuns.
   */
  if (peer_storage.ss_family !=
      (sa_family_t)WINN_STAGE_B_DARWIN_AF_SYSTEM) {
    return require_utun
               ? WINN_STAGE_B_DARWIN_PROBE_INVALID
               : WINN_STAGE_B_DARWIN_PROBE_NOT_UTUN;
  }
  if (peer_address_length !=
      (socklen_t)sizeof(peer_address)) {
    return WINN_STAGE_B_DARWIN_PROBE_INVALID;
  }
  memcpy(&peer_address, &peer_storage, sizeof(peer_address));
  if (peer_address.length != (uint8_t)sizeof(peer_address) ||
      peer_address.family !=
          (uint8_t)WINN_STAGE_B_DARWIN_AF_SYSTEM ||
      peer_address.system_address !=
          (uint16_t)WINN_STAGE_B_DARWIN_AF_SYS_CONTROL) {
    return WINN_STAGE_B_DARWIN_PROBE_INVALID;
  }

  memcpy(
      control_info.control_name,
      WINN_STAGE_B_DARWIN_UTUN_CONTROL_NAME,
      sizeof(WINN_STAGE_B_DARWIN_UTUN_CONTROL_NAME));
  if (syscalls->ctl_iocginfo(
          file_descriptor, &control_info, syscalls->context) != 0 ||
      !winn_control_name_is_canonical(control_info.control_name) ||
      control_info.control_id == 0U) {
    return WINN_STAGE_B_DARWIN_PROBE_INVALID;
  }
  if (peer_address.control_id != control_info.control_id) {
    return require_utun
               ? WINN_STAGE_B_DARWIN_PROBE_INVALID
               : WINN_STAGE_B_DARWIN_PROBE_NOT_UTUN;
  }
  if (peer_address.unit == 0U ||
      !winn_reserved_is_zero(&peer_address)) {
    return WINN_STAGE_B_DARWIN_PROBE_INVALID;
  }

  interface_name_length = (socklen_t)sizeof(interface_name);
  if (syscalls->getsockopt(
          file_descriptor,
          WINN_STAGE_B_DARWIN_SYSPROTO_CONTROL,
          WINN_STAGE_B_DARWIN_UTUN_OPT_IFNAME,
          interface_name,
          &interface_name_length,
          syscalls->context) != 0 ||
      !winn_ifname_matches_unit(
          interface_name,
          interface_name_length,
          peer_address.unit)) {
    return WINN_STAGE_B_DARWIN_PROBE_INVALID;
  }

  output->candidate.file_descriptor = file_descriptor;
  output->candidate.peer_control_id = peer_address.control_id;
  output->candidate.utun_control_id = control_info.control_id;
  output->candidate.unit = peer_address.unit;
  output->candidate.peer_address_family =
      (uint32_t)peer_address.family;
  output->candidate.expected_system_address_family =
      (uint32_t)WINN_STAGE_B_DARWIN_AF_SYSTEM;
  output->candidate.peer_address_length_valid = 1U;
  return WINN_STAGE_B_DARWIN_PROBE_VALID_UTUN;
}

static WinnStageBDarwinUtunStatus winn_read_process_fd_ceiling(
    const WinnStageBDarwinUtunSyscalls *syscalls,
    int32_t *output_ceiling) {
  uint64_t process_fd_ceiling = 0U;
  *output_ceiling = 0;
  if (syscalls->get_process_fd_ceiling(
          &process_fd_ceiling, syscalls->context) != 0) {
    return WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED;
  }
  if (process_fd_ceiling == 0U ||
      process_fd_ceiling >
          (uint64_t)WINN_STAGE_B_DARWIN_MAX_FD_CEILING ||
      process_fd_ceiling > (uint64_t)INT32_MAX) {
    return WINN_STAGE_B_DARWIN_UTUN_INVALID_SCAN_RANGE;
  }
  *output_ceiling = (int32_t)process_fd_ceiling;
  return WINN_STAGE_B_DARWIN_UTUN_OK;
}

static WinnStageBDarwinUtunStatus winn_enumerate_exactly_one(
    const WinnStageBDarwinUtunSyscalls *syscalls,
    int32_t process_fd_ceiling,
    int32_t excluded_fd,
    WinnStageBDarwinDiscoveredUtun *output) {
  WinnStageBDarwinDiscoveredUtun found;
  size_t count = 0U;
  int32_t fd;

  memset(output, 0, sizeof(*output));
  memset(&found, 0, sizeof(found));
  for (fd = 0; fd < process_fd_ceiling; ++fd) {
    WinnStageBDarwinDiscoveredUtun current;
    WinnStageBDarwinProbeResult probe;
    if (fd == excluded_fd) {
      continue;
    }
    memset(&current, 0, sizeof(current));
    probe = winn_probe_fd(syscalls, fd, false, &current);
    if (probe == WINN_STAGE_B_DARWIN_PROBE_INVALID) {
      winn_secure_zero(&current, sizeof(current));
      winn_secure_zero(&found, sizeof(found));
      return WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED;
    }
    if (probe == WINN_STAGE_B_DARWIN_PROBE_VALID_UTUN) {
      ++count;
      if (count == 1U) {
        found = current;
      } else {
        winn_secure_zero(&current, sizeof(current));
        winn_secure_zero(&found, sizeof(found));
        return WINN_STAGE_B_DARWIN_UTUN_MULTIPLE_CANDIDATES;
      }
    }
    winn_secure_zero(&current, sizeof(current));
  }
  if (count == 0U) {
    return WINN_STAGE_B_DARWIN_UTUN_ZERO_CANDIDATES;
  }
  *output = found;
  winn_secure_zero(&found, sizeof(found));
  return WINN_STAGE_B_DARWIN_UTUN_OK;
}

static void winn_close_duplicate_once(
    const WinnStageBDarwinUtunSyscalls *syscalls,
    int32_t duplicate_fd) {
  (void)syscalls->close_fd(duplicate_fd, syscalls->context);
}

static WinnStageBDarwinUtunStatus winn_discover_pinned(
    const WinnStageBDarwinUtunSyscalls *syscalls,
    WinnStageBDarwinPinnedUtun *output_pinned) {
  WinnStageBDarwinDiscoveredUtun initial;
  WinnStageBDarwinDiscoveredUtun duplicate_before_scan;
  WinnStageBDarwinDiscoveredUtun rescanned;
  WinnStageBDarwinDiscoveredUtun duplicate_after_scan;
  WinnStageBDarwinUtunStatus status;
  int32_t process_fd_ceiling = 0;
  int32_t rechecked_process_fd_ceiling = 0;
  int32_t duplicate_fd;
  int32_t duplicate_flags = 0;
  int32_t duplicate_errno = 0;

  memset(output_pinned, 0, sizeof(*output_pinned));
  output_pinned->candidate.file_descriptor = -1;

  memset(&initial, 0, sizeof(initial));
  memset(&duplicate_before_scan, 0, sizeof(duplicate_before_scan));
  memset(&rescanned, 0, sizeof(rescanned));
  memset(&duplicate_after_scan, 0, sizeof(duplicate_after_scan));

  status = winn_read_process_fd_ceiling(
      syscalls, &process_fd_ceiling);
  if (status != WINN_STAGE_B_DARWIN_UTUN_OK) {
    goto finish;
  }
  status = winn_enumerate_exactly_one(
      syscalls, process_fd_ceiling, -1, &initial);
  if (status != WINN_STAGE_B_DARWIN_UTUN_OK) {
    goto finish;
  }

  duplicate_fd = syscalls->fcntl_dupfd_cloexec(
      initial.candidate.file_descriptor, 0, syscalls->context);
  if (duplicate_fd < 0) {
    status = WINN_STAGE_B_DARWIN_UTUN_DUP_FAILED;
    goto finish;
  }
  if (duplicate_fd == initial.candidate.file_descriptor) {
    /*
     * F_DUPFD_CLOEXEC cannot validly return its input descriptor. Because this
     * value aliases the original rather than proving new ownership, never
     * close it on this contract-violation path.
     */
    status = WINN_STAGE_B_DARWIN_UTUN_DUP_FAILED;
    goto finish;
  }
  if (duplicate_fd >= process_fd_ceiling) {
    winn_close_duplicate_once(syscalls, duplicate_fd);
    status = WINN_STAGE_B_DARWIN_UTUN_DUP_FAILED;
    goto finish;
  }
  if (syscalls->fcntl_getfd(
          duplicate_fd,
          &duplicate_flags,
          &duplicate_errno,
          syscalls->context) != 0 ||
      (duplicate_flags & FD_CLOEXEC) == 0) {
    winn_close_duplicate_once(syscalls, duplicate_fd);
    status = WINN_STAGE_B_DARWIN_UTUN_DUP_NOT_CLOEXEC;
    goto finish;
  }
  if (winn_probe_fd(
          syscalls,
          duplicate_fd,
          true,
          &duplicate_before_scan) !=
          WINN_STAGE_B_DARWIN_PROBE_VALID_UTUN ||
      !winn_candidate_equal(
          &initial.candidate,
          &duplicate_before_scan.candidate,
          false)) {
    winn_close_duplicate_once(syscalls, duplicate_fd);
    status = WINN_STAGE_B_DARWIN_UTUN_DESCRIPTOR_REUSED;
    goto finish;
  }

  status = winn_read_process_fd_ceiling(
      syscalls, &rechecked_process_fd_ceiling);
  if (status != WINN_STAGE_B_DARWIN_UTUN_OK ||
      rechecked_process_fd_ceiling != process_fd_ceiling) {
    winn_close_duplicate_once(syscalls, duplicate_fd);
    status = WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED;
    goto finish;
  }
  status = winn_enumerate_exactly_one(
      syscalls, process_fd_ceiling, duplicate_fd, &rescanned);
  if (status != WINN_STAGE_B_DARWIN_UTUN_OK ||
      !winn_candidate_equal(
          &initial.candidate, &rescanned.candidate, true)) {
    winn_close_duplicate_once(syscalls, duplicate_fd);
    status = WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED;
    goto finish;
  }

  if (winn_probe_fd(
          syscalls,
          duplicate_fd,
          true,
          &duplicate_after_scan) !=
          WINN_STAGE_B_DARWIN_PROBE_VALID_UTUN ||
      !winn_candidate_equal(
          &duplicate_before_scan.candidate,
          &duplicate_after_scan.candidate,
          true)) {
    winn_close_duplicate_once(syscalls, duplicate_fd);
    status = WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED;
    goto finish;
  }
  status = winn_read_process_fd_ceiling(
      syscalls, &rechecked_process_fd_ceiling);
  if (status != WINN_STAGE_B_DARWIN_UTUN_OK ||
      rechecked_process_fd_ceiling != process_fd_ceiling) {
    winn_close_duplicate_once(syscalls, duplicate_fd);
    status = WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED;
    goto finish;
  }

  output_pinned->candidate = duplicate_after_scan.candidate;
  output_pinned->owns_duplicate = true;
  status = WINN_STAGE_B_DARWIN_UTUN_OK;

finish:
  winn_secure_zero(&initial, sizeof(initial));
  winn_secure_zero(&duplicate_before_scan, sizeof(duplicate_before_scan));
  winn_secure_zero(&rescanned, sizeof(rescanned));
  winn_secure_zero(&duplicate_after_scan, sizeof(duplicate_after_scan));
  return status;
}

WinnStageBDarwinUtunStatus winn_stage_b_darwin_utun_with_pinned(
    const WinnStageBDarwinUtunSyscalls *syscalls,
    WinnStageBDarwinPinnedAction action,
    void *action_context,
    WinnStageBDarwinActionResult *output_result) {
  WinnStageBDarwinPinnedUtun pinned;
  WinnStageBDarwinUtunStatus status;
  int32_t duplicate_fd;
  int close_result = 0;
  int gate_release_result;

  if (output_result != NULL) {
    memset(output_result, 0, sizeof(*output_result));
  }
  if (!winn_syscalls_valid(syscalls) ||
      action == NULL || output_result == NULL) {
    return WINN_STAGE_B_DARWIN_UTUN_INVALID_ARGUMENT;
  }
  memset(&pinned, 0, sizeof(pinned));
  pinned.candidate.file_descriptor = -1;

  if (syscalls->acquire_descriptor_gate(
          syscalls->context) != 0) {
    return WINN_STAGE_B_DARWIN_UTUN_GATE_ACQUIRE_FAILED;
  }

  status = winn_discover_pinned(syscalls, &pinned);
  if (status == WINN_STAGE_B_DARWIN_UTUN_OK) {
    duplicate_fd = pinned.candidate.file_descriptor;
    output_result->action_was_called = 1U;
    output_result->action_status =
        action(&pinned.candidate, action_context);
    pinned.owns_duplicate = false;
    winn_secure_zero(&pinned, sizeof(pinned));
    pinned.candidate.file_descriptor = -1;
    close_result = syscalls->close_fd(
        duplicate_fd, syscalls->context);
  }

  gate_release_result = syscalls->release_descriptor_gate(
      syscalls->context);
  winn_secure_zero(&pinned, sizeof(pinned));
  if (gate_release_result != 0) {
    return WINN_STAGE_B_DARWIN_UTUN_GATE_RELEASE_FAILED;
  }
  if (close_result != 0) {
    return WINN_STAGE_B_DARWIN_UTUN_CLOSE_FAILED;
  }
  return status;
}
