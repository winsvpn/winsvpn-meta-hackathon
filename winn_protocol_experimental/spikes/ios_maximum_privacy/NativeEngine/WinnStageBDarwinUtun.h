#ifndef WINN_STAGE_B_DARWIN_UTUN_H
#define WINN_STAGE_B_DARWIN_UTUN_H

#include "WinnStageBNativeEngine.h"

#include <sys/socket.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  /*
   * This accommodates Darwin's current kern.maxfilesperproc ceiling while
   * keeping a complete synchronous scan explicitly bounded. A kernel ceiling
   * above it is rejected; it is never partially scanned.
   */
  WINN_STAGE_B_DARWIN_MAX_FD_CEILING = 262144,
  WINN_STAGE_B_DARWIN_IFNAME_CAPACITY = 16,
  WINN_STAGE_B_DARWIN_MAX_KCTL_NAME = 96,
  WINN_STAGE_B_DARWIN_AF_SYS_CONTROL = 2,
  WINN_STAGE_B_DARWIN_SYSPROTO_CONTROL = 2,
  WINN_STAGE_B_DARWIN_UTUN_OPT_IFNAME = 2
};

#define WINN_STAGE_B_DARWIN_UTUN_CONTROL_NAME \
  "com.apple.net.utun_control"

/*
 * iPhoneOS does not publish <sys/kern_control.h> or <net/if_utun.h>. These
 * fixed-width ABI mirrors avoid making the isolated boundary depend on those
 * private SDK headers. The test lane static-asserts every size, alignment, and
 * field offset against the native macOS SDK layouts.
 */
typedef struct WinnStageBDarwinCtlInfo {
  uint32_t control_id;
  char control_name[WINN_STAGE_B_DARWIN_MAX_KCTL_NAME];
} WinnStageBDarwinCtlInfo;

typedef struct WinnStageBDarwinSockaddrCtl {
  uint8_t length;
  uint8_t family;
  uint16_t system_address;
  uint32_t control_id;
  uint32_t unit;
  uint32_t reserved[5];
} WinnStageBDarwinSockaddrCtl;

typedef enum WinnStageBDarwinUtunStatus {
  WINN_STAGE_B_DARWIN_UTUN_OK = 0,
  WINN_STAGE_B_DARWIN_UTUN_INVALID_ARGUMENT,
  WINN_STAGE_B_DARWIN_UTUN_INVALID_SCAN_RANGE,
  WINN_STAGE_B_DARWIN_UTUN_SCAN_FAILED,
  WINN_STAGE_B_DARWIN_UTUN_ZERO_CANDIDATES,
  WINN_STAGE_B_DARWIN_UTUN_MULTIPLE_CANDIDATES,
  WINN_STAGE_B_DARWIN_UTUN_INVALID_CANDIDATE,
  WINN_STAGE_B_DARWIN_UTUN_GATE_ACQUIRE_FAILED,
  WINN_STAGE_B_DARWIN_UTUN_GATE_RELEASE_FAILED,
  WINN_STAGE_B_DARWIN_UTUN_DUP_FAILED,
  WINN_STAGE_B_DARWIN_UTUN_DUP_NOT_CLOEXEC,
  WINN_STAGE_B_DARWIN_UTUN_DESCRIPTOR_REUSED,
  WINN_STAGE_B_DARWIN_UTUN_RACE_DETECTED,
  WINN_STAGE_B_DARWIN_UTUN_CLOSE_FAILED
} WinnStageBDarwinUtunStatus;

/*
 * get_process_fd_ceiling returns a kernel-enforced upper bound greater than
 * every live descriptor in the process, including descriptors that remain
 * live above a subsequently lowered RLIMIT_NOFILE. The Apple adapter must use
 * the Darwin kern.maxfilesperproc value (or a stronger lifetime ceiling), not
 * the current soft or hard RLIMIT. The boundary scans every descriptor in
 * [0, ceiling) and refuses zero, unbounded, or over-audited ceilings.
 *
 * fcntl_getfd models fcntl(fd, F_GETFD). It writes descriptor flags and
 * returns 0 on success. On failure it returns -1 and writes the errno value.
 * EBADF is the only failure treated as an unused slot during enumeration.
 *
 * getpeername returns its errno explicitly. During enumeration only ENOTSOCK
 * and ENOTCONN are expected non-candidate results: F_GETFD already proved the
 * descriptor live, and the boundary supplies valid storage and length. EBADF,
 * EINTR, EINVAL, EFAULT, and all other failures therefore indicate a race,
 * transient failure, or contract violation and fail the scan.
 *
 * The remaining callbacks model getpeername, ioctl(CTLIOCGINFO),
 * getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME), fcntl(F_DUPFD_CLOEXEC),
 * and close. They return 0 on success and -1 on failure, except dup which
 * returns the new descriptor or -1.
 */
typedef int (*WinnStageBDarwinAcquireDescriptorGate)(void *context);
typedef int (*WinnStageBDarwinReleaseDescriptorGate)(void *context);
typedef int (*WinnStageBDarwinGetProcessFDCeiling)(
    uint64_t *output_process_fd_ceiling,
    void *context);
typedef int (*WinnStageBDarwinFcntlGetFD)(
    int32_t file_descriptor,
    int32_t *output_flags,
    int32_t *output_errno,
    void *context);
typedef int (*WinnStageBDarwinGetPeerName)(
    int32_t file_descriptor,
    struct sockaddr_storage *address,
    socklen_t *address_length,
    int32_t *output_errno,
    void *context);
typedef int (*WinnStageBDarwinCtlIOCGInfo)(
    int32_t file_descriptor,
    WinnStageBDarwinCtlInfo *control_info,
    void *context);
typedef int (*WinnStageBDarwinGetSockOpt)(
    int32_t file_descriptor,
    int32_t level,
    int32_t option_name,
    void *option_value,
    socklen_t *option_length,
    void *context);
typedef int32_t (*WinnStageBDarwinFcntlDupFDCloseOnExec)(
    int32_t file_descriptor,
    int32_t minimum_file_descriptor,
    void *context);
typedef int (*WinnStageBDarwinCloseFD)(
    int32_t file_descriptor,
    void *context);

typedef struct WinnStageBDarwinUtunSyscalls {
  WinnStageBDarwinAcquireDescriptorGate acquire_descriptor_gate;
  WinnStageBDarwinReleaseDescriptorGate release_descriptor_gate;
  WinnStageBDarwinGetProcessFDCeiling get_process_fd_ceiling;
  WinnStageBDarwinFcntlGetFD fcntl_getfd;
  WinnStageBDarwinGetPeerName getpeername;
  WinnStageBDarwinCtlIOCGInfo ctl_iocginfo;
  WinnStageBDarwinGetSockOpt getsockopt;
  WinnStageBDarwinFcntlDupFDCloseOnExec fcntl_dupfd_cloexec;
  WinnStageBDarwinCloseFD close_fd;
  void *context;
} WinnStageBDarwinUtunSyscalls;

/*
 * action executes synchronously while the process-global descriptor gate and
 * validated duplicate are both owned by this boundary. It is the narrow seam
 * intended to call winn_stage_b_native_engine_start. It must not retain the
 * candidate pointer or file descriptor, invoke this boundary recursively,
 * release the gate, close/dup2/closefrom descriptors, or unwind nonlocally.
 */
typedef int32_t (*WinnStageBDarwinPinnedAction)(
    const WinnStageBUtunCandidate *candidate,
    void *context);

typedef struct WinnStageBDarwinActionResult {
  int32_t action_status;
  uint8_t action_was_called;
  uint8_t reserved[3];
} WinnStageBDarwinActionResult;

/*
 * Acquires the process-global descriptor gate, discovers exactly one live utun
 * across the complete kernel descriptor ceiling, pins/revalidates a CLOEXEC
 * duplicate, invokes action synchronously, closes the duplicate, and only then
 * releases the gate. No public intermediate ownership or early-unlock API is
 * provided. The owner must use this same gate around every process operation
 * capable of create/dup/dup2/close/closefrom or utun replacement.
 *
 * The secret-free candidate and interface name never escape this synchronous
 * boundary except that action receives the candidate for the duration of its
 * call. action_status is opaque to this boundary. action_was_called remains
 * zero if discovery failed, and is one even when subsequent close/gate cleanup
 * reports an error.
 */
WinnStageBDarwinUtunStatus winn_stage_b_darwin_utun_with_pinned(
    const WinnStageBDarwinUtunSyscalls *syscalls,
    WinnStageBDarwinPinnedAction action,
    void *action_context,
    WinnStageBDarwinActionResult *output_result);

#ifdef __cplusplus
}
#endif

#endif
