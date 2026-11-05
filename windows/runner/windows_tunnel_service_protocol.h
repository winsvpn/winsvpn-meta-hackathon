#ifndef RUNNER_WINDOWS_TUNNEL_SERVICE_PROTOCOL_H_
#define RUNNER_WINDOWS_TUNNEL_SERVICE_PROTOCOL_H_

#include <cstdint>

namespace winsvpn::tunnel_service {

constexpr wchar_t kServiceName[] = L"WinsVpnTunnelManager";
constexpr wchar_t kServiceDisplayName[] = L"Win's VPN Tunnel Manager";
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\ProtectedPrefix\\Administrators\\WinsVPN.TunnelManager.v1";
constexpr wchar_t kStartCancellationEventPrefix[] =
    L"Global\\WinsVPN.TunnelStartCancel.v1.";
constexpr uint32_t kProtocolMagic = 0x31505657;  // "WVP1" little-endian.
// Version 4 adds the start/stop round-trip success verbs: a successful kStart
// now answers kStartSucceeded and a successful kStop answers kStopSucceeded
// (kOk is reserved for kStatus). The client demands the verb-specific status on
// a start/stop round-trip, so a response can no longer be mistaken for the
// success of the wrong operation. Bumping the version keeps a v3 client/service
// from silently misreading the new status values.
constexpr uint16_t kProtocolVersion = 4;
constexpr uint32_t kMaxRequestBytes = 512 * 1024;
constexpr uint32_t kMaxResponseBytes = 8 * 1024;

// Actual component deadlines used by the synchronous privileged start path.
constexpr uint32_t kLegacyUninstallCommandTimeoutMilliseconds = 60000;
constexpr uint32_t kLegacyInitialRemovalWaitMilliseconds = 3000;
constexpr uint32_t kLegacyScmStopTimeoutMilliseconds = 15000;
constexpr uint32_t kLegacyFinalRemovalWaitMilliseconds = 10000;
constexpr uint32_t kAwgEngineStopWaitMilliseconds = 5000;
constexpr uint32_t kAwgUapiReadinessTimeoutMilliseconds = 10000;
constexpr uint32_t kAwgUapiWriteTimeoutMilliseconds = 3000;
constexpr uint32_t kAwgUapiResponseTimeoutMilliseconds = 5000;
constexpr uint32_t kAwgBaselineReadinessTimeoutMilliseconds = 1000;
constexpr uint32_t kAwgSetconfTimeoutMilliseconds = 15000;
constexpr uint32_t kAwgAdapterReadinessTimeoutMilliseconds = 10000;
constexpr uint32_t kAwgConvergenceDeadlineMilliseconds = 25000;
constexpr uint32_t kRouteCommitMarginMilliseconds = 15000;
// Winn Protocol v3 adds two bounded components to the start path, and only on a
// winn/3 start: launching the datapath engine and waiting for its CreateAck
// (windows_winn_engine.cpp bounds that at 10s), and then waiting for the
// engine's own transfer-proven signal, transport_observed_both_ways.
//
// The second one runs AFTER WaitForAwgConvergence has already proved a recent
// handshake and nontrivial bidirectional transfer, which on a winn/3 tunnel can
// only have crossed through the seam and the engine. So by the time this
// deadline starts the counters are expected to be true already, and it is
// bounded short deliberately: it is a confirmation, not a second convergence
// loop. Five seconds against a 250ms poll is twenty chances to read a counter
// that has already moved; a session that needs longer than that has not
// converged, it has failed.
constexpr uint32_t kWinnEngineCreateTimeoutMilliseconds = 10000;
constexpr uint32_t kWinnTransportConvergenceDeadlineMilliseconds = 5000;

// Normal AWG critical path includes both 5s engine-stop waits; full UAPI
// readiness/write/response budgets for startup and validation; setconf;
// interface readiness; a shorter baseline UAPI query; the 25s convergence loop
// plus one final baseline query that may cross its deadline; and route margin.
// Slower stale SCM/driver failure sequences are intentionally preempted by the
// overall watchdog; termination is fail-closed because the AWG child lives in
// a kill-on-close job.
constexpr uint32_t kNormalAwgCriticalPathBudgetMilliseconds =
    kAwgEngineStopWaitMilliseconds + kAwgEngineStopWaitMilliseconds +
    kAwgUapiReadinessTimeoutMilliseconds +
    kAwgUapiWriteTimeoutMilliseconds + kAwgUapiResponseTimeoutMilliseconds +
    kAwgSetconfTimeoutMilliseconds + kAwgUapiReadinessTimeoutMilliseconds +
    kAwgUapiWriteTimeoutMilliseconds + kAwgUapiResponseTimeoutMilliseconds +
    kAwgAdapterReadinessTimeoutMilliseconds +
    kAwgBaselineReadinessTimeoutMilliseconds +
    kAwgUapiWriteTimeoutMilliseconds + kAwgUapiResponseTimeoutMilliseconds +
    kAwgConvergenceDeadlineMilliseconds +
    kAwgBaselineReadinessTimeoutMilliseconds +
    kAwgUapiWriteTimeoutMilliseconds + kAwgUapiResponseTimeoutMilliseconds +
    kRouteCommitMarginMilliseconds;
// The winn/3 critical path is the AWG one plus the two Winn components. It is
// stated separately rather than folded into the constant above so that a reader
// can see what a winn/3 start costs over a winn/1 start, and so the watchdog
// assertion below covers the LONGER of the two rather than the one that
// happened to be written first.
constexpr uint32_t kNormalWinnCriticalPathBudgetMilliseconds =
    kNormalAwgCriticalPathBudgetMilliseconds +
    kWinnEngineCreateTimeoutMilliseconds +
    kWinnTransportConvergenceDeadlineMilliseconds;
constexpr uint32_t kStartOverallWatchdogMilliseconds = 150000;
constexpr uint32_t kStartCommandTimeoutMilliseconds = 160000;
// Stop is a safety operation, not a complete repair/uninstall transaction.
// If a vendor SCM or driver call violates this hard ceiling, terminating the
// manager closes the AWG kill-on-close job and SCM recovery restores a clean
// command endpoint. Every stop origin uses this same bound.
constexpr uint32_t kStopOverallWatchdogMilliseconds = 20000;
constexpr uint32_t kStopCommandTimeoutMilliseconds = 25000;
constexpr uint32_t kResponseFlushTimeoutMilliseconds = 3000;
constexpr uint32_t kResponseWriteTimeoutMilliseconds = 3000;
// CancelSynchronousIo normally releases FlushFileBuffers promptly, but a
// misbehaving filesystem/filter driver must not turn response delivery into an
// unbounded service hang. The service terminates fail-closed if this drain
// window is violated.
constexpr uint32_t kResponseFlushCancelDrainMilliseconds = 1000;
// A status response may perform the bounded AWG UAPI readiness/write/read
// sequence (1s + 3s + 5s). Keep the client deadline strictly above that
// service-side ceiling so abandoning a status request cannot leave the single
// manager pipe occupied by work the client has already timed out.
constexpr uint32_t kStatusCommandTimeoutMilliseconds = 12000;
constexpr uint32_t kMutationPipeWaitTimeoutMilliseconds = 5000;
constexpr uint32_t kStatusPipeWaitTimeoutMilliseconds = 300;

static_assert(kStartCommandTimeoutMilliseconds >
                  kStartOverallWatchdogMilliseconds,
              "Start response must outlast the synchronous service watchdog.");
static_assert(kStartOverallWatchdogMilliseconds >
                  kNormalAwgCriticalPathBudgetMilliseconds,
              "Start watchdog must fit the normal AWG critical path.");
static_assert(kStartOverallWatchdogMilliseconds >
                  kNormalWinnCriticalPathBudgetMilliseconds,
              "Start watchdog must fit the normal winn/3 critical path, which "
              "adds the engine CreateAck and the transport-observed gate.");
static_assert(kStatusCommandTimeoutMilliseconds >
                  kAwgBaselineReadinessTimeoutMilliseconds +
                      kAwgUapiWriteTimeoutMilliseconds +
                      kAwgUapiResponseTimeoutMilliseconds,
              "Status response must outlast its bounded AWG UAPI query.");

enum class Command : uint16_t {
  kStart = 1,
  kStop = 2,
  kStatus = 3,
};

enum class Status : uint16_t {
  kOk = 0,
  kRejected = 1,
  kInvalidRequest = 2,
  kOperationFailed = 3,
  // The start/stop round-trip success verbs. A kStart round-trip returns
  // kStartSucceeded on success and a kStop round-trip returns kStopSucceeded;
  // kOk is only used for kStatus. The client rejects a successful start/stop
  // that answers with the wrong verb, so the status a round-trip returns is
  // the correct one for the operation that was requested.
  kStartSucceeded = 4,
  kStopSucceeded = 5,
};

#pragma pack(push, 1)
struct RequestHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t command;
  uint32_t payload_size;
  uint32_t carrier_pid;
  uint64_t transition_generation;
};

struct ResponseHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t status;
  uint32_t payload_size;
};
#pragma pack(pop)

static_assert(sizeof(RequestHeader) == 24,
              "Tunnel service request header layout drifted.");
static_assert(sizeof(ResponseHeader) == 12,
              "Tunnel service response header layout drifted.");

}  // namespace winsvpn::tunnel_service

#endif  // RUNNER_WINDOWS_TUNNEL_SERVICE_PROTOCOL_H_
