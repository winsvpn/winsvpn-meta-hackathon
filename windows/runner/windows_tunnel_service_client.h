#ifndef RUNNER_WINDOWS_TUNNEL_SERVICE_CLIENT_H_
#define RUNNER_WINDOWS_TUNNEL_SERVICE_CLIENT_H_

#include <string>
#include <cstdint>

bool StartWindowsTunnelThroughService(const std::string& config,
                                      uint32_t carrier_pid,
                                      uint64_t transition_generation,
                                      std::string* error);
bool ArmWindowsTunnelStartCancellation(uint64_t transition_generation,
                                       std::string* error);
void SignalWindowsTunnelStartCancellation();
void DisarmWindowsTunnelStartCancellation();
bool StopWindowsTunnelThroughService(std::string* error);
bool QueryWindowsTunnelManager(std::string* status, std::string* error);

#endif  // RUNNER_WINDOWS_TUNNEL_SERVICE_CLIENT_H_
