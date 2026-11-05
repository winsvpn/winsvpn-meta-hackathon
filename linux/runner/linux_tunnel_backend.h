#ifndef RUNNER_LINUX_TUNNEL_BACKEND_H_
#define RUNNER_LINUX_TUNNEL_BACKEND_H_

#include <flutter_linux/flutter_linux.h>

#include <string>

void RegisterLinuxTunnelBackend(FlBinaryMessenger* messenger);
bool ShutdownLinuxTunnelBackend(std::string* error);

#endif  // RUNNER_LINUX_TUNNEL_BACKEND_H_
