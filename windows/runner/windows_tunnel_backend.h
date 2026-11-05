#ifndef RUNNER_WINDOWS_TUNNEL_BACKEND_H_
#define RUNNER_WINDOWS_TUNNEL_BACKEND_H_

#include <flutter/binary_messenger.h>

#include <string>

void RegisterWindowsTunnelBackend(flutter::BinaryMessenger* messenger);
void ShutdownWindowsTunnelBackend();
bool RunWindowsSecureStorageSelfTest(std::string* error);

#endif  // RUNNER_WINDOWS_TUNNEL_BACKEND_H_
