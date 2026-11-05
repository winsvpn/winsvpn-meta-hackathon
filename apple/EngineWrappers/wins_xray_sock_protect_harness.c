/*
 * Direct in-process harness for Apple Xray socket protection.
 *
 * Compiles with -DWINS_XRAY_TRANSPORT_TESTING=1 against
 * WinsXrayVlessWsTransport.m and stub LibXray* symbols. It does not
 * link libwg-go.a, talk to the network, or build/sign an appex.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

typedef void (*libxray_sockcallback)(uintptr_t fd, void *ctx);

extern int wins_xray_vless_ws_transport_configure(const char *launch_json);
extern int wins_xray_vless_ws_transport_start(void);
extern void wins_xray_vless_ws_transport_stop(void);
extern int64_t wins_xray_test_libxray_max_memory_bytes(void);
extern void wins_xray_test_set_ifindex_override(int ifindex);
extern void wins_xray_test_pause_callback_before_lock(void);
extern void wins_xray_test_wait_callback_before_lock(void);
extern void wins_xray_test_release_callback_before_lock(void);
extern void wins_xray_test_pause_callback_before_bind(void);
extern void wins_xray_test_wait_callback_before_bind(void);
extern void wins_xray_test_release_callback_before_bind(void);
extern int wins_xray_test_protect_active(void);
extern int wins_xray_test_callback_registered(void);
extern int wins_xray_test_running(void);
extern int wins_xray_test_terminal(void);
extern int wins_xray_test_config_file_present(void);

#define MAX_STUB_CALLBACKS 8
static libxray_sockcallback g_stub_callbacks[MAX_STUB_CALLBACKS];
static void *g_stub_contexts[MAX_STUB_CALLBACKS];
static size_t g_stub_callback_count;
static int g_stub_set_fail;
static int g_stub_run_fail;
static int g_stub_stop_fail;
static int g_set_calls;
static int g_run_calls;
static int g_stop_calls;
static int64_t g_last_max_memory = -1;

struct callback_thread_args {
  int fd;
};

struct stop_thread_state {
  pthread_mutex_t lock;
  pthread_cond_t cond;
  bool entered;
  bool done;
};

char *LibXraySetSockCallback(libxray_sockcallback cb, void *ctx) {
  g_set_calls += 1;
  if (g_stub_set_fail) {
    char *message = strdup("sock callback unavailable");
    return message;
  }
  if (cb == NULL) {
    char *message = strdup("NULL sock callback");
    return message;
  }
  if (g_stub_callback_count >= MAX_STUB_CALLBACKS) {
    return strdup("too many sock callbacks");
  }
  g_stub_callbacks[g_stub_callback_count] = cb;
  g_stub_contexts[g_stub_callback_count] = ctx;
  g_stub_callback_count += 1;
  return NULL;
}

char *LibXrayRunXray(const char *datDir, const char *configPath, int64_t maxMemory) {
  (void)datDir;
  (void)configPath;
  g_run_calls += 1;
  g_last_max_memory = maxMemory;
  if (g_stub_run_fail) {
    return strdup("run failed after partial initialization");
  }
  return NULL;
}

char *LibXrayStopXray(void) {
  g_stop_calls += 1;
  if (g_stub_stop_fail) {
    return strdup("stop failed");
  }
  return NULL;
}

static void fail(const char *message) {
  fprintf(stderr, "FAIL: %s\n", message);
  exit(1);
}

static void expect(bool ok, const char *message) {
  if (!ok) {
    fail(message);
  }
}

static int open_socket(int family, int type) {
  int fd = socket(family, type, 0);
  if (fd < 0) {
    fail("socket()");
  }
  return fd;
}

static bool fd_is_open(int fd) {
  return fcntl(fd, F_GETFD) >= 0;
}

static unsigned int ipv4_bound_if(int fd) {
  unsigned int value = 0;
  socklen_t len = (socklen_t)sizeof(value);
  if (getsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &value, &len) != 0) {
    return 0;
  }
  return value;
}

static unsigned int ipv6_bound_if(int fd) {
  unsigned int value = 0;
  socklen_t len = (socklen_t)sizeof(value);
  if (getsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &value, &len) != 0) {
    return 0;
  }
  return value;
}

static void invoke_engine_callback(int fd) {
  expect(g_stub_callback_count > 0, "engine sock callback was not registered");
  for (size_t i = 0; i < g_stub_callback_count; i++) {
    expect(g_stub_callbacks[i] != NULL, "registered callback must be non-NULL");
    g_stub_callbacks[i]((uintptr_t)fd, g_stub_contexts[i]);
  }
}

static void *invoke_engine_callback_thread(void *opaque) {
  struct callback_thread_args *args = (struct callback_thread_args *)opaque;
  invoke_engine_callback(args->fd);
  return NULL;
}

static void *stop_transport_thread(void *opaque) {
  struct stop_thread_state *state = (struct stop_thread_state *)opaque;
  pthread_mutex_lock(&state->lock);
  state->entered = true;
  pthread_cond_broadcast(&state->cond);
  pthread_mutex_unlock(&state->lock);
  wins_xray_vless_ws_transport_stop();
  pthread_mutex_lock(&state->lock);
  state->done = true;
  pthread_cond_broadcast(&state->cond);
  pthread_mutex_unlock(&state->lock);
  return NULL;
}

static void apply_connect_watchdog(int fd) {
  struct timeval tv;
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, (socklen_t)sizeof(tv));
}

static int socket_type(int fd) {
  int type = -1;
  socklen_t len = (socklen_t)sizeof(type);
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0) {
    return -1;
  }
  return type;
}

static void expect_blocking_connect_enotsock(
    int family, int type, const char *ip, int port, const char *what) {
  int canary = open_socket(AF_INET, SOCK_DGRAM);
  int fd = open_socket(family, type);
  invoke_engine_callback(fd);
  expect(fd_is_open(fd), "fail-close must not close the engine-owned fd");
  expect(fd_is_open(canary), "fail-close must not close an unrelated descriptor");
  expect(socket_type(canary) == SOCK_DGRAM,
         "fail-close must not replace an unrelated descriptor");
  apply_connect_watchdog(fd);

  int rc = 0;
  int saved = 0;
  if (family == AF_INET6) {
    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin6_len = (uint8_t)sizeof(dest);
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons((uint16_t)port);
    expect(inet_pton(AF_INET6, ip, &dest.sin6_addr) == 1,
           "IPv6 inet_pton must accept the probe address");
    errno = 0;
    rc = connect(fd, (const struct sockaddr *)&dest, (socklen_t)sizeof(dest));
    saved = errno;
  } else {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_len = (uint8_t)sizeof(dest);
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)port);
    expect(inet_pton(AF_INET, ip, &dest.sin_addr) == 1,
           "IPv4 inet_pton must accept the probe address");
    errno = 0;
    rc = connect(fd, (const struct sockaddr *)&dest, (socklen_t)sizeof(dest));
    saved = errno;
  }
  close(fd);
  close(canary);

  if (rc == 0 || saved == ECONNREFUSED || saved == ETIMEDOUT ||
      saved == EINPROGRESS || saved != ENOTSOCK) {
    char message[320];
    snprintf(message,
             sizeof(message),
             "%s: blocking connect(%s, %d) rc=%d errno=%d",
             what,
             ip,
             port,
             rc,
             saved);
    fail(message);
  }
}

static void expect_localhost_connect_enotsock(void) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;
  struct addrinfo *resolved = NULL;
  expect(getaddrinfo("localhost", "9", &hints, &resolved) == 0 && resolved != NULL,
         "localhost must resolve from local host files");
  bool probed = false;
  for (struct addrinfo *ai = resolved; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
      continue;
    }
    int fd = open_socket(ai->ai_family, SOCK_STREAM);
    invoke_engine_callback(fd);
    expect(fd_is_open(fd), "localhost fail-close must not close the fd");
    apply_connect_watchdog(fd);
    errno = 0;
    int rc = connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen);
    int saved = errno;
    close(fd);
    probed = true;
    if (rc == 0 || saved == ECONNREFUSED || saved == ETIMEDOUT ||
        saved == EINPROGRESS || saved != ENOTSOCK) {
      freeaddrinfo(resolved);
      char message[320];
      snprintf(message,
               sizeof(message),
               "localhost blocking connect rc=%d errno=%d family=%d",
               rc,
               saved,
               ai->ai_family);
      fail(message);
    }
  }
  freeaddrinfo(resolved);
  expect(probed, "localhost must produce at least one IPv4 or IPv6 address");
}

static const char *kLaunchJson =
    "{\"xray\":{"
    "\"uuid\":\"123e4567-e89b-12d3-a456-426614174000\","
    "\"host\":\"example.invalid\","
    "\"port\":\"443\","
    "\"servername\":\"example.invalid\","
    "\"path\":\"/vless\","
    "\"security\":\"tls\","
    "\"localport\":\"51820\","
    "\"remoteawghost\":\"127.0.0.1\","
    "\"remoteawgport\":\"51821\""
    "}}";

static void configure_or_fail(void) {
  expect(wins_xray_vless_ws_transport_configure(kLaunchJson) == 1,
         "configure rejected a valid launch descriptor");
}

int main(void) {
  expect(wins_xray_test_libxray_max_memory_bytes() == (int64_t)(16 * 1024 * 1024),
         "appex libxray maxMemory must be 16 MiB");
  expect(wins_xray_test_libxray_max_memory_bytes() != 0,
         "appex libxray maxMemory must not be 0");

  expect(wins_xray_vless_ws_transport_start() == 0,
         "start without configure must fail closed");
  expect(g_set_calls == 0, "unconfigured start must not register a sock callback");
  expect(g_run_calls == 0, "unconfigured start must not run Xray");

  configure_or_fail();
  g_stub_set_fail = 1;
  expect(wins_xray_vless_ws_transport_start() == 0,
         "start must fail closed when LibXraySetSockCallback is unavailable");
  expect(g_run_calls == 0, "Xray must not start without a sock callback");
  expect(wins_xray_test_callback_registered() == 0,
         "failed registration must not be sticky");
  expect(wins_xray_test_protect_active() == 0,
         "failed registration must leave protection inactive");
  g_stub_set_fail = 0;

  configure_or_fail();
  wins_xray_test_set_ifindex_override(0);
  expect(wins_xray_vless_ws_transport_start() == 0,
         "start must fail closed when no physical interface is available");
  expect(g_set_calls == 2, "registration is attempted once after the failure case");
  expect(g_run_calls == 0, "Xray must not start without route protection");
  expect(wins_xray_test_protect_active() == 0,
         "unavailable protection must leave the gate inactive");
  expect(wins_xray_test_callback_registered() == 1,
         "a successful SetSockCallback must be retained");
  expect(g_stub_callback_count == 1,
         "successful registration must append exactly one DialerController");
  wins_xray_test_set_ifindex_override(-1);

  pid_t reconfigure_child = fork();
  expect(reconfigure_child >= 0,
         "fork for configure-while-running probe must succeed");
  if (reconfigure_child == 0) {
    configure_or_fail();
    int runs_before = g_run_calls;
    int stops_before = g_stop_calls;
    expect(wins_xray_vless_ws_transport_start() == 1,
           "configure-while-running probe must start once");
    expect(wins_xray_vless_ws_transport_configure(kLaunchJson) == 0,
           "configure while running must stop and reject replacement config");
    expect(g_run_calls == runs_before + 1,
           "configure while running must not start a replacement generation");
    expect(g_stop_calls == stops_before + 1,
           "configure while running must clean up the consumed generation");
    expect(wins_xray_test_terminal() == 1,
           "configure while running must consume the process generation");
    expect(wins_xray_test_protect_active() == 0,
           "configure while running must leave protection disarmed");
    expect(wins_xray_vless_ws_transport_start() == 0,
           "configure while running must make later start fail closed");
    expect(g_stub_callback_count == 1,
           "configure while running must not append another controller");
    int delayed = open_socket(AF_INET, SOCK_STREAM);
    invoke_engine_callback(delayed);
    errno = 0;
    expect(socket_type(delayed) == -1 && errno == ENOTSOCK,
           "old callback after configure-while-running must be poisoned");
    close(delayed);
    _exit(0);
  }
  int reconfigure_status = 0;
  expect(waitpid(reconfigure_child, &reconfigure_status, 0) == reconfigure_child,
         "waitpid for configure-while-running probe must succeed");
  expect(WIFEXITED(reconfigure_status) && WEXITSTATUS(reconfigure_status) == 0,
         "configure-while-running terminal child must pass");

  pid_t linearization_child = fork();
  expect(linearization_child >= 0,
         "fork for active-check linearization probe must succeed");
  if (linearization_child == 0) {
    configure_or_fail();
    expect(wins_xray_vless_ws_transport_start() == 1,
           "linearization probe must start once");
    int protected_fd = open_socket(AF_INET, SOCK_STREAM);
    struct callback_thread_args callback_args = {.fd = protected_fd};
    pthread_t callback_thread;
    wins_xray_test_pause_callback_before_bind();
    expect(pthread_create(
               &callback_thread, NULL, invoke_engine_callback_thread, &callback_args) == 0,
           "callback thread creation must succeed");
    wins_xray_test_wait_callback_before_bind();

    struct stop_thread_state stop_state = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .entered = false,
        .done = false,
    };
    pthread_t stop_thread;
    expect(pthread_create(&stop_thread, NULL, stop_transport_thread, &stop_state) == 0,
           "stop thread creation must succeed");
    pthread_mutex_lock(&stop_state.lock);
    while (!stop_state.entered) {
      pthread_cond_wait(&stop_state.cond, &stop_state.lock);
    }
    pthread_mutex_unlock(&stop_state.lock);
    usleep(50000);
    pthread_mutex_lock(&stop_state.lock);
    expect(!stop_state.done,
           "stop must not complete while callback holds the protection lock");
    pthread_mutex_unlock(&stop_state.lock);

    wins_xray_test_release_callback_before_bind();
    expect(pthread_join(callback_thread, NULL) == 0,
           "callback thread join must succeed");
    expect(pthread_join(stop_thread, NULL) == 0,
           "stop thread join must succeed");
    expect(ipv4_bound_if(protected_fd) != 0,
           "callback that passed the active check must bind before stop completes");
    expect(wins_xray_test_protect_active() == 0,
           "linearized stop must leave protection inactive");
    int stale_fd = open_socket(AF_INET, SOCK_STREAM);
    invoke_engine_callback(stale_fd);
    errno = 0;
    expect(socket_type(stale_fd) == -1 && errno == ENOTSOCK,
           "callback after linearized stop must be poisoned");
    close(stale_fd);
    close(protected_fd);
    _exit(0);
  }
  int linearization_status = 0;
  expect(waitpid(linearization_child, &linearization_status, 0) ==
             linearization_child,
         "waitpid for active-check linearization probe must succeed");
  expect(WIFEXITED(linearization_status) &&
             WEXITSTATUS(linearization_status) == 0,
         "active-check linearization child must pass");

  pid_t failed_run_child = fork();
  expect(failed_run_child >= 0, "fork for partial-run probe must succeed");
  if (failed_run_child == 0) {
    configure_or_fail();
    g_stub_run_fail = 1;
    int runs_before = g_run_calls;
    int stops_before = g_stop_calls;
    expect(wins_xray_vless_ws_transport_start() == 0,
           "a failed LibXrayRunXray must fail the wrapper start");
    expect(g_run_calls == runs_before + 1,
           "partial-run probe must call LibXrayRunXray exactly once");
    expect(g_stop_calls == stops_before + 1,
           "a failed LibXrayRunXray must close partial Go instance state");
    expect(wins_xray_test_terminal() == 1,
           "a RunXray attempt with successful cleanup must be terminal");
    expect(wins_xray_test_protect_active() == 0,
           "failed run cleanup must leave protection disarmed");
    g_stub_run_fail = 0;
    expect(wins_xray_vless_ws_transport_configure(kLaunchJson) == 0,
           "configure after a partial RunXray attempt must be rejected");
    expect(wins_xray_vless_ws_transport_start() == 0,
           "restart after a partial RunXray attempt must be rejected");
    expect(g_run_calls == runs_before + 1,
           "terminal restart must not call LibXrayRunXray again");
    int delayed = open_socket(AF_INET, SOCK_STREAM);
    invoke_engine_callback(delayed);
    errno = 0;
    expect(socket_type(delayed) == -1 && errno == ENOTSOCK,
           "delayed partial-run callback must be poisoned after cleanup");
    close(delayed);
    _exit(0);
  }
  int failed_run_status = 0;
  expect(waitpid(failed_run_child, &failed_run_status, 0) == failed_run_child,
         "waitpid for partial-run probe must succeed");
  expect(WIFEXITED(failed_run_status) && WEXITSTATUS(failed_run_status) == 0,
         "partial-run terminal child must pass");

  pid_t cleanup_failure_child = fork();
  expect(cleanup_failure_child >= 0,
         "fork for partial-run cleanup-failure probe must succeed");
  if (cleanup_failure_child == 0) {
    configure_or_fail();
    g_stub_run_fail = 1;
    g_stub_stop_fail = 1;
    (void)wins_xray_vless_ws_transport_start();
    _exit(99);
  }
  int cleanup_failure_status = 0;
  expect(waitpid(cleanup_failure_child, &cleanup_failure_status, 0) ==
             cleanup_failure_child,
         "waitpid for partial-run cleanup-failure probe must succeed");
  expect(WIFEXITED(cleanup_failure_status) &&
             WEXITSTATUS(cleanup_failure_status) == 70,
         "failed partial-run cleanup must terminate fail closed");

  configure_or_fail();
  expect(wins_xray_test_config_file_present() == 1,
         "configure must write the on-disk client config");
  expect(wins_xray_vless_ws_transport_start() == 1, "start with protection must succeed");
  expect(wins_xray_test_config_file_present() == 0,
         "start must delete the on-disk client config");
  expect(g_run_calls == 1, "LibXrayRunXray must run after protection is armed");
  expect(g_last_max_memory == (int64_t)(16 * 1024 * 1024),
         "LibXrayRunXray must receive the bounded appex maxMemory");
  expect(g_last_max_memory != 0, "LibXrayRunXray must not receive maxMemory 0");
  expect(wins_xray_test_protect_active() == 1, "protection must be active while running");
  expect(wins_xray_test_running() == 1, "transport must report running");
  expect(g_stub_callback_count == 1,
         "registered callback list must contain exactly one controller");
  expect(g_stub_callbacks[0] != NULL, "registered callback pointer must be retained");
  expect(g_stub_contexts[0] == NULL, "callback ctx must be NULL globals");

  int ipv4_tcp = open_socket(AF_INET, SOCK_STREAM);
  int ipv6_tcp = open_socket(AF_INET6, SOCK_STREAM);
  int ipv4_dns = open_socket(AF_INET, SOCK_DGRAM);
  int ipv6_dns = open_socket(AF_INET6, SOCK_DGRAM);
  invoke_engine_callback(ipv4_tcp);
  invoke_engine_callback(ipv6_tcp);
  invoke_engine_callback(ipv4_dns);
  invoke_engine_callback(ipv6_dns);
  expect(fd_is_open(ipv4_tcp) && fd_is_open(ipv6_tcp) && fd_is_open(ipv4_dns) &&
             fd_is_open(ipv6_dns),
         "protect must not close engine-owned fds");
  expect(ipv4_bound_if(ipv4_tcp) != 0 && ipv4_bound_if(ipv4_tcp) != UINT32_MAX,
         "IPv4 Happy Eyeballs TCP fd must be IP_BOUND_IF protected");
  expect(ipv6_bound_if(ipv6_tcp) != 0 && ipv6_bound_if(ipv6_tcp) != UINT32_MAX,
         "IPv6 Happy Eyeballs TCP fd must be IPV6_BOUND_IF protected");
  expect(ipv4_bound_if(ipv4_dns) != 0 && ipv4_bound_if(ipv4_dns) != UINT32_MAX,
         "IPv4 TLS/ECH DNS UDP fd must be IP_BOUND_IF protected");
  expect(ipv6_bound_if(ipv6_dns) != 0 && ipv6_bound_if(ipv6_dns) != UINT32_MAX,
         "IPv6 TLS/ECH DNS UDP fd must be IPV6_BOUND_IF protected");

  close(ipv4_tcp);
  close(ipv6_tcp);
  close(ipv4_dns);
  close(ipv6_dns);

  int reconnect = open_socket(AF_INET, SOCK_STREAM);
  invoke_engine_callback(reconnect);
  expect(fd_is_open(reconnect), "reconnect fd must stay owned by the engine");
  expect(ipv4_bound_if(reconnect) != 0 && ipv4_bound_if(reconnect) != UINT32_MAX,
         "reconnect socket must be protected before connect");
  close(reconnect);

  int set_calls_before_restart = g_set_calls;
  expect(wins_xray_vless_ws_transport_start() == 1, "idempotent start must succeed");
  expect(g_set_calls == set_calls_before_restart,
         "SetSockCallback must not append a second DialerController");

  pid_t stop_child = fork();
  expect(stop_child >= 0, "fork for stop-failure probe must succeed");
  if (stop_child == 0) {
    g_stub_stop_fail = 1;
    wins_xray_vless_ws_transport_stop();
    _exit(99);
  }
  int stop_status = 0;
  expect(waitpid(stop_child, &stop_status, 0) == stop_child,
         "waitpid for stop-failure probe must succeed");
  expect(WIFEXITED(stop_status) && WEXITSTATUS(stop_status) == 70,
         "failed LibXrayStopXray must terminate fail closed");

  int delayed_stop_fd = open_socket(AF_INET, SOCK_STREAM);
  struct callback_thread_args delayed_stop_args = {.fd = delayed_stop_fd};
  pthread_t delayed_stop_thread;
  wins_xray_test_pause_callback_before_lock();
  expect(pthread_create(
             &delayed_stop_thread, NULL, invoke_engine_callback_thread, &delayed_stop_args) == 0,
         "delayed callback thread creation must succeed");
  wins_xray_test_wait_callback_before_lock();
  wins_xray_vless_ws_transport_stop();
  wins_xray_test_release_callback_before_lock();
  expect(pthread_join(delayed_stop_thread, NULL) == 0,
         "delayed callback thread join must succeed");
  errno = 0;
  expect(socket_type(delayed_stop_fd) == -1 && errno == ENOTSOCK,
         "callback delayed across stop must be poisoned");
  close(delayed_stop_fd);
  expect(wins_xray_test_running() == 0, "stop must clear running");
  expect(wins_xray_test_protect_active() == 0, "stop must disarm protection");
  expect(wins_xray_test_config_file_present() == 0,
         "stop must not restore the client config");
  expect(g_stop_calls == 1, "stop must call LibXrayStopXray");
  expect(g_set_calls == set_calls_before_restart,
         "stop must not pass a NULL or replacement sock callback");
  expect(g_stub_callback_count == 1,
         "stop and rejected restart must retain exactly one controller");
  expect(g_stub_callbacks[0] != NULL,
         "callback function must remain the static production pointer");

  int stale = open_socket(AF_INET, SOCK_STREAM);
  invoke_engine_callback(stale);
  expect(fd_is_open(stale), "stale callback must not close the fd");
  close(stale);
  expect_blocking_connect_enotsock(
      AF_INET, SOCK_STREAM, "127.0.0.1", 9,
      "stale IPv4 TCP loopback 127.0.0.1:9");
  expect_blocking_connect_enotsock(
      AF_INET, SOCK_STREAM, "127.0.0.1", 1,
      "stale IPv4 TCP loopback 127.0.0.1:1");
  expect_blocking_connect_enotsock(
      AF_INET, SOCK_STREAM, "192.0.2.1", 443,
      "stale IPv4 TCP non-loopback 192.0.2.1:443");
  expect_blocking_connect_enotsock(
      AF_INET6, SOCK_STREAM, "::1", 9,
      "stale IPv6 TCP loopback ::1:9");
  expect_blocking_connect_enotsock(
      AF_INET6, SOCK_STREAM, "2001:db8::1", 443,
      "stale IPv6 TCP non-loopback 2001:db8::1:443");
  expect_blocking_connect_enotsock(
      AF_INET, SOCK_DGRAM, "127.0.0.1", 53,
      "stale IPv4 UDP loopback 127.0.0.1:53");
  expect_blocking_connect_enotsock(
      AF_INET, SOCK_DGRAM, "192.0.2.1", 53,
      "stale IPv4 UDP non-loopback 192.0.2.1:53");
  expect_blocking_connect_enotsock(
      AF_INET6, SOCK_DGRAM, "::1", 53,
      "stale IPv6 UDP loopback ::1:53");
  expect_blocking_connect_enotsock(
      AF_INET6, SOCK_DGRAM, "2001:db8::1", 53,
      "stale IPv6 UDP non-loopback 2001:db8::1:53");
  expect_localhost_connect_enotsock();

  int exhausted = open_socket(AF_INET, SOCK_STREAM);
  struct rlimit saved_limit;
  expect(getrlimit(RLIMIT_NOFILE, &saved_limit) == 0,
         "getrlimit(RLIMIT_NOFILE) must succeed");
  struct rlimit constrained_limit = saved_limit;
  if (constrained_limit.rlim_cur > 64) {
    constrained_limit.rlim_cur = 64;
  }
  expect(setrlimit(RLIMIT_NOFILE, &constrained_limit) == 0,
         "setrlimit(RLIMIT_NOFILE) must succeed");
  int fillers[256];
  size_t filler_count = 0;
  while (filler_count < sizeof(fillers) / sizeof(fillers[0])) {
    int filler = open("/dev/null", O_RDONLY);
    if (filler < 0) {
      break;
    }
    fillers[filler_count++] = filler;
  }
  expect(errno == EMFILE, "descriptor fill must reach EMFILE");
  invoke_engine_callback(exhausted);
  expect(setrlimit(RLIMIT_NOFILE, &saved_limit) == 0,
         "restoring RLIMIT_NOFILE must succeed");
  for (size_t i = 0; i < filler_count; i++) {
    close(fillers[i]);
  }
  errno = 0;
  expect(socket_type(exhausted) == -1 && errno == ENOTSOCK,
         "stale callback must poison the socket while at EMFILE");
  close(exhausted);

  expect(wins_xray_test_terminal() == 1,
         "a successful RunXray followed by stop must be terminal");
  expect(wins_xray_vless_ws_transport_configure(kLaunchJson) == 0,
         "configure after stop must require a fresh extension process");
  expect(wins_xray_vless_ws_transport_start() == 0,
         "restart after stop must be rejected");
  expect(g_set_calls == set_calls_before_restart,
         "rejected restart must not append a DialerController");
  expect(g_run_calls == 1,
         "rejected restart must not call LibXrayRunXray again");
  int after_restart = open_socket(AF_INET, SOCK_STREAM);
  invoke_engine_callback(after_restart);
  errno = 0;
  expect(socket_type(after_restart) == -1 && errno == ENOTSOCK,
         "rejected restart callback must remain on the poison path");
  close(after_restart);

  printf("APPLE XRAY SOCK PROTECT HARNESS: PASS\n");
  return 0;
}
