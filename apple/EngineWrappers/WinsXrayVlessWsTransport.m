#import <Foundation/Foundation.h>

#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * amneziawg-apple WireGuardKitGo C ABI (owner-controlled engine, do not bump).
 * LibXraySetSockCallback registers an xray-core DialerController that is
 * invoked on every outbound DefaultSystemDialer socket before connect:
 * IPv4, IPv6, Happy Eyeballs parallel dials, TLS/ECH DNS, and reconnects.
 * The Go side APPENDS controllers and rejects a NULL callback, so this
 * wrapper registers a stable C function once and never unregisters.
 */
typedef void (*libxray_sockcallback)(uintptr_t fd, void *ctx);
extern char *LibXrayRunXray(const char *datDir, const char *configPath, int64_t maxMemory);
extern char *LibXrayStopXray(void);
extern char *LibXraySetSockCallback(libxray_sockcallback cb, void *ctx);

/*
 * WINS_XRAY_LIBXRAY_MAX_MEMORY_BYTES
 *
 * LibXrayRunXray treats maxMemory == 0 as "no Go memory limit"
 * (amnezia-libxray skips InitForceFree / debug.SetMemoryLimit). That is
 * not acceptable in a Network Extension: the AWG and Xray C APIs share
 * one Go runtime inside libwg-go.a, and an unbounded Xray heap can
 * jetsam the appex and take AWG with it. Winn3 is a second Go runtime
 * in a different dylib; this cap does not SetMemoryLimit that runtime,
 * and it must stay small enough that Xray cannot crowd Winn3/Swift/NE
 * out of the iOS packet-tunnel jetsam budget (~50 MiB on iOS 15+,
 * ~15 MiB on iOS 13/14). The Winn3 direct-AWG start gate already
 * requires 12 MiB of remaining headroom.
 *
 * 16 MiB is a Go debug.SetMemoryLimit soft heap goal for the shared
 * AWG+Xray runtime: enough for AWG plus a VLESS-WS client, well under
 * the NE ceiling and the Winn3 headroom gate. Do not pass 0, and do not
 * raise this without re-measuring appex phys_footprint.
 */
#define WINS_XRAY_LIBXRAY_MAX_MEMORY_BYTES ((int64_t)(16 * 1024 * 1024))

static pthread_mutex_t g_xray_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_xray_protect_lock = PTHREAD_MUTEX_INITIALIZER;
static char *g_xray_dat_dir = NULL;
static char *g_xray_config_path = NULL;
static bool g_xray_configured = false;
static bool g_xray_running = false;
static bool g_xray_sock_callback_registered = false;
static bool g_xray_protect_active = false;
static int g_xray_fail_closed_poison_fd = -1;
static void *g_xray_callback_image_handle = NULL;

typedef enum {
  WINS_XRAY_LIFECYCLE_READY = 0,
  WINS_XRAY_LIFECYCLE_STARTING = 1,
  WINS_XRAY_LIFECYCLE_RUNNING = 2,
  WINS_XRAY_LIFECYCLE_STOPPING = 3,
  WINS_XRAY_LIFECYCLE_TERMINAL = 4,
} wins_xray_lifecycle_state;

/*
 * LibXray's callback ABI carries only (fd, ctx), with no immutable generation
 * token and no unregister operation. After the first RunXray attempt this
 * process can therefore never distinguish a delayed old-generation callback
 * from a new-generation callback. One Run attempt consumes the process.
 */
static wins_xray_lifecycle_state g_xray_lifecycle = WINS_XRAY_LIFECYCLE_READY;
#if defined(WINS_XRAY_TRANSPORT_TESTING) && WINS_XRAY_TRANSPORT_TESTING
/* -1 = live lookup; 0 = force unavailable; >0 = force this ifindex. */
static int g_xray_test_ifindex_override = -1;
static pthread_mutex_t g_xray_test_barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_xray_test_barrier_cond = PTHREAD_COND_INITIALIZER;
static bool g_xray_test_pause_before_lock = false;
static bool g_xray_test_before_lock_reached = false;
static bool g_xray_test_release_before_lock = false;
static bool g_xray_test_pause_before_bind = false;
static bool g_xray_test_before_bind_reached = false;
static bool g_xray_test_release_before_bind = false;
#endif

static NSDictionary *wins_xray_launch_dictionary(const char *launch_json) {
  if (launch_json == NULL || launch_json[0] == '\0') {
    return nil;
  }
  NSData *data = [NSData dataWithBytes:launch_json length:strlen(launch_json)];
  if (data.length == 0) {
    return nil;
  }
  NSError *error = nil;
  id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
  if (error != nil || ![object isKindOfClass:[NSDictionary class]]) {
    return nil;
  }
  return (NSDictionary *)object;
}

static NSString *wins_xray_required_string_value(NSDictionary *dictionary, NSString *key, NSUInteger max_length) {
  id value = [dictionary objectForKey:key];
  if ([value isKindOfClass:[NSString class]]) {
    NSString *trimmed = [(NSString *)value stringByTrimmingCharactersInSet:
        [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length > 0 && trimmed.length <= max_length) {
      return trimmed;
    }
  }
  return nil;
}

static BOOL wins_xray_has_no_whitespace_or_control(NSString *value) {
  NSCharacterSet *unsafe = [NSCharacterSet whitespaceAndNewlineCharacterSet];
  if ([value rangeOfCharacterFromSet:unsafe].location != NSNotFound) {
    return NO;
  }
  return [value rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location == NSNotFound;
}

static BOOL wins_xray_valid_ipv4_address(NSString *value) {
  NSArray<NSString *> *octets = [value componentsSeparatedByString:@"."];
  if (octets.count != 4) {
    return NO;
  }
  for (NSString *octet in octets) {
    if (octet.length == 0) {
      return NO;
    }
    NSScanner *scanner = [NSScanner scannerWithString:octet];
    scanner.charactersToBeSkipped = nil;
    NSInteger parsed = -1;
    if (![scanner scanInteger:&parsed] || !scanner.isAtEnd || parsed < 0 || parsed > 255) {
      return NO;
    }
    if (![[NSString stringWithFormat:@"%ld", (long)parsed] isEqualToString:octet]) {
      return NO;
    }
  }
  return YES;
}

static BOOL wins_xray_valid_host_name_or_address(NSString *value) {
  if (value.length == 0 || value.length > 253) {
    return NO;
  }
  if (!wins_xray_has_no_whitespace_or_control(value) ||
      [value containsString:@"/"] ||
      [value containsString:@":"]) {
    return NO;
  }
  if ([value isEqualToString:@"localhost"] || wins_xray_valid_ipv4_address(value)) {
    return YES;
  }
  if ([value hasPrefix:@"."] || [value hasSuffix:@"."]) {
    return NO;
  }
  NSCharacterSet *allowed =
      [NSCharacterSet characterSetWithCharactersInString:
          @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"];
  for (NSString *label in [value componentsSeparatedByString:@"."]) {
    if (label.length == 0 ||
        label.length > 63 ||
        [label hasPrefix:@"-"] ||
        [label hasSuffix:@"-"] ||
        [label rangeOfCharacterFromSet:[allowed invertedSet]].location != NSNotFound) {
      return NO;
    }
  }
  return YES;
}

static BOOL wins_xray_valid_path(NSString *value) {
  return [value hasPrefix:@"/"] &&
      value.length <= 2048 &&
      wins_xray_has_no_whitespace_or_control(value);
}

static NSNumber *wins_xray_required_port_value(NSDictionary *dictionary, NSString *key) {
  NSString *raw = wins_xray_required_string_value(dictionary, key, 5);
  if (raw == nil || raw.length == 0) {
    return nil;
  }
  NSScanner *scanner = [NSScanner scannerWithString:raw];
  scanner.charactersToBeSkipped = nil;
  NSInteger parsed = 0;
  if (![scanner scanInteger:&parsed] || !scanner.isAtEnd || parsed <= 0 || parsed > 65535) {
    return nil;
  }
  return @(parsed);
}

static NSDictionary *wins_xray_client_config(NSDictionary *xray) {
  NSString *uuid = wins_xray_required_string_value(xray, @"uuid", 64);
  NSString *host = wins_xray_required_string_value(xray, @"host", 253);
  NSNumber *port = wins_xray_required_port_value(xray, @"port");
  NSString *server_name = wins_xray_required_string_value(xray, @"servername", 253);
  NSString *path = wins_xray_required_string_value(xray, @"path", 2048);
  NSString *security =
      [wins_xray_required_string_value(xray, @"security", 8) lowercaseString];
  NSNumber *local_port = wins_xray_required_port_value(xray, @"localport");
  NSString *remote_awg_host = wins_xray_required_string_value(xray, @"remoteawghost", 253);
  NSNumber *remote_awg_port = wins_xray_required_port_value(xray, @"remoteawgport");

  if (uuid == nil ||
      [[NSUUID alloc] initWithUUIDString:uuid] == nil ||
      !wins_xray_valid_host_name_or_address(host) ||
      port == nil ||
      !wins_xray_valid_host_name_or_address(server_name) ||
      !wins_xray_valid_path(path) ||
      !([security isEqualToString:@"none"] || [security isEqualToString:@"tls"]) ||
      local_port == nil ||
      !wins_xray_valid_host_name_or_address(remote_awg_host) ||
      remote_awg_port == nil) {
    return nil;
  }

  // Xray 26.3.27 requires network/address/port for tunnel settings. Newer
  // prerelease field names are ignored and silently default this to TCP.
  NSDictionary *inbound_settings = @{
    @"network": @"udp",
    @"address": remote_awg_host,
    @"port": remote_awg_port,
    @"followRedirect": @NO,
    @"userLevel": @0
  };
  NSDictionary *inbound = @{
    @"tag": @"awg-local-in",
    @"listen": @"127.0.0.1",
    @"port": local_port,
    @"protocol": @"tunnel",
    @"settings": inbound_settings,
    @"streamSettings": @{
      @"sockopt": @{
        @"tcpNoDelay": @YES
      }
    }
  };

  NSDictionary *user = @{
    @"id": uuid,
    @"encryption": @"none",
    @"level": @0
  };
  NSDictionary *vnext = @{
    @"address": host,
    @"port": port,
    @"users": @[user]
  };
  NSDictionary *ws_settings = @{
    @"path": path,
    @"headers": @{@"Host": server_name}
  };
  NSMutableDictionary *stream_settings = [@{
    @"network": @"ws",
    @"security": security,
    @"wsSettings": ws_settings,
    @"sockopt": @{
      @"tcpNoDelay": @YES,
      @"domainStrategy": @"UseIPv4",
      @"tcpFastOpen": @YES,
      @"tcpKeepAliveIdle": @30,
      @"tcpKeepAliveInterval": @15,
      @"tcpUserTimeout": @15000,
      @"tcpMptcp": @NO
    }
  } mutableCopy];

  if ([security isEqualToString:@"tls"]) {
    [stream_settings setObject:@{
      @"serverName": server_name,
      @"allowInsecure": @NO
    } forKey:@"tlsSettings"];
  }

  NSDictionary *outbound = @{
    @"tag": @"vless-ws-out",
    @"protocol": @"vless",
    @"settings": @{@"vnext": @[vnext]},
    @"streamSettings": stream_settings,
    @"targetStrategy": @"UseIPv4",
    @"mux": @{
      @"enabled": @NO,
      @"concurrency": @0,
      @"xudpConcurrency": @0,
      @"xudpProxyUDP443": @"skip"
    }
  };
  NSDictionary *routing_rule = @{
    @"type": @"field",
    @"inboundTag": @[@"awg-local-in"],
    @"outboundTag": @"vless-ws-out"
  };

  NSDictionary *policy = @{
    @"levels": @{
      @"0": @{
        @"handshake": @4,
        @"connIdle": @300,
        @"uplinkOnly": @2,
        @"downlinkOnly": @5,
        @"bufferSize": @2048
      }
    },
    @"system": @{
      @"statsInboundUplink": @NO,
      @"statsInboundDownlink": @NO,
      @"statsOutboundUplink": @NO,
      @"statsOutboundDownlink": @NO
    }
  };

  return @{
    @"log": @{@"loglevel": @"warning"},
    @"policy": policy,
    @"inbounds": @[inbound],
    @"outbounds": @[outbound],
    @"routing": @{@"rules": @[routing_rule]}
  };
}

// Validates that `directory_path` is an existing directory owned by this
// process, not group/other accessible, and not a symlink, then returns an
// open directory descriptor (O_NOFOLLOW) so every later operation is
// anchored to that exact directory instead of a pathname that a same-user/
// same-container process could swap out from under us between checks
// (L-2). Returns a negative value on any validation failure.
static int wins_xray_open_verified_directory(NSString *directory_path) {
  const char *fs_path = directory_path.fileSystemRepresentation;
  if (fs_path == NULL) {
    return -1;
  }

  struct stat pre_open_info;
  memset(&pre_open_info, 0, sizeof(pre_open_info));
  if (lstat(fs_path, &pre_open_info) != 0 ||
      !S_ISDIR(pre_open_info.st_mode) ||
      pre_open_info.st_uid != geteuid() ||
      (pre_open_info.st_mode & 0777) != 0700) {
    return -1;
  }

  int dirfd = open(fs_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dirfd < 0) {
    return -1;
  }

  // Re-validate through the now-open descriptor to close the race between
  // the lstat above and this open() actually resolving the same directory.
  struct stat opened_info;
  memset(&opened_info, 0, sizeof(opened_info));
  if (fstat(dirfd, &opened_info) != 0 ||
      !S_ISDIR(opened_info.st_mode) ||
      opened_info.st_uid != geteuid() ||
      (opened_info.st_mode & 0777) != 0700 ||
      opened_info.st_dev != pre_open_info.st_dev ||
      opened_info.st_ino != pre_open_info.st_ino) {
    close(dirfd);
    return -1;
  }
  return dirfd;
}

static BOOL wins_xray_write_config(NSDictionary *config, NSString **dat_dir, NSString **config_path) {
  NSString *base = [NSTemporaryDirectory() stringByAppendingPathComponent:@"winsvpn-xray"];
  NSFileManager *file_manager = [NSFileManager defaultManager];
  NSError *error = nil;
  if (![file_manager createDirectoryAtPath:base
               withIntermediateDirectories:YES
                                attributes:@{NSFilePosixPermissions: @0700}
                                     error:&error]) {
    return NO;
  }

  NSData *data = [NSJSONSerialization dataWithJSONObject:config
                                                 options:NSJSONWritingSortedKeys
                                                   error:&error];
  if (data == nil || error != nil) {
    return NO;
  }

  int dirfd = wins_xray_open_verified_directory(base);
  if (dirfd < 0) {
    return NO;
  }

  // Clear any stale file left by a previous run/crash so the O_EXCL create
  // below is guaranteed to be a fresh file, then create and write the new
  // one by descriptor (openat/fchmod/write/fsync) rather than by pathname
  // (NSData writeToFile:/setAttributes:ofItemAtPath: both resolve the path
  // fresh and are not symlink-safe).
  if (unlinkat(dirfd, "wins_xray_client.json", 0) != 0 && errno != ENOENT) {
    close(dirfd);
    return NO;
  }
  int fd = openat(dirfd,
                   "wins_xray_client.json",
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                   0600);
  if (fd < 0 || fchmod(fd, 0600) != 0) {
    if (fd >= 0) {
      close(fd);
      (void)unlinkat(dirfd, "wins_xray_client.json", 0);
    }
    close(dirfd);
    return NO;
  }

  BOOL wrote_ok = YES;
  const char *bytes = data.bytes;
  size_t remaining = data.length;
  while (remaining > 0) {
    ssize_t written = write(fd, bytes, remaining);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      wrote_ok = NO;
      break;
    }
    bytes += written;
    remaining -= (size_t)written;
  }
  if (wrote_ok && fsync(fd) != 0) {
    wrote_ok = NO;
  }
  close(fd);
  if (!wrote_ok) {
    // A partial or unsynced file can still hold the VLESS uuid and server
    // address; never leave it behind on a failed configure.
    (void)unlinkat(dirfd, "wins_xray_client.json", 0);
  }
  close(dirfd);
  if (!wrote_ok) {
    return NO;
  }

  *dat_dir = base;
  *config_path = [base stringByAppendingPathComponent:@"wins_xray_client.json"];
  return YES;
}

static bool wins_xray_interface_name_is_non_physical(const char *name) {
  if (name == NULL || name[0] == '\0') {
    return true;
  }
  if (strcmp(name, "lo") == 0) {
    return true;
  }
  if (name[0] == 'l' && name[1] == 'o' && name[2] >= '0' && name[2] <= '9') {
    return true;
  }
  static const char *const prefixes[] = {
      "utun", "awdl", "llw", "ipsec", "p2p", "gif", "stf", "bridge", "ap1",
      "anpi", "vmenet", "vmnet", "feth", NULL};
  for (size_t i = 0; prefixes[i] != NULL; i++) {
    size_t prefix_len = strlen(prefixes[i]);
    if (strncmp(name, prefixes[i], prefix_len) == 0) {
      return true;
    }
  }
  return false;
}

static int wins_xray_interface_rank(const char *name) {
  if (strncmp(name, "en", 2) == 0) {
    return 3;
  }
  if (strncmp(name, "pdp_ip", 6) == 0) {
    return 2;
  }
  return 1;
}

/*
 * An interface is a usable egress only if it carries a routable address.
 * Thunderbolt/USB-C ports (en1..en6 on Apple silicon Macs) and an idle Wi-Fi
 * radio are IFF_UP with no address; binding a socket to one makes every
 * connect(2) fail with ENETUNREACH.
 */
static bool wins_xray_ifaddr_is_routable(const struct sockaddr *addr) {
  if (addr == NULL) {
    return false;
  }
  if (addr->sa_family == AF_INET) {
    uint32_t host = ntohl(((const struct sockaddr_in *)addr)->sin_addr.s_addr);
    return host != 0 && (host >> 24) != 127 && (host & 0xFFFF0000u) != 0xA9FE0000u;
  }
  if (addr->sa_family == AF_INET6) {
    const struct in6_addr *v6 = &((const struct sockaddr_in6 *)addr)->sin6_addr;
    return !IN6_IS_ADDR_UNSPECIFIED(v6) && !IN6_IS_ADDR_LOOPBACK(v6) &&
           !IN6_IS_ADDR_LINKLOCAL(v6);
  }
  return false;
}

static unsigned int wins_xray_physical_interface_index(void) {
#if defined(WINS_XRAY_TRANSPORT_TESTING) && WINS_XRAY_TRANSPORT_TESTING
  if (g_xray_test_ifindex_override >= 0) {
    return (unsigned int)g_xray_test_ifindex_override;
  }
#endif
  struct ifaddrs *list = NULL;
  if (getifaddrs(&list) != 0) {
    return 0;
  }
  unsigned int chosen = 0;
  int chosen_rank = -1;
  for (struct ifaddrs *ifa = list; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_name == NULL ||
        (ifa->ifa_flags & IFF_UP) == 0 ||
        (ifa->ifa_flags & IFF_RUNNING) == 0 ||
        (ifa->ifa_flags & IFF_LOOPBACK) != 0 ||
        !wins_xray_ifaddr_is_routable(ifa->ifa_addr) ||
        wins_xray_interface_name_is_non_physical(ifa->ifa_name)) {
      continue;
    }
    unsigned int index = if_nametoindex(ifa->ifa_name);
    if (index == 0) {
      continue;
    }
    int rank = wins_xray_interface_rank(ifa->ifa_name);
    if (rank > chosen_rank) {
      chosen = index;
      chosen_rank = rank;
    }
  }
  freeifaddrs(list);
  return chosen;
}

static int wins_xray_socket_domain(int fd) {
  struct sockaddr_storage storage;
  memset(&storage, 0, sizeof(storage));
  socklen_t storage_len = (socklen_t)sizeof(storage);
  if (getsockname(fd, (struct sockaddr *)&storage, &storage_len) == 0 &&
      (storage.ss_family == AF_INET || storage.ss_family == AF_INET6)) {
    return (int)storage.ss_family;
  }
  return AF_UNSPEC;
}

/*
 * Inactive/stale DialerController path. Darwin rejects an invalid bound-if
 * index and does not keep it on the socket; a full-duplex close on an
 * unconnected socket is a no-op; bind-to-loopback still lets
 * connect(127.0.0.1) send a SYN. listen(2) without a prior bind advertises
 * INADDR_ANY. Poison the engine-owned integer in place by dup2(2)-ing a
 * retained pipe read end onto fd. The poison descriptor is created before
 * the callback is registered, so this path allocates nothing and still works
 * at EMFILE. Later connect(2) fails with ENOTSOCK for IPv4 and IPv6, stream
 * and datagram. dup2 keeps the same integer so the kernel cannot reuse that
 * number for an unrelated descriptor; Go still owns it. If the invariant is
 * ever broken and dup2 cannot replace the socket, terminate the extension
 * rather than return a live, unprotected network descriptor.
 */
static void wins_xray_fail_closed_fd(int fd, int domain) {
  (void)domain;
  int rc;
  do {
    rc = dup2(g_xray_fail_closed_poison_fd, fd);
  } while (rc < 0 && errno == EINTR);
  if (rc != fd) {
    _exit(70);
  }
  int fd_flags = fcntl(fd, F_GETFD);
  if (fd_flags < 0 || fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) != 0) {
    _exit(70);
  }
#ifdef F_SETNOSIGPIPE
  (void)fcntl(fd, F_SETNOSIGPIPE, 1);
#endif
}

static bool wins_xray_prepare_fail_closed_poison_locked(void) {
  if (g_xray_fail_closed_poison_fd >= 0) {
    return true;
  }
  int poison[2];
  if (pipe(poison) != 0) {
    return false;
  }
  int flags = fcntl(poison[0], F_GETFD);
  int status_flags = fcntl(poison[0], F_GETFL);
  if (flags < 0 || status_flags < 0 ||
      fcntl(poison[0], F_SETFD, flags | FD_CLOEXEC) != 0 ||
      fcntl(poison[0], F_SETFL, status_flags | O_NONBLOCK) != 0) {
    close(poison[0]);
    close(poison[1]);
    return false;
  }
  close(poison[1]);
  g_xray_fail_closed_poison_fd = poison[0];
  return true;
}

static bool wins_xray_bind_fd_to_interface(int fd, int domain, unsigned int ifindex) {
  bool ok = false;
  if (domain == AF_INET6 || domain == AF_UNSPEC) {
    if (setsockopt(
            fd, IPPROTO_IPV6, IPV6_BOUND_IF, &ifindex, (socklen_t)sizeof(ifindex)) == 0) {
      ok = true;
    }
  }
  if (domain == AF_INET || domain == AF_UNSPEC) {
    if (setsockopt(
            fd, IPPROTO_IP, IP_BOUND_IF, &ifindex, (socklen_t)sizeof(ifindex)) == 0) {
      ok = true;
    }
  }
  return ok;
}

/*
 * PacketTunnel/NetworkExtension route-protection for ephemeral Xray
 * destinations: bind the fd to the physical (non-utun) interface by index
 * before connect. A single excludedRoutes /32 cannot cover Happy Eyeballs,
 * TLS/ECH DNS, or reconnect sockets. Do not close(fd); Go still owns it.
 */
static void wins_xray_sock_callback(uintptr_t raw_fd, void *ctx) {
  (void)ctx;
  if (raw_fd > (uintptr_t)INT_MAX) {
    return;
  }
  int fd = (int)raw_fd;
  if (fd < 0) {
    return;
  }

#if defined(WINS_XRAY_TRANSPORT_TESTING) && WINS_XRAY_TRANSPORT_TESTING
  pthread_mutex_lock(&g_xray_test_barrier_lock);
  if (g_xray_test_pause_before_lock) {
    g_xray_test_before_lock_reached = true;
    pthread_cond_broadcast(&g_xray_test_barrier_cond);
    while (!g_xray_test_release_before_lock) {
      pthread_cond_wait(&g_xray_test_barrier_cond, &g_xray_test_barrier_lock);
    }
  }
  pthread_mutex_unlock(&g_xray_test_barrier_lock);
#endif

  pthread_mutex_lock(&g_xray_protect_lock);
  int domain = wins_xray_socket_domain(fd);
  if (!g_xray_protect_active) {
    wins_xray_fail_closed_fd(fd, domain == AF_INET6 ? AF_INET6 : AF_INET);
    pthread_mutex_unlock(&g_xray_protect_lock);
    return;
  }

#if defined(WINS_XRAY_TRANSPORT_TESTING) && WINS_XRAY_TRANSPORT_TESTING
  pthread_mutex_lock(&g_xray_test_barrier_lock);
  if (g_xray_test_pause_before_bind) {
    g_xray_test_before_bind_reached = true;
    pthread_cond_broadcast(&g_xray_test_barrier_cond);
    while (!g_xray_test_release_before_bind) {
      pthread_cond_wait(&g_xray_test_barrier_cond, &g_xray_test_barrier_lock);
    }
  }
  pthread_mutex_unlock(&g_xray_test_barrier_lock);
#endif

  unsigned int ifindex = wins_xray_physical_interface_index();
  if (ifindex == 0 || !wins_xray_bind_fd_to_interface(fd, domain, ifindex)) {
    wins_xray_fail_closed_fd(fd, domain == AF_INET6 ? AF_INET6 : AF_INET);
  }
  pthread_mutex_unlock(&g_xray_protect_lock);
}

static bool wins_xray_pin_callback_image_locked(void) {
  if (g_xray_callback_image_handle != NULL) {
    return true;
  }
#if defined(WINS_XRAY_TRANSPORT_TESTING) && WINS_XRAY_TRANSPORT_TESTING
  /* The harness compiles the wrapper into its main executable. */
  g_xray_callback_image_handle = (void *)&wins_xray_sock_callback;
  return true;
#else
  Dl_info image;
  memset(&image, 0, sizeof(image));
  if (dladdr((const void *)&wins_xray_sock_callback, &image) == 0 ||
      image.dli_fname == NULL || image.dli_fname[0] == '\0') {
    return false;
  }
  void *handle = dlopen(image.dli_fname, RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL) {
    return false;
  }
  /* Intentionally never dlclose: LibXray permanently retains the callback. */
  g_xray_callback_image_handle = handle;
  return true;
#endif
}

static bool wins_xray_result_ok(char *result) {
  if (result == NULL) {
    return true;
  }
  bool ok = result[0] == '\0';
  free(result);
  return ok;
}

static void wins_xray_protect_disarm_locked(void) {
  pthread_mutex_lock(&g_xray_protect_lock);
  g_xray_protect_active = false;
  pthread_mutex_unlock(&g_xray_protect_lock);
}

static bool wins_xray_protect_arm_locked(void) {
  unsigned int ifindex = wins_xray_physical_interface_index();
  if (ifindex == 0) {
    return false;
  }
  pthread_mutex_lock(&g_xray_protect_lock);
  g_xray_protect_active = true;
  pthread_mutex_unlock(&g_xray_protect_lock);
  return true;
}

static bool wins_xray_register_sock_callback_locked(void) {
  if (g_xray_sock_callback_registered) {
    return true;
  }
  if (!wins_xray_prepare_fail_closed_poison_locked()) {
    return false;
  }
  if (!wins_xray_pin_callback_image_locked()) {
    return false;
  }
  char *result = LibXraySetSockCallback(wins_xray_sock_callback, NULL);
  if (!wins_xray_result_ok(result)) {
    return false;
  }
  g_xray_sock_callback_registered = true;
  return true;
}

static void wins_xray_stop_locked(void) {
  wins_xray_protect_disarm_locked();
  if (g_xray_lifecycle == WINS_XRAY_LIFECYCLE_RUNNING ||
      g_xray_lifecycle == WINS_XRAY_LIFECYCLE_STARTING) {
    g_xray_lifecycle = WINS_XRAY_LIFECYCLE_STOPPING;
    char *result = LibXrayStopXray();
    if (!wins_xray_result_ok(result)) {
      _exit(70);
    }
    g_xray_lifecycle = WINS_XRAY_LIFECYCLE_TERMINAL;
  }
  g_xray_running = false;
}

// Removes the on-disk Xray client config (it holds the VLESS uuid credential
// plus server host/port) once it is no longer needed. Must be called with
// g_xray_lock held. Deliberately NOT called from wins_xray_stop_locked(),
// which configure() also invokes when reconfiguring while already running —
// by that point configure() has already overwritten this same fixed path
// with the *new* config, so deleting there would remove the new file before
// start() ever reads it. Only the public stop()/start() entry points below
// call this, once the file is truly no longer in play.
static void wins_xray_delete_config_file_locked(void) {
  if (g_xray_config_path == NULL) {
    return;
  }
  NSString *path = [NSString stringWithUTF8String:g_xray_config_path];
  if (path != nil) {
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
  }
}

__attribute__((visibility("default")))
int wins_xray_vless_ws_transport_contract_version(void) {
  return 1;
}

__attribute__((visibility("default")))
int wins_xray_vless_ws_transport_configure(const char *launch_json) {
  @autoreleasepool {
    NSDictionary *launch = wins_xray_launch_dictionary(launch_json);
    NSDictionary *xray = [launch objectForKey:@"xray"];
    if (![xray isKindOfClass:[NSDictionary class]]) {
      return 0;
    }
    NSDictionary *config = wins_xray_client_config(xray);
    if (config == nil) {
      return 0;
    }

    pthread_mutex_lock(&g_xray_lock);
    if (g_xray_lifecycle == WINS_XRAY_LIFECYCLE_RUNNING ||
        g_xray_lifecycle == WINS_XRAY_LIFECYCLE_STARTING) {
      wins_xray_stop_locked();
      wins_xray_delete_config_file_locked();
      pthread_mutex_unlock(&g_xray_lock);
      return 0;
    }
    if (g_xray_lifecycle != WINS_XRAY_LIFECYCLE_READY) {
      pthread_mutex_unlock(&g_xray_lock);
      return 0;
    }

    NSString *dat_dir = nil;
    NSString *config_path = nil;
    if (!wins_xray_write_config(config, &dat_dir, &config_path)) {
      pthread_mutex_unlock(&g_xray_lock);
      return 0;
    }

    free(g_xray_dat_dir);
    free(g_xray_config_path);
    g_xray_dat_dir = strdup([dat_dir UTF8String]);
    g_xray_config_path = strdup([config_path UTF8String]);
    g_xray_configured = g_xray_dat_dir != NULL && g_xray_config_path != NULL;
    if (!g_xray_configured) {
      [[NSFileManager defaultManager] removeItemAtPath:config_path error:nil];
      free(g_xray_dat_dir);
      free(g_xray_config_path);
      g_xray_dat_dir = NULL;
      g_xray_config_path = NULL;
    }
    pthread_mutex_unlock(&g_xray_lock);

    return g_xray_configured ? 1 : 0;
  }
}

__attribute__((visibility("default")))
int wins_xray_vless_ws_transport_start(void) {
  pthread_mutex_lock(&g_xray_lock);
  if (g_xray_lifecycle == WINS_XRAY_LIFECYCLE_RUNNING && g_xray_running) {
    pthread_mutex_unlock(&g_xray_lock);
    return 1;
  }
  if (g_xray_lifecycle != WINS_XRAY_LIFECYCLE_READY) {
    pthread_mutex_unlock(&g_xray_lock);
    return 0;
  }
  if (!g_xray_configured || g_xray_dat_dir == NULL || g_xray_config_path == NULL) {
    pthread_mutex_unlock(&g_xray_lock);
    return 0;
  }

  bool ok = false;
  @try {
    if (!wins_xray_register_sock_callback_locked()) {
      return 0;
    }
    if (!wins_xray_protect_arm_locked()) {
      return 0;
    }
    g_xray_lifecycle = WINS_XRAY_LIFECYCLE_STARTING;
    char *run_result = LibXrayRunXray(
        g_xray_dat_dir, g_xray_config_path, WINS_XRAY_LIBXRAY_MAX_MEMORY_BYTES);
    ok = wins_xray_result_ok(run_result);
    g_xray_running = ok;
    if (ok) {
      g_xray_lifecycle = WINS_XRAY_LIFECYCLE_RUNNING;
    } else {
      wins_xray_protect_disarm_locked();
      g_xray_lifecycle = WINS_XRAY_LIFECYCLE_STOPPING;
      char *stop_result = LibXrayStopXray();
      if (!wins_xray_result_ok(stop_result)) {
        // _exit skips the @finally scrub below.
        wins_xray_delete_config_file_locked();
        _exit(70);
      }
      g_xray_lifecycle = WINS_XRAY_LIFECYCLE_TERMINAL;
    }
  } @finally {
    // LibXrayRunXray reads the config file once while starting and does not
    // revisit it afterward, so the on-disk copy (VLESS uuid + server host/
    // port) is scrubbed immediately whether start succeeded or failed,
    // rather than lingering until the next configure() overwrites it.
    wins_xray_delete_config_file_locked();
    pthread_mutex_unlock(&g_xray_lock);
  }
  return ok ? 1 : 0;
}

__attribute__((visibility("default")))
void wins_xray_vless_ws_transport_stop(void) {
  pthread_mutex_lock(&g_xray_lock);
  @try {
    wins_xray_stop_locked();
  } @finally {
    wins_xray_delete_config_file_locked();
    pthread_mutex_unlock(&g_xray_lock);
  }
}

#if defined(WINS_XRAY_TRANSPORT_TESTING) && WINS_XRAY_TRANSPORT_TESTING
/*
 * Test-only hooks. Production wrapper builds must not define
 * WINS_XRAY_TRANSPORT_TESTING; without it these symbols are absent.
 */
int64_t wins_xray_test_libxray_max_memory_bytes(void) {
  return WINS_XRAY_LIBXRAY_MAX_MEMORY_BYTES;
}

void wins_xray_test_set_ifindex_override(int ifindex) {
  g_xray_test_ifindex_override = ifindex;
}

void wins_xray_test_pause_callback_before_lock(void) {
  pthread_mutex_lock(&g_xray_test_barrier_lock);
  g_xray_test_pause_before_lock = true;
  g_xray_test_before_lock_reached = false;
  g_xray_test_release_before_lock = false;
  pthread_mutex_unlock(&g_xray_test_barrier_lock);
}

void wins_xray_test_wait_callback_before_lock(void) {
  pthread_mutex_lock(&g_xray_test_barrier_lock);
  while (!g_xray_test_before_lock_reached) {
    pthread_cond_wait(&g_xray_test_barrier_cond, &g_xray_test_barrier_lock);
  }
  pthread_mutex_unlock(&g_xray_test_barrier_lock);
}

void wins_xray_test_release_callback_before_lock(void) {
  pthread_mutex_lock(&g_xray_test_barrier_lock);
  g_xray_test_release_before_lock = true;
  g_xray_test_pause_before_lock = false;
  pthread_cond_broadcast(&g_xray_test_barrier_cond);
  pthread_mutex_unlock(&g_xray_test_barrier_lock);
}

void wins_xray_test_pause_callback_before_bind(void) {
  pthread_mutex_lock(&g_xray_test_barrier_lock);
  g_xray_test_pause_before_bind = true;
  g_xray_test_before_bind_reached = false;
  g_xray_test_release_before_bind = false;
  pthread_mutex_unlock(&g_xray_test_barrier_lock);
}

void wins_xray_test_wait_callback_before_bind(void) {
  pthread_mutex_lock(&g_xray_test_barrier_lock);
  while (!g_xray_test_before_bind_reached) {
    pthread_cond_wait(&g_xray_test_barrier_cond, &g_xray_test_barrier_lock);
  }
  pthread_mutex_unlock(&g_xray_test_barrier_lock);
}

void wins_xray_test_release_callback_before_bind(void) {
  pthread_mutex_lock(&g_xray_test_barrier_lock);
  g_xray_test_release_before_bind = true;
  g_xray_test_pause_before_bind = false;
  pthread_cond_broadcast(&g_xray_test_barrier_cond);
  pthread_mutex_unlock(&g_xray_test_barrier_lock);
}

int wins_xray_test_protect_active(void) {
  pthread_mutex_lock(&g_xray_protect_lock);
  bool active = g_xray_protect_active;
  pthread_mutex_unlock(&g_xray_protect_lock);
  return active ? 1 : 0;
}

int wins_xray_test_callback_registered(void) {
  pthread_mutex_lock(&g_xray_lock);
  bool registered = g_xray_sock_callback_registered;
  pthread_mutex_unlock(&g_xray_lock);
  return registered ? 1 : 0;
}

int wins_xray_test_running(void) {
  pthread_mutex_lock(&g_xray_lock);
  bool running = g_xray_running;
  pthread_mutex_unlock(&g_xray_lock);
  return running ? 1 : 0;
}

int wins_xray_test_terminal(void) {
  pthread_mutex_lock(&g_xray_lock);
  bool terminal = g_xray_lifecycle == WINS_XRAY_LIFECYCLE_TERMINAL;
  pthread_mutex_unlock(&g_xray_lock);
  return terminal ? 1 : 0;
}

int wins_xray_test_config_file_present(void) {
  pthread_mutex_lock(&g_xray_lock);
  int present = 0;
  if (g_xray_config_path != NULL) {
    present = access(g_xray_config_path, F_OK) == 0 ? 1 : 0;
  }
  pthread_mutex_unlock(&g_xray_lock);
  return present;
}
#endif
