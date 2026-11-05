#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <TargetConditionals.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#if __has_include(<sys/kern_control.h>)
#include <sys/kern_control.h>
#else
#define MAX_KCTL_NAME 96
struct ctl_info {
  uint32_t ctl_id;
  char ctl_name[MAX_KCTL_NAME];
};
struct sockaddr_ctl {
  unsigned char sc_len;
  unsigned char sc_family;
  uint16_t ss_sysaddr;
  uint32_t sc_id;
  uint32_t sc_unit;
  uint32_t sc_reserved[5];
};
#define CTLIOCGINFO _IOWR('N', 3, struct ctl_info)
#endif

extern int wgTurnOn(const char *settings, int32_t tun_fd);
extern void wgTurnOff(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern char *wgGetConfig(int handle);

typedef struct WinsAmneziaWGPacketEngine {
  char *uapi_config;
  int32_t wg_handle;
  bool started;
  CFTypeRef retained_packet_flow;
} WinsAmneziaWGPacketEngine;

static char *wins_strdup_nsstring(NSString *value) {
  if (value == nil) {
    return NULL;
  }
  const char *utf8 = [value UTF8String];
  if (utf8 == NULL || utf8[0] == '\0') {
    return NULL;
  }
  return strdup(utf8);
}

static NSDictionary *wins_launch_dictionary(const char *launch_json) {
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

static int32_t wins_locate_utun_file_descriptor(void) {
  struct ctl_info ctl_info = {0};
  strlcpy(ctl_info.ctl_name, "com.apple.net.utun_control", sizeof(ctl_info.ctl_name));

  for (int32_t fd = 0; fd <= 1024; fd += 1) {
    struct sockaddr_ctl address = {0};
    socklen_t address_len = (socklen_t)sizeof(address);
    int result = getpeername(fd, (struct sockaddr *)&address, &address_len);
    if (result != 0 || address.sc_family != AF_SYSTEM) {
      continue;
    }

    if (ctl_info.ctl_id == 0) {
      result = ioctl(fd, CTLIOCGINFO, &ctl_info);
      if (result != 0) {
        continue;
      }
    }

    if (address.sc_id == ctl_info.ctl_id) {
      return fd;
    }
  }

  return -1;
}

__attribute__((visibility("default")))
int wins_amneziawg_packet_engine_contract_version(void) {
  return 1;
}

__attribute__((visibility("default")))
void *wins_amneziawg_packet_engine_create(const char *launch_json, const void *packet_flow) {
  @autoreleasepool {
    NSDictionary *launch = wins_launch_dictionary(launch_json);
    NSString *uapi_config = [launch objectForKey:@"amneziawg_uapi_config"];
    if (![uapi_config isKindOfClass:[NSString class]] || uapi_config.length == 0) {
      return NULL;
    }

    WinsAmneziaWGPacketEngine *engine =
        (WinsAmneziaWGPacketEngine *)calloc(1, sizeof(WinsAmneziaWGPacketEngine));
    if (engine == NULL) {
      return NULL;
    }

    engine->uapi_config = wins_strdup_nsstring(uapi_config);
    engine->wg_handle = -1;
    engine->started = false;
    if (packet_flow != NULL) {
      engine->retained_packet_flow = CFRetain(packet_flow);
    }

    if (engine->uapi_config == NULL) {
      if (engine->retained_packet_flow != NULL) {
        CFRelease(engine->retained_packet_flow);
      }
      free(engine);
      return NULL;
    }

    return engine;
  }
}

__attribute__((visibility("default")))
int wins_amneziawg_packet_engine_start(void *opaque_engine) {
  WinsAmneziaWGPacketEngine *engine = (WinsAmneziaWGPacketEngine *)opaque_engine;
  if (engine == NULL || engine->uapi_config == NULL) {
    return 0;
  }
  if (engine->started) {
    return 1;
  }

  int32_t tun_fd = wins_locate_utun_file_descriptor();
  if (tun_fd < 0) {
    return 0;
  }

  int32_t handle = wgTurnOn(engine->uapi_config, tun_fd);
  if (handle < 0) {
    return 0;
  }

  engine->wg_handle = handle;
  engine->started = true;

#if TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST
  wgDisableSomeRoamingForBrokenMobileSemantics(handle);
#endif

  return 1;
}

/*
 * The UDP port the running AWG engine is bound to, read from its own UAPI
 * "get" document, or 0. The document also carries private_key=, so it is
 * wiped before release and never logged.
 */
__attribute__((visibility("default")))
int wins_amneziawg_packet_engine_listen_port(void *opaque_engine) {
  WinsAmneziaWGPacketEngine *engine = (WinsAmneziaWGPacketEngine *)opaque_engine;
  if (engine == NULL || !engine->started || engine->wg_handle < 0) {
    return 0;
  }
  char *config = wgGetConfig(engine->wg_handle);
  if (config == NULL) {
    return 0;
  }
  int port = 0;
  const char *line = config;
  while (*line != '\0') {
    if (strncmp(line, "listen_port=", 12) == 0) {
      long value = strtol(line + 12, NULL, 10);
      if (value > 0 && value <= 65535) {
        port = (int)value;
      }
      break;
    }
    const char *newline = strchr(line, '\n');
    if (newline == NULL) {
      break;
    }
    line = newline + 1;
  }
  size_t length = strlen(config);
  memset_s(config, length, 0, length);
  free(config);
  return port;
}

__attribute__((visibility("default")))
void wins_amneziawg_packet_engine_stop(void *opaque_engine) {
  WinsAmneziaWGPacketEngine *engine = (WinsAmneziaWGPacketEngine *)opaque_engine;
  if (engine == NULL || !engine->started || engine->wg_handle < 0) {
    return;
  }

  wgTurnOff(engine->wg_handle);
  engine->wg_handle = -1;
  engine->started = false;
}

__attribute__((visibility("default")))
void wins_amneziawg_packet_engine_destroy(void *opaque_engine) {
  WinsAmneziaWGPacketEngine *engine = (WinsAmneziaWGPacketEngine *)opaque_engine;
  if (engine == NULL) {
    return;
  }

  wins_amneziawg_packet_engine_stop(engine);
  if (engine->uapi_config != NULL) {
    /* The UAPI document carries private_key= and preshared_key=. */
    memset_s(engine->uapi_config, strlen(engine->uapi_config), 0,
             strlen(engine->uapi_config));
  }
  free(engine->uapi_config);
  if (engine->retained_packet_flow != NULL) {
    CFRelease(engine->retained_packet_flow);
  }
  free(engine);
}
