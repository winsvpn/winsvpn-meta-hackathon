/*
 * A stand-in for WinsAmneziaWGPacketEngine that records what it was created
 * with instead of calling wgTurnOn().
 *
 * The real wrapper needs a live utun device, which does not exist outside a
 * NetworkExtension. Everything this harness is checking happens strictly ABOVE
 * that call: whether the Swift host starts the Winn seam first, reads the port
 * the REAL Go archive bound, and hands AmneziaWG a UAPI document repointed at
 * it. So the wrapper is replaced and the argument it receives is captured.
 *
 * Exports the identical v1 five-symbol carrier ABI, so WinsNativeEngineComponent
 * finds it through the same dlopen(NULL)/dlsym path it uses for a linked
 * component in the appex.
 */

#import <Foundation/Foundation.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static char *g_captured_uapi = NULL;
static int g_create_calls = 0;
static int g_start_calls = 0;
static int g_stop_calls = 0;
static int g_destroy_calls = 0;

typedef struct WinsAwgStub {
  char *uapi;
  bool started;
} WinsAwgStub;

__attribute__((visibility("default")))
int wins_amneziawg_packet_engine_contract_version(void) {
  return 1;
}

__attribute__((visibility("default")))
void *wins_amneziawg_packet_engine_create(const char *launch_json, const void *packet_flow) {
  (void)packet_flow;
  @autoreleasepool {
    g_create_calls += 1;
    if (launch_json == NULL) {
      return NULL;
    }
    NSData *data = [NSData dataWithBytes:launch_json length:strlen(launch_json)];
    NSError *error = nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error != nil || ![object isKindOfClass:[NSDictionary class]]) {
      return NULL;
    }
    id uapi = [(NSDictionary *)object objectForKey:@"amneziawg_uapi_config"];
    if (![uapi isKindOfClass:[NSString class]]) {
      return NULL;
    }
    WinsAwgStub *stub = (WinsAwgStub *)calloc(1, sizeof(WinsAwgStub));
    if (stub == NULL) {
      return NULL;
    }
    stub->uapi = strdup([(NSString *)uapi UTF8String]);
    if (g_captured_uapi != NULL) {
      free(g_captured_uapi);
    }
    g_captured_uapi = strdup(stub->uapi);
    return stub;
  }
}

__attribute__((visibility("default")))
int wins_amneziawg_packet_engine_start(void *opaque) {
  WinsAwgStub *stub = (WinsAwgStub *)opaque;
  g_start_calls += 1;
  if (stub == NULL) {
    return 0;
  }
  stub->started = true;
  return 1;
}

__attribute__((visibility("default")))
void wins_amneziawg_packet_engine_stop(void *opaque) {
  WinsAwgStub *stub = (WinsAwgStub *)opaque;
  g_stop_calls += 1;
  if (stub != NULL) {
    stub->started = false;
  }
}

__attribute__((visibility("default")))
void wins_amneziawg_packet_engine_destroy(void *opaque) {
  WinsAwgStub *stub = (WinsAwgStub *)opaque;
  g_destroy_calls += 1;
  if (stub == NULL) {
    return;
  }
  free(stub->uapi);
  free(stub);
}

/* Harness probes. */

__attribute__((visibility("default")))
const char *wins_test_captured_awg_uapi(void) {
  return g_captured_uapi;
}

__attribute__((visibility("default")))
void wins_test_reset_awg_stub(void) {
  if (g_captured_uapi != NULL) {
    free(g_captured_uapi);
    g_captured_uapi = NULL;
  }
  g_create_calls = 0;
  g_start_calls = 0;
  g_stop_calls = 0;
  g_destroy_calls = 0;
}

__attribute__((visibility("default")))
int wins_test_awg_create_calls(void) { return g_create_calls; }

__attribute__((visibility("default")))
int wins_test_awg_start_calls(void) { return g_start_calls; }

__attribute__((visibility("default")))
int wins_test_awg_stop_calls(void) { return g_stop_calls; }

__attribute__((visibility("default")))
int wins_test_awg_destroy_calls(void) { return g_destroy_calls; }
