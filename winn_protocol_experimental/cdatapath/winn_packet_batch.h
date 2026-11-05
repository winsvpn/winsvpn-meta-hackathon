#ifndef WINS_WINN3_PACKET_BATCH_H
#define WINS_WINN3_PACKET_BATCH_H
#include <stddef.h>
#include <stdint.h>

/* Apple 64-bit ABI. All integers are in host byte order. */
#define WINS_WINN3_BATCH_MAX 32
#define WINS_WINN3_PACKET_STRIDE 24
#define WINS_WINN3_PACKET_MAX 65535

typedef struct WinsWinn3PacketDescriptor {
  void *data;
  uint32_t length;
  uint32_t capacity;
  uint32_t family;
  uint32_t reserved;
} WinsWinn3PacketDescriptor;

#if defined(__cplusplus)
static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
#else
_Static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
_Static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
#endif
#endif
