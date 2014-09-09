#ifndef DEF_PACKET_H
#define DEF_PACKET_H

#include "types.h"
#include <stdlib.h>

typedef struct layer {
  int type;
  void *object;
  void (*destructor)(void*);
  struct layer *next;

}layer_t;

typedef struct packet {
  int last_layer;       /* Last layer type */
  u8* raw;              /* Raw packet */
  u32 size;             /* Raw packet size */
  layer_t *layers;      /* List of layers */

}packet_t;

packet_t* packet_new(void);
void packet_free(packet_t **packet);
layer_t* layer_new(void);
void layer_free(layer_t **layer);
layer_t* packet_get_layer(packet_t *p, int layer);
int packet_has_layer(packet_t *p, int layer);
void packet_foreach_layer(packet_t *p, void (*callback)(layer_t*, void* user), void* user);
packet_t* packet_parse(u8* data, u32 size, int layer_type);

#endif /* DEF_PACKET_H */
