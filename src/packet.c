#include "packet.h"
#include "types.h"
#include "parsers.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

packet_t* packet_new(void) {
  packet_t *new;

  if((new = malloc(sizeof(packet_t))) == NULL)
    return NULL;

  memset(new, 0, sizeof(packet_t));

  return new;
}

layer_t* layer_new(void) {
  layer_t *new;

  if((new = malloc(sizeof(layer_t))) == NULL)
    return NULL;

  memset(new, 0, sizeof(layer_t));

  return new;
}

void layer_free(layer_t **layer) {
  layer_t *l = *layer;

  if(l == NULL)
    return;

  layer_free(&l->next);
  if(l->destructor)
    l->destructor(l->object);

  free(l);
  *layer = NULL;
}

void packet_free(packet_t **packet) {
  packet_t *pkt = *packet;

  layer_free(&pkt->layers);
  free(pkt);
  *packet = NULL;
}

layer_t* packet_get_layer(packet_t *p, int layer) {
  layer_t *it;

  for(it = p->layers; it; it = it->next) {
    if(it->type == layer)
      return it;
  }
  return NULL;
}

int packet_has_layer(packet_t *p, int layer) {
  return packet_get_layer(p, layer) != NULL;
}

void packet_foreach_layer(packet_t *p, void (*callback)(layer_t*, void* user), void* user) {
  layer_t *it;

  for(it = p->layers; it; it = it->next) {
    callback(it, user);
  }
}

packet_t* packet_parse(u8* data, u32 size, int layer_type) {
  packet_t *p;

  if(layer_type < 0 || layer_type >= LAYER_MAX)
    return NULL;
  if((p = packet_new()) == NULL)
    return NULL;

  if(!layer_parsers[layer_type](&p->layers, data, size)) {
    packet_free(&p);
    return NULL;
  }

  return p;
}
