/************************************************************************/
/* libpkt - A packet dissector library  			        */
/* 								        */
/* Copyright 2014, -TOSH-					        */
/* File coded by -TOSH-	(tosh <at> t0x0sh <dot> org		        */
/* 								        */
/* This file is part of libpkt.					        */
/* 								        */
/* libpkt is free software: you can redistribute it and/or modify       */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* libpkt is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with libpkt.  If not, see <http://www.gnu.org/licenses/>       */
/************************************************************************/


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

packet_t* packet_parse(const u8* data, u32 size, int layer_type) {
  packet_t *p;

  if(layer_type < 0 || layer_type >= LAYER_MAX)
    return NULL;
  if((p = packet_new()) == NULL)
    return NULL;

  p->size = size;
  p->raw  = data;

  if(!layer_parsers[layer_type](p, &p->layers, data, size)) {
    packet_free(&p);
    return NULL;
  }

  return p;
}
