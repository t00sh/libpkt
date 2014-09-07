#include "packet.h"
#include "types.h"
#include <stdlib.h>
#include <string.h>

packet_t* packet_new(void) {
  packet_t *new;

  if((new = malloc(sizeof(packet_t))) == NULL)
    return NULL;

  memset(new, 0, sizeof(packet_t));

  return new;
}

void packet_free(packet_t **packet) {
  packet_t *pkt = *packet;

  if(pkt->next != NULL) {
    packet_free(&pkt->next);
  }

  if(pkt->destructor != NULL) {
    pkt->destructor(pkt->object);
  }

  free(pkt);
  *packet = NULL;
}


void packet_insert(packet_t **dst, packet_t *src) {
  packet_t *tmp;

  if(*dst == NULL) {
    *dst = src;
  } else {
    tmp = *dst;

    while(tmp->next) {
      tmp = tmp->next;
    }

    tmp->next = src;
  }
}
