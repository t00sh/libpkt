#ifndef DEF_PACKET_H
#define DEF_PACKET_H

#include "types.h"

#define PKT_TYPE_NONE    0
#define PKT_TYPE_ETHER   1
#define PKT_TYPE_IPV4    2
#define PKT_TYPE_IPV6    3
#define PKT_TYPE_TCP     4
#define PKT_TYPE_UDP     5

typedef struct packet {
  int type;
  void *object;
  void (*destructor)(void*);
  struct packet *next;

}packet_t;

packet_t* packet_new(void);
void packet_free(packet_t **packet);

#endif /* DEF_PACKET_H */
