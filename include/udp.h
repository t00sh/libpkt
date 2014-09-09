#ifndef DEF_UDP_H
#define DEF_UDP_H

#include "types.h"
#include <sys/types.h>

typedef struct udp_hdr {
	u16	src;
	u16	dst;
	u16	len;
	u16	check;
}udp_hdr;


#define UDP_HLEN 8UL
#define UDP_IS_VALID_LEN(len) (len >= UDP_HLEN)


int udp_get_dport(layer_t *l, u16 *port);
int udp_get_sport(layer_t *l, u16 *port);

#endif /* DEF_UDP_H */
