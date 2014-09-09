#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "udp.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int udp_parse(layer_t **layer, u8 *data, u32 size) {
    udp_hdr *udp;

  if(!UDP_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  udp = (udp_hdr*)data;

  if(UDP_HLEN > size) {
    /* TODO: return error infos */

    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_UDP;
  (*layer)->object = udp;

  /* dissector_run(udp_dissectors,
		*layer,
		data + UDP_HLEN(udp),
		size - UDP_HLEN(udp));
  */

  return 1;

}

int udp_get_sport(layer_t *l, u16 *port) {
  udp_hdr *hdr;

  if(l->type !=  LAYER_UDP)
    return 0;

  hdr = l->object;
  *port = ntohs(hdr->src);
  return 1;
}

int udp_get_dport(layer_t *l, u16 *port) {
  udp_hdr *hdr;

  if(l->type !=  LAYER_UDP)
    return 0;

  hdr = l->object;
  *port = ntohs(hdr->dst);
  return 1;
}
