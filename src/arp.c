#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "arp.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int arp_parse(layer_t **layer, u8 *data, u32 size) {
    arp_hdr *arp;

  if(!ARP_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  arp = (arp_hdr*)data;

  if(ARP_HLEN(arp) >= size) {
    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_ARP;
  (*layer)->object = arp;

  /* dissector_run(arp_dissectors,
		*layer,
		data + ARP_HLEN(arp),
		size - ARP_HLEN(arp));
  */

  return 1;

}

int arp_get_op(layer_t *l, u16 *op) {
  arp_hdr *hdr;

  if(l->type !=  LAYER_ARP)
    return 0;

  hdr = l->object;
  *op = hdr->op;
  return 1;
}
