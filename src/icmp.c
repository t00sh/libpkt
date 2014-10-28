#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "icmp.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int icmp_parse(layer_t **layer, u8 *data, u32 size) {
    icmp_hdr *icmp;

  if(!ICMP_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  icmp = (icmp_hdr*)data;

  (*layer)->type = LAYER_ICMP;
  (*layer)->object = icmp;

  dissector_run(icmp_dissectors,
		*layer,
		data + ICMP_MIN_HLEN,
		size - ICMP_MIN_HLEN);


  return 1;

}

int icmp_get_type(layer_t *l, u8 *type) {
  icmp_hdr *hdr;

  if(l->type !=  LAYER_ICMP)
    return 0;

  hdr = l->object;
  *type = hdr->type;
  return 1;
}

int icmp_get_code(layer_t *l, u8 *code) {
  icmp_hdr *hdr;

  if(l->type !=  LAYER_ICMP)
    return 0;

  hdr = l->object;
  *code = hdr->code;
  return 1;
}
