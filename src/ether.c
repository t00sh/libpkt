#include "types.h"
#include "packet.h"
#include "dissector.h"
#include "ipv4.h"
#include "ether.h"
#include "parsers.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>


int ether_is_ipv4(layer_t *l) {
  ether_hdr *hdr = l->object;

  if(ntohs(hdr->type) == ETHERTYPE_IP)
    return 1;

  return 0;
}

int ether_is_ipv6(layer_t *l) {
  ether_hdr *hdr = l->object;

  if(ntohs(hdr->type) == ETHERTYPE_IPV6)
    return 1;

  return 0;
}

/* TODO: better error handling (not just return 0) */
int ether_parse(layer_t **layer, u8 *data, u32 size) {

  if(!ETHER_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  (*layer)->type = LAYER_ETHER;
  (*layer)->object = data;

  dissector_run(ether_dissectors,
		*layer,
		data + ETHER_HLEN,
		size - ETHER_HLEN);

  return 1;
}


int ether_get_type(layer_t *l, u16 *type) {
  ether_hdr *hdr;

  if(l->type !=  LAYER_ETHER)
    return 0;

  hdr = l->object;
  *type = ntohs(hdr->type);

  return 1;
}

static void ether_addr_to_str(etheraddr_t *addr, char str[ETHER_ADDR_STR_LEN]) {
  sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
	  addr->bytes[0],
	  addr->bytes[1],
	  addr->bytes[2],
	  addr->bytes[3],
	  addr->bytes[4],
	  addr->bytes[5]);
}

int ether_get_srcStr(layer_t *l, char addr[ETHER_ADDR_STR_LEN]) {
  ether_hdr *hdr;

  if(l->type !=  LAYER_ETHER)
    return 0;

  hdr = l->object;
  ether_addr_to_str(&hdr->src, addr);

  return 1;
}

int ether_get_dstStr(layer_t *l, char addr[ETHER_ADDR_STR_LEN]) {
  ether_hdr *hdr;

  if(l->type !=  LAYER_ETHER)
    return 0;

  hdr = l->object;
  ether_addr_to_str(&hdr->dst, addr);

  return 1;
}
