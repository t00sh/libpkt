#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "ipv6.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ipv6_is_tcp(layer_t *l) {
  ipv6_hdr *ipv6 = l->object;

  if(ipv6->nexthdr == IPPROTO_TCP)
    return 1;
  return 0;
}

int ipv6_is_udp(layer_t *l) {
  ipv6_hdr *ipv6 = l->object;

  if(ipv6->nexthdr == IPPROTO_UDP)
    return 1;
  return 0;
}

int ipv6_parse(layer_t **layer, u8 *data, u32 size) {
  ipv6_hdr *ipv6;

  if(!IPV6_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  ipv6 = (ipv6_hdr*)data;

  if(ntohs(ipv6->payload_len) > size) {
    /* TODO: return error infos */

    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_IPV6;
  (*layer)->object = ipv6;

  dissector_run(ipv6_dissectors,
		*layer,
		data + IPV6_HLEN,
		size - IPV6_HLEN);

  return 1;
}

int ipv6_get_nexthdr(layer_t *l, u8 *nexthdr) {
  ipv6_hdr *hdr;

  if(l->type !=  LAYER_IPV6)
    return 0;

  hdr = l->object;
  *nexthdr = hdr->nexthdr;

  return 1;
}

static void ipv6_addr_to_str(ipv6addr_t *addr, char str[IPV6_ADDR_STR_LEN]) {
  sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	  addr->bytes[0],
	  addr->bytes[1],
	  addr->bytes[2],
	  addr->bytes[3],
	  addr->bytes[4],
	  addr->bytes[5],
	  addr->bytes[6],
	  addr->bytes[7],
	  addr->bytes[8],
	  addr->bytes[9],
	  addr->bytes[10],
	  addr->bytes[11],
	  addr->bytes[12],
	  addr->bytes[13],
	  addr->bytes[14],
	  addr->bytes[15]);
}

int ipv6_get_saddrStr(layer_t *l, char str[IPV6_ADDR_STR_LEN]) {
  ipv6_hdr *hdr;

  if(l->type !=  LAYER_IPV6)
    return 0;

  hdr = l->object;
  ipv6_addr_to_str(&hdr->saddr, str);

  return 1;
}

int ipv6_get_daddrStr(layer_t *l, char str[IPV6_ADDR_STR_LEN]) {
  ipv6_hdr *hdr;

  if(l->type !=  LAYER_IPV6)
    return 0;

  hdr = l->object;
  ipv6_addr_to_str(&hdr->daddr, str);

  return 1;
}
