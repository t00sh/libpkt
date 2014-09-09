#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "ipv4.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ipv4_is_tcp(layer_t *l) {
  ipv4_hdr *ipv4 = l->object;

  if(ipv4->protocol == IPPROTO_TCP)
    return 1;
  return 0;
}

int ipv4_is_udp(layer_t *l) {
  ipv4_hdr *ipv4 = l->object;

  if(ipv4->protocol == IPPROTO_UDP)
    return 1;
  return 0;
}

int ipv4_is_icmp(layer_t *l) {
  ipv4_hdr *ipv4 = l->object;

  if(ipv4->protocol == IPPROTO_ICMP)
    return 1;
  return 0;
}

int ipv4_parse(layer_t **layer, u8 *data, u32 size) {
  ipv4_hdr *ipv4;

  if(!IPV4_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  ipv4 = (ipv4_hdr*)data;

  if(IPV4_HLEN(ipv4) > size) {
    /* TODO: return error infos */

    layer_free(layer);
    return 0;
  }

  if(ntohs(ipv4->tot_len) > size) {
    /* TODO: return error infos */

    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_IPV4;
  (*layer)->object = ipv4;

  dissector_run(ipv4_dissectors,
		*layer,
		data + IPV4_HLEN(ipv4),
		size - IPV4_HLEN(ipv4));

  return 1;
}

int ipv4_get_protocol(layer_t *l, u8 *proto) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  *proto = hdr->protocol;

  return 1;
}

static void ipv4_addr_to_str(ipv4addr_t *addr, char str[IPV4_ADDR_STR_LEN]) {
  sprintf(str, "%d.%d.%d.%d",
	  addr->bytes[0],
	  addr->bytes[1],
	  addr->bytes[2],
	  addr->bytes[3]);
}

int ipv4_get_saddrStr(layer_t *l, char str[IPV4_ADDR_STR_LEN]) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  ipv4_addr_to_str(&hdr->saddr, str);

  return 1;
}

int ipv4_get_daddrStr(layer_t *l, char str[IPV4_ADDR_STR_LEN]) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  ipv4_addr_to_str(&hdr->daddr, str);

  return 1;
}
