#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "dns.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int dns_parse(layer_t **layer, u8 *data, u32 size) {
  dns_hdr *dns;

  if(!DNS_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  dns = (dns_hdr*)data;

  (*layer)->type = LAYER_DNS;
  (*layer)->object = dns;

  /* dissector_run(dns_dissectors,
		*layer,
		data + DNS_HLEN(dns),
		size - DNS_HLEN(dns));
  */

  return 1;
}

int dns_get_id(layer_t *l, u16 *id) {
  dns_hdr *hdr;

  if(l->type !=  LAYER_DNS)
    return 0;


  hdr = l->object;
  *id = ntohs(hdr->id);

  return 1;
}
