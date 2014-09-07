#include "types.h"
#include "packet.h"
#include "dissector.h"
#include "ipv4.h"
#include "ether.h"

#include <stdlib.h>

int ether_is_ipv4(packet_t *pkt);

dissector_t ether_dissectors[] = {
  { ether_is_ipv4, ipv4_parse },
  { NULL,          NULL       }
};

int ether_is_ipv4(packet_t *pkt) {
  ether_hdr *hdr = pkt->object;

  if(ntohs(hdr->type) == ETHERTYPE_IP)
    return 1;

  return 0;
}

int ether_is_ipv6(packet_t *pkt) {
  ether_hdr *hdr = pkt->object;

  if(ntohs(hdr->type) == ETHERTYPE_IPV6)
    return 1;

  return 0;
}

void ether_parse(packet_t **pkt, u8 *data, u32 size) {
  if(!ETHER_IS_VALID_LEN(size))
    return;

  if((*pkt = packet_new()) == NULL)
    return;

  (*pkt)->type = PKT_TYPE_ETHER;
  (*pkt)->object = data;

  dissector_run(ether_dissectors, 
		*pkt, 
		data + ETHER_HLEN,
		size - ETHER_HLEN);
}
