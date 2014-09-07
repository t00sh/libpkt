#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "ipv4.h"

#include <stdlib.h>
#include <arpa/inet.h>

dissector_t ipv4_dissectors[] = {
  { NULL, NULL }
};
void ipv4_parse(packet_t **pkt, u8 *data, u32 size) {
  ipv4_hdr *ipv4;

  if(!IPV4_IS_VALID_LEN(size))
    return;

  if((*pkt = packet_new()) == NULL)
    return;

  ipv4 = (ipv4_hdr*)data;
  
  if(IPV4_HLEN(ipv4) == IPV4_MIN_HLEN)
    ipv4->options = NULL;

  if(IPV4_HLEN(ipv4) > size) {
    /* TODO: return error infos */

    packet_free(pkt);
    return;
  }

  if(ntohs(ipv4->tot_len) > size) {
    /* TODO: return error infos */

    packet_free(pkt);
    return;
  }

  (*pkt)->type = PKT_TYPE_IPV4;
  (*pkt)->object = ipv4;

  dissector_run(ipv4_dissectors, 
		*pkt, 
		data + IPV4_HLEN(ipv4),
		size - IPV4_HLEN(ipv4));
}
