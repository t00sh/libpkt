#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "tcp.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int tcp_parse(layer_t **layer, u8 *data, u32 size) {
    tcp_hdr *tcp;

  if(!TCP_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  tcp = (tcp_hdr*)data;

  if(TCP_HLEN(tcp) > size) {
    /* TODO: return error infos */

    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_TCP;
  (*layer)->object = tcp;

  /* dissector_run(tcp_dissectors,
		*layer,
		data + TCP_HLEN(tcp),
		size - TCP_HLEN(tcp));
  */

  return 1;

}

int tcp_get_sport(layer_t *l, u16 *port) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *port = ntohs(hdr->src);
  return 1;
}

int tcp_get_dport(layer_t *l, u16 *port) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *port = ntohs(hdr->dst);
  return 1;
}
