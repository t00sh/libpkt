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

  dissector_run(tcp_dissectors,
		*layer,
		data + TCP_HLEN(tcp),
		size - TCP_HLEN(tcp));


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

int tcp_get_seq(layer_t *l, u32 *seq) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *seq = ntohl(hdr->seq);
  return 1;
}

int tcp_get_ackSeq(layer_t *l, u32 *ack_seq) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *ack_seq = ntohl(hdr->ack_seq);
  return 1;
}

int tcp_get_doff(layer_t *l, u8 *doff) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *doff = hdr->doff;
  return 1;
}

int tcp_get_fin(layer_t *l, u8 *fin) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *fin = hdr->fin;
  return 1;
}

int tcp_get_syn(layer_t *l, u8 *syn) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *syn = hdr->syn;
  return 1;
}

int tcp_get_rst(layer_t *l, u8 *rst) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *rst = hdr->rst;
  return 1;
}

int tcp_get_psh(layer_t *l, u8 *psh) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *psh = hdr->psh;
  return 1;
}

int tcp_get_ack(layer_t *l, u8 *ack) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *ack = hdr->ack;
  return 1;
}

int tcp_get_urg(layer_t *l, u8 *urg) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *urg = hdr->urg;
  return 1;
}

int tcp_get_ece(layer_t *l, u8 *ece) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *ece = hdr->ece;
  return 1;
}

int tcp_get_cwr(layer_t *l, u8 *cwr) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *cwr = hdr->cwr;
  return 1;
}

int tcp_get_flags(layer_t *l, u8 *flags) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *flags = hdr->flags;
  return 1;
}

int tcp_get_window(layer_t *l, u16 *window) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *window = ntohs(hdr->window);
  return 1;
}

int tcp_get_check(layer_t *l, u16 *check) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *check = hdr->check;
  return 1;
}

int tcp_get_urgPtr(layer_t *l, u16 *urg_ptr) {
  tcp_hdr *hdr;

  if(l->type !=  LAYER_TCP)
    return 0;

  hdr = l->object;
  *urg_ptr = ntohs(hdr->urg_ptr);
  return 1;
}
