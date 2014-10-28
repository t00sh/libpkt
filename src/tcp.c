#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "tcp.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TCP_PORT_NSIIOPS 261
#define TCP_PORT_HTTPS 443
#define TCP_PORT_DDM_SSL 448
#define TCP_PORT_SMTPS 465
#define TCP_PORT_NNTPS 563
#define TCP_PORT_SSHELL 614
#define TCP_PORT_LDAPS 636
#define TCP_PORT_FTPS_DATA 989
#define TCP_PORT_FTPS 990
#define TCP_PORT_TELNETS 992
#define TCP_PORT_IMAPS 993
#define TCP_PORT_IRCS 994
#define TCP_PORT_POP3S 995

#define TCP_CHECK_PORT(h,p) (ntohs(h->src) == p || ntohs(h->dst) == p)

int tcp_is_tls(layer_t *l) {
  tcp_hdr *tcp = l->object;

  if(TCP_CHECK_PORT(tcp, TCP_PORT_NSIIOPS) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_HTTPS) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_DDM_SSL) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_SMTPS) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_NNTPS) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_SSHELL) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_LDAPS) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_FTPS_DATA) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_FTPS) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_TELNETS) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_IMAPS) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_IRCS) ||
     TCP_CHECK_PORT(tcp, TCP_PORT_POP3S))
    return 1;
  return 0;
}

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
