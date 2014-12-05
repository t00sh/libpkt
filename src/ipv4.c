/************************************************************************/
/* libpkt - A packet dissector library  			        */
/* 								        */
/* Copyright 2014, -TOSH-					        */
/* File coded by -TOSH-	(tosh <at> t0x0sh <dot> org		        */
/* 								        */
/* This file is part of libpkt.					        */
/* 								        */
/* libpkt is free software: you can redistribute it and/or modify       */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* libpkt is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with libpkt.  If not, see <http://www.gnu.org/licenses/>       */
/************************************************************************/


#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "ipv4.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IPV4_MIN_HLEN (sizeof(ipv4_hdr))
#define IPV4_IS_VALID_LEN(len) (len >= IPV4_MIN_HLEN)
#define IPV4_HLEN(h) ((u16)(((ipv4_hdr*)(h))->ihl << 2))
#define IPV4_HAVE_OPTIONS(h) (IPV4_HLEN(h) > IPV4_MIN_HLEN)

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

int ipv4_parse(packet_t *p, layer_t **layer, const u8 *data, u32 size) {
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

  if(ntohs(ipv4->tot_len) > size ||
     ntohs(ipv4->tot_len) < IPV4_HLEN(ipv4)) {
    /* TODO: return error infos */

    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_IPV4;
  (*layer)->object = ipv4;

  dissector_run(p,
		ipv4_dissectors,
		*layer,
		data + IPV4_HLEN(ipv4),
		ntohs(ipv4->tot_len) - IPV4_HLEN(ipv4)
		);

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

int ipv4_get_saddr(layer_t *l, ipv4addr_t *addr) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  memcpy(addr, &hdr->saddr, sizeof(ipv4addr_t));

  return 1;
}

int ipv4_get_daddr(layer_t *l, ipv4addr_t *addr) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  memcpy(addr, &hdr->daddr, sizeof(ipv4addr_t));

  return 1;
}

int ipv4_get_ihl(layer_t *l, u8* ihl) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  *ihl = hdr->ihl;
  return 1;
}

int ipv4_get_version(layer_t *l, u8* version) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  *version = hdr->version;

  return 1;
}

int ipv4_get_tos(layer_t *l, u8* tos) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  *tos = hdr->tos;

  return 1;
}

int ipv4_get_totLen(layer_t *l, u16* tot_len) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  *tot_len = ntohs(hdr->tot_len);

  return 1;
}

int ipv4_get_id(layer_t *l, u16* id) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  *id = ntohs(hdr->id);

  return 1;
}

int ipv4_get_fragOff(layer_t *l, u16* frag_off) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  *frag_off = ntohs(hdr->frag_off);
  return 1;
}

int ipv4_get_ttl(layer_t *l, u8* ttl) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  *ttl = hdr->ttl;

  return 1;
}

int ipv4_get_check(layer_t *l, u16* check) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;
  *check = ntohs(hdr->check);

  return 1;
}

int ipv4_get_options(layer_t *l, u8** options, u32 *options_len) {
  ipv4_hdr *hdr;

  if(l->type !=  LAYER_IPV4)
    return 0;

  hdr = l->object;

  if(IPV4_HLEN(hdr) == IPV4_MIN_HLEN) {
    *options = NULL;
    *options_len = 0;
  } else {
    *options = (u8*)(hdr) + IPV4_MIN_HLEN;
    *options_len = IPV4_HLEN(hdr) - IPV4_MIN_HLEN;
  }

  return 1;
}
