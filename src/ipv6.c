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
#include "ipv6.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define IPV6_HBH_HLEN(h) (8UL + (h->hdr_len << 3))
#define IPV6_FRAG_HLEN 8UL
#define IPV6_ROUTE_HLEN(h) (8UL + (h->hdr_len << 3))

#define IPV6_MIN_HLEN 40UL
#define IPV6_IS_VALID_LEN(len) (len >= IPV6_MIN_HLEN)
#define IPV6_HLEN (IPV6_MIN_HLEN)

int ipv6_get_layer_nexthdr(layer_t *l, u8* nexthdr) {
  if(l->type == LAYER_IPV6)
    *nexthdr = ((ipv6_hdr*)(l->object))->nexthdr;
  else if(l->type == LAYER_IPV6_HBH_EXT)
    *nexthdr = ((ipv6_hbh_hdr*)(l->object))->nexthdr;
  else if(l->type == LAYER_IPV6_FRAG_EXT)
    *nexthdr = ((ipv6_frag_hdr*)(l->object))->nexthdr;
  else if(l->type == LAYER_IPV6_ROUTE_EXT)
    *nexthdr = ((ipv6_route_hdr*)(l->object))->nexthdr;
  else
    return 0;

  return 1;
}

int ipv6_is_tcp(layer_t *l) {
  u8 nexthdr;

  if(ipv6_get_layer_nexthdr(l, &nexthdr) && nexthdr == IPPROTO_TCP)
    return 1;
  return 0;
}

int ipv6_is_udp(layer_t *l) {
  u8 nexthdr;

  if(ipv6_get_layer_nexthdr(l, &nexthdr) && nexthdr == IPPROTO_UDP)
    return 1;
  return 0;
}

int ipv6_is_route_ext(layer_t *l) {
  u8 nexthdr;

  if(ipv6_get_layer_nexthdr(l, &nexthdr) && nexthdr == IPPROTO_ROUTING)
    return 1;
  return 0;
}

int ipv6_is_hbh_ext(layer_t *l) {
  u8 nexthdr;

  if(ipv6_get_layer_nexthdr(l, &nexthdr) && nexthdr == IPPROTO_HOPOPTS)
    return 1;
  return 0;
}

int ipv6_is_frag_ext(layer_t *l) {
  u8 nexthdr;

  if(ipv6_get_layer_nexthdr(l, &nexthdr) && nexthdr == IPPROTO_FRAGMENT)
    return 1;
  return 0;
}

int ipv6_parse_hbh_ext(packet_t *p, layer_t **layer, u8 *data, u32 size) {
  ipv6_hbh_hdr *hbh;

  if(size < sizeof(ipv6_hbh_hdr))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  hbh = (ipv6_hbh_hdr*)data;

  if(size < IPV6_HBH_HLEN(hbh)) {
    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_IPV6_HBH_EXT;
  (*layer)->object = hbh;

  dissector_run(p,
		ipv6_dissectors,
		*layer,
		data + IPV6_HBH_HLEN(hbh),
		size - IPV6_HBH_HLEN(hbh));

  return 1;
}

int ipv6_parse_frag_ext(packet_t *p, layer_t **layer, u8 *data, u32 size) {
  ipv6_frag_hdr *frag;

  if(size < sizeof(ipv6_frag_hdr))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  frag = (ipv6_frag_hdr*)data;

  (*layer)->type = LAYER_IPV6_FRAG_EXT;
  (*layer)->object = frag;

  dissector_run(p,
		ipv6_dissectors,
		*layer,
		data + IPV6_FRAG_HLEN,
		size - IPV6_FRAG_HLEN);

  return 1;
}

int ipv6_parse_route_ext(packet_t *p, layer_t **layer, u8 *data, u32 size) {
  ipv6_route_hdr *route;

  if(size < sizeof(ipv6_route_hdr))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  route = (ipv6_route_hdr*)data;

  if(size < IPV6_ROUTE_HLEN(route)) {
    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_IPV6_ROUTE_EXT;
  (*layer)->object = route;

  dissector_run(p,
		ipv6_dissectors,
		*layer,
		data + IPV6_ROUTE_HLEN(route),
		size - IPV6_ROUTE_HLEN(route));

  return 1;
}

int ipv6_parse(packet_t *p, layer_t **layer, u8 *data, u32 size) {
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

  dissector_run(p,
		ipv6_dissectors,
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

/* TODO: produce a "shorter" ipv6 (replace sequence of zero by ::) */
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

int ipv6_get_saddr(layer_t *l, ipv6addr_t *addr) {
  ipv6_hdr *hdr;

  if(l->type !=  LAYER_IPV6)
    return 0;

  hdr = l->object;
  memcpy(addr, &hdr->saddr, sizeof(ipv6addr_t));

  return 1;
}

int ipv6_get_daddr(layer_t *l, ipv6addr_t *addr) {
  ipv6_hdr *hdr;

  if(l->type !=  LAYER_IPV6)
    return 0;

  hdr = l->object;
  memcpy(addr, &hdr->daddr, sizeof(ipv6addr_t));

  return 1;
}
