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
#include "udp.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define UDP_PORT_DNS 53

int udp_is_dns(layer_t *l) {
  udp_hdr *udp = l->object;

  if(ntohs(udp->src) == UDP_PORT_DNS ||
     ntohs(udp->dst) == UDP_PORT_DNS)
    return 1;
  return 0;
}

int udp_parse(packet_t *p, layer_t **layer, u8 *data, u32 size) {
    udp_hdr *udp;

  if(!UDP_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  udp = (udp_hdr*)data;

  if(UDP_HLEN > size) {
    /* TODO: return error infos */

    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_UDP;
  (*layer)->object = udp;

  dissector_run(p,
		udp_dissectors,
		*layer,
		data + UDP_HLEN,
		size - UDP_HLEN);


  return 1;

}

int udp_get_sport(layer_t *l, u16 *port) {
  udp_hdr *hdr;

  if(l->type !=  LAYER_UDP)
    return 0;

  hdr = l->object;
  *port = ntohs(hdr->src);
  return 1;
}

int udp_get_dport(layer_t *l, u16 *port) {
  udp_hdr *hdr;

  if(l->type !=  LAYER_UDP)
    return 0;

  hdr = l->object;
  *port = ntohs(hdr->dst);
  return 1;
}


int udp_get_len(layer_t *l, u16 *len) {
  udp_hdr *hdr;

  if(l->type !=  LAYER_UDP)
    return 0;

  hdr = l->object;
  *len = ntohs(hdr->len);
  return 1;
}

int udp_get_checksum(layer_t *l, u16 *checksum) {
  udp_hdr *hdr;

  if(l->type !=  LAYER_UDP)
    return 0;

  hdr = l->object;
  *checksum = ntohs(hdr->check);
  return 1;
}
