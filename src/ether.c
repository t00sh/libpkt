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


#include "types.h"
#include "packet.h"
#include "dissector.h"
#include "ipv4.h"
#include "ether.h"
#include "parsers.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define ETHER_HLEN	14
#define	ETHER_IS_VALID_LEN(l) ((l) >= ETHER_HLEN)

int ether_is_ipv4(layer_t *l) {
  ether_hdr *hdr = l->object;

  if(ntohs(hdr->type) == ETHERTYPE_IP)
    return 1;

  return 0;
}

int ether_is_ipv6(layer_t *l) {
  ether_hdr *hdr = l->object;

  if(ntohs(hdr->type) == ETHERTYPE_IPV6)
    return 1;

  return 0;
}

int ether_is_arp(layer_t *l) {
  ether_hdr *hdr = l->object;

  if(ntohs(hdr->type) == ETHERTYPE_ARP)
    return 1;

  return 0;
}

/* TODO: better error handling (not just return 0) */
int ether_parse(packet_t *p, layer_t **layer, u8 *data, u32 size) {

  if(!ETHER_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  (*layer)->type = LAYER_ETHER;
  (*layer)->object = data;

  dissector_run(p,
		ether_dissectors,
		*layer,
		data + ETHER_HLEN,
		size - ETHER_HLEN);

  return 1;
}


int ether_get_type(layer_t *l, u16 *type) {
  ether_hdr *hdr;

  if(l->type !=  LAYER_ETHER)
    return 0;

  hdr = l->object;
  *type = ntohs(hdr->type);

  return 1;
}

static void ether_addr_to_str(etheraddr_t *addr, char str[ETHER_ADDR_STR_LEN]) {
  sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
	  addr->bytes[0],
	  addr->bytes[1],
	  addr->bytes[2],
	  addr->bytes[3],
	  addr->bytes[4],
	  addr->bytes[5]);
}

int ether_get_srcStr(layer_t *l, char addr[ETHER_ADDR_STR_LEN]) {
  ether_hdr *hdr;

  if(l->type !=  LAYER_ETHER)
    return 0;

  hdr = l->object;
  ether_addr_to_str(&hdr->src, addr);

  return 1;
}

int ether_get_dstStr(layer_t *l, char addr[ETHER_ADDR_STR_LEN]) {
  ether_hdr *hdr;

  if(l->type !=  LAYER_ETHER)
    return 0;

  hdr = l->object;
  ether_addr_to_str(&hdr->dst, addr);

  return 1;
}
