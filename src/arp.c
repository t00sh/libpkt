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
#include "arp.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARP_MIN_HLEN 8UL
#define ARP_HLEN(h) ((u32)(ARP_MIN_HLEN + 2*h->hln + 2*h->pln))
#define ARP_IS_VALID_LEN(len) (len >= ARP_MIN_HLEN)

int arp_parse(packet_t *p, layer_t **layer, u8 *data, u32 size) {
  arp_hdr *arp;

  (void)p;

  if(!ARP_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  arp = (arp_hdr*)data;

  if(ARP_HLEN(arp) >= size) {
    layer_free(layer);
    return 0;
  }

  (*layer)->type = LAYER_ARP;
  (*layer)->object = arp;

  return 1;

}

int arp_get_op(layer_t *l, u16 *op) {
  arp_hdr *hdr;

  if(l->type !=  LAYER_ARP)
    return 0;

  hdr = l->object;
  *op = hdr->op;
  return 1;
}
