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
#include "icmp.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define ICMP_MIN_HLEN 8UL
#define ICMP_IS_VALID_LEN(len) (len >= ICMP_MIN_HLEN)

int icmp_parse(packet_t *p, layer_t **layer, const u8 *data, u32 size) {
  icmp_hdr *icmp;

  if(!ICMP_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  icmp = (icmp_hdr*)data;

  (*layer)->type = LAYER_ICMP;
  (*layer)->object = icmp;

  dissector_run(p,
		icmp_dissectors,
		*layer,
		data + ICMP_MIN_HLEN,
		size - ICMP_MIN_HLEN);


  return 1;

}

int icmp_get_type(layer_t *l, u8 *type) {
  icmp_hdr *hdr;

  if(l->type !=  LAYER_ICMP)
    return 0;

  hdr = l->object;
  *type = hdr->type;
  return 1;
}

int icmp_get_code(layer_t *l, u8 *code) {
  icmp_hdr *hdr;

  if(l->type !=  LAYER_ICMP)
    return 0;

  hdr = l->object;
  *code = hdr->code;
  return 1;
}
