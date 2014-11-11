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
#include "dns.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DNS_MIN_HLEN 12UL
#define DNS_IS_VALID_LEN(len) (len >= DNS_MIN_HLEN)

int dns_parse(packet_t *p, layer_t **layer, u8 *data, u32 size) {
  dns_hdr *dns;

  (void)p;

  if(!DNS_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  dns = (dns_hdr*)data;

  (*layer)->type = LAYER_DNS;
  (*layer)->object = dns;

  /* dissector_run(dns_dissectors,
		*layer,
		data + DNS_HLEN(dns),
		size - DNS_HLEN(dns));
  */

  return 1;
}

int dns_get_id(layer_t *l, u16 *id) {
  dns_hdr *hdr;

  if(l->type !=  LAYER_DNS)
    return 0;


  hdr = l->object;
  *id = ntohs(hdr->id);

  return 1;
}
