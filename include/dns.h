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


#ifndef DEF_DNS_H
#define DEF_DNS_H


#include "types.h"

/*!
 * \file
 * \brief Implement LAYER_DNS
 */

/*! DNS header
 * \private
 */
typedef struct dns_hdr {

  u16 id;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  u16 rcode:4;
  u16 cd:1;
  u16 ad:1;
  u16 z:1;
  u16 ra:1;
  u16 rd:1;
  u16 tc:1;
  u16 aa:1;
  u16 opcode:4;
  u16 qr:1;
#elif __BYTE_ORDER__ == __ORGER_BIG_ENDIAN__
  u16 qr:1;
  u16 opcode:4;
  u16 aa:1;
  u16 tc:1;
  u16 rd:1;
  u16 ra:1;
  u16 z:1;
  u16 ad:1;
  u16 cd:1;
  u16 rcode:4;
#else
# error	"Please fix <bits/endian.h>"
#endif

  u16 tot_query;
  u16 tot_answer;
  u16 tot_auth_rr;
  u16 tot_add_rr;

}__attribute__((__packed__)) dns_hdr;


int dns_get_id(layer_t *l, u16 *id);

#endif /* DEF_DNS_H */
