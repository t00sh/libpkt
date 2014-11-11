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


#ifndef DEF_IPV4_H
#define DEF_IPV4_H

#include "packet.h"
#include "types.h"

/*!
 * \file
 * \brief Implement LAYER_IPV4
 */

#define IPV4_ALEN 4   /* IPv4 address len */
#define IPV4_ADDR_STR_LEN 16 /* IPv4 string len */

/*! Describe ipv4 address */
typedef struct ipv4addr {
  u8 bytes[IPV4_ALEN];
}__attribute__((__packed__)) ipv4addr_t;

/*! IPv4 header
 * \private
 */
typedef struct ipv4_hdr {

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  u8         ihl:4;
  u8         version:4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  u8         version:4;
  u8         ihl:4;
#else
# error	"Endianness undefined ?!"
#endif
  u8	      tos;
  u16	      tot_len;
  u16	      id;
  u16	      frag_off;
  u8	      ttl;
  u8          protocol;
  u16         check;
  ipv4addr_t  saddr;
  ipv4addr_t  daddr;

  /* Options */
}__attribute__((__packed__)) ipv4_hdr;


/*! IPv4 protocols */
enum ipv4_proto {
  IPPROTO_ICMP=1,
  IPPROTO_TCP=6,
  IPPROTO_UDP=17
};

int ipv4_get_protocol(layer_t *l, u8 *proto);
int ipv4_get_saddrStr(layer_t *l, char str[IPV4_ADDR_STR_LEN]);
int ipv4_get_daddrStr(layer_t *l, char str[IPV4_ADDR_STR_LEN]);
int ipv4_get_ihl(layer_t *l, u8* ihl);
int ipv4_get_version(layer_t *l, u8* version);
int ipv4_get_tos(layer_t *l, u8* tos);
int ipv4_get_totLen(layer_t *l, u16* tot_len);
int ipv4_get_id(layer_t *l, u16* id);
int ipv4_get_fragOff(layer_t *l, u16* frag_off);
int ipv4_get_ttl(layer_t *l, u8* ttl);
int ipv4_get_check(layer_t *l, u16* check);
int ipv4_get_options(layer_t *l, u8** options, u32 *options_len);
int ipv4_get_daddr(layer_t *l, ipv4addr_t *addr);
int ipv4_get_saddr(layer_t *l, ipv4addr_t *addr);

#endif /* DEF_IPV4_H */
