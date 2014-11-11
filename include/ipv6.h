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


#ifndef DEF_IPV6_H
#define DEF_IPV6_H


#include "packet.h"
#include "types.h"
#include "ipv4.h"

/*!
 * \file
 * \brief Implement LAYER_IPV6
 */

#define IPV6_ALEN 16   /* Ipv6 address len */
#define IPV6_ADDR_STR_LEN 48 /* Ipv6 string len */

/*! ipv6 address structure */
typedef struct ipv6addr {
  u8 bytes[IPV6_ALEN];
}__attribute__((__packed__)) ipv6addr_t;

/*!
 * IPv6 header
 * \private
 */
typedef struct ipv6_hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  u8			priority:4,
    version:4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  u8			version:4,
    priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
  u8			flow_lbl[3];

  u16			payload_len;
  u8			nexthdr;
  u8			hop_limit;

  ipv6addr_t      	saddr;
  ipv6addr_t      	daddr;

}__attribute__((__packed__))ipv6_hdr;


/* Extension headers */

/*! Hop by hop and destination extension header
 * \private
 */
typedef struct ipv6_hbh_hdr {
  u8 nexthdr;
  u8 hdr_len;
  u16 opts;
  u32 opts2;

  /* Optional options and padding */

}__attribute__((__packed__)) ipv6_hbh_hdr;

/*! routing extension header
 * \private
 */
typedef struct ipv6_route_hdr {

  u8 nexthdr;
  u8 hdr_len;
  u8 type;
  u8 segments;
  u16 opts;

  /* Optional options and padding */

}__attribute__((__packed__)) ipv6_route_hdr;

/*! Fragment extension header
 * \private
 */
typedef struct ipv6_frag_hdr {
  u8 nexthdr;
  u8 reserved;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  u16 m:1,
    res:2,
    frag:13;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  u16 frag:13,
    res:2,
    m:1;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
  u32 ident;
}__attribute__((__packed__)) ipv6_frag_hdr;


typedef enum ipv6_proto {
  IPPROTO_HOPOPTS=0,
  IPPROTO_ROUTING=43,
  IPPROTO_FRAGMENT=44,
  IPPROTO_ICMPV6=58,
  IPPROTO_DSTOPTS=60,
  IPPROTO_MH=135
}ipv6_proto;


int ipv6_get_nexthdr(layer_t *l, u8 *nexthdr);
int ipv6_get_saddrStr(layer_t *l, char str[IPV6_ADDR_STR_LEN]);
int ipv6_get_daddrStr(layer_t *l, char str[IPV6_ADDR_STR_LEN]);
int ipv6_get_saddr(layer_t *l, ipv6addr_t *addr);
int ipv6_get_daddr(layer_t *l, ipv6addr_t *addr);

#endif /* DEF_IPV6_H */
