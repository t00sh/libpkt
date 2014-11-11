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


#ifndef DEF_ETHER_H
#define DEF_ETHER_H

/*!
 * \file
 * \brief Implement LAYER_ETHER
 */

#define ETHER_ALEN 6		/* Ethernet address len */
#define ETHER_ADDR_STR_LEN 18   /* Ethernet address string len */

#include "types.h"

/*! ethernet address */
typedef struct etheraddr {
  u8 bytes[ETHER_ALEN];
}__attribute__((__packed__)) etheraddr_t;

/*! 10Mb/s ethernet header
 * \private
 */
typedef struct ether_hdr {
  etheraddr_t  dst;	/* destination eth addr	*/
  etheraddr_t  src;	/* source ether addr	*/
  u16 type;	        /* packet type ID field	*/
} __attribute__ ((__packed__)) ether_hdr;


#define	ETHERTYPE_PUP		0x0200          /**< Xerox PUP */
#define ETHERTYPE_SPRITE	0x0500		/**< Sprite */
#define	ETHERTYPE_IP		0x0800		/**< IP */
#define	ETHERTYPE_ARP		0x0806		/**< Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/**< Reverse ARP */
#define ETHERTYPE_AT		0x809B		/**< AppleTalk protocol */
#define ETHERTYPE_AARP		0x80F3		/**< AppleTalk ARP */
#define	ETHERTYPE_VLAN		0x8100		/**< IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX		0x8137		/**< IPX */
#define	ETHERTYPE_IPV6		0x86dd		/**< IP protocol version 6 */
#define ETHERTYPE_LOOPBACK	0x9000		/**< used to test interfaces */


int ether_get_type(layer_t *l, u16 *type);
int ether_get_srcStr(layer_t *l, char addr[ETHER_ADDR_STR_LEN]);
int ether_get_dstStr(layer_t *l, char addr[ETHER_ADDR_STR_LEN]);

#endif /* DEF_ETHER_H */
