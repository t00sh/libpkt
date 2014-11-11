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


#ifndef DEF_ARP_H
#define DEF_ARP_H


#include "types.h"

/*!
 * \file
 * \brief implement ARP_LAYER
 */

/*!
 * Structure for the ARP header
 * \private
 */
typedef struct arp_hdr {
  u16	hrd;	/**< format of hardware address */
  u16	pro;	/**< format of protocol address */
  u8	hln;	/**< length of hardware address (ETH_ADDR_LEN) */
  u8	pln;	/**< length of protocol address (IP_ADDR_LEN) */
  u16	op;	/**< operation */
}__attribute__((__packed__))arp_hdr;

/*!
 * Hardware address format
 */
typedef enum arp_hrd_format {
  ARP_HRD_ETH=0x0001,	   /**< ethernet hardware */
  ARP_HRD_IEEE802=0x0006   /**< IEEE 802 hardware */
}arp_hrd_format;

/*!
 * Protocol address format
 */
typedef enum arp_pro_format {
  ARP_PRO_IP=0x0800,	/**< IP protocol */
}arp_pro_format;

/*
 * ARP operation
 */
typedef enum arp_op {
  ARP_OP_REQUEST=1,	/**< request to resolve ha given pa */
  ARP_OP_REPLY=2,	/**< response giving hardware address */
  ARP_OP_REVREQUEST=3,	/**< request to resolve pa given ha */
  ARP_OP_REVREPLY=4,	/**< response giving protocol address */
}arp_op;

/*!
 * Get the ARP op field
 * @param l The ARP layer
 * @param op A pointer to u16 integer, for storing operator
 * @return 0 if <l> isn't a ARP layer, 1 overwhise
 */
int arp_get_op(layer_t *l, u16 *op);

#endif /* DEF_ARP_H */
