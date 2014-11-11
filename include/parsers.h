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


#ifndef DEF_PARSERS_H
#define DEF_PARSERS_H

#include "dissector.h"

/*!
 * \file
 * \brief Layers and dissectors definitions
 */

/*! All layers types */
enum layer_types {
  LAYER_ETHER=0,         /**< Ethernet */
  LAYER_IPV4,            /**< IPv4 */
  LAYER_TCP,             /**< TCP */
  LAYER_UDP,             /**< UDP */
  LAYER_ICMP,            /**< ICMP */
  LAYER_ARP,             /**< ARP */
  LAYER_DNS,             /**< DNS */
  LAYER_IPV6,            /**< IPv6 */
  LAYER_RAW,             /**< Raw */
  LAYER_IPV6_HBH_EXT,    /**< IPv6 hbh extension header */
  LAYER_IPV6_FRAG_EXT,   /**< IPv6 frag extension header */
  LAYER_IPV6_ROUTE_EXT,  /**< IPv6 route extension header */
  LAYER_TLS,             /**< TLS/SSL */
  LAYER_MAX              /**< layer max (unused) */
};

extern int (*layer_parsers[])(packet_t *p, layer_t**, u8*, u32);
extern dissector_t ether_dissectors[];
extern dissector_t ipv4_dissectors[];
extern dissector_t udp_dissectors[];
extern dissector_t ipv6_dissectors[];
extern dissector_t tcp_dissectors[];
extern dissector_t icmp_dissectors[];
extern dissector_t tls_dissectors[];

#endif /* DEF_PARSERS_H */
