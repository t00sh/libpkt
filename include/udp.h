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


#ifndef DEF_UDP_H
#define DEF_UDP_H


#include "types.h"

/*!
 * \file
 * \brief Implement LAYER_UDP
 */

/*! UDP header */
typedef struct udp_hdr {
  u16	src;   /**< source port */
  u16	dst;   /**< dest port */
  u16	len;   /**< len of the UDP header + data */
  u16	check; /**< checksum */
}udp_hdr;


#define UDP_HLEN 8UL
#define UDP_IS_VALID_LEN(len) (len >= UDP_HLEN)


/*! Get the UDP destination port */
int udp_get_dport(layer_t *l, u16 *port);

/*! Get the UDP source port */
int udp_get_sport(layer_t *l, u16 *port);

/*! Get the UDP len */
int udp_get_len(layer_t *l, u16 *len);

/*! Get the UDP checksum */
int udp_get_checksum(layer_t *l, u16 *checksum);


#endif /* DEF_UDP_H */
