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


#ifndef DEF_TCP_H
#define DEF_TCP_H

#include "types.h"

/*!
 * \file
 * \brief Implement LAYER_TCP
 */

/*! TCP header
 * \private
 */
typedef struct tcp_hdr {
  u16 src;
  u16 dst;
  u32 seq;
  u32 ack_seq;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  u8	res1:4,
    doff:4;
  union {
    struct {
      u8 fin:1,
	syn:1,
	rst:1,
	psh:1,
	ack:1,
	urg:1,
	ece:1,
	cwr:1;
    };
    u8 flags;
  };
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	u8	doff:4,
	  res1:4;
  union {
    struct {
    u8 cwr:1,
      ece:1,
      urg:1,
      ack:1,
      psh:1,
      rst:1,
      syn:1,
      fin:1;
    };
    u8 flags;
  }
#else
#error	"Endianness undefined ?!"
#endif
  u16	window;
  u16	check;
  u16	urg_ptr;
}__attribute__((__packed__)) tcp_hdr;


int tcp_get_dport(layer_t *l, u16 *port);
int tcp_get_sport(layer_t *l, u16 *port);
int tcp_get_seq(layer_t *l, u32 *seq);
int tcp_get_ackSeq(layer_t *l, u32 *ack_seq);
int tcp_get_doff(layer_t *l, u8 *doff);
int tcp_get_fin(layer_t *l, u8 *fin);
int tcp_get_syn(layer_t *l, u8 *syn);
int tcp_get_rst(layer_t *l, u8 *rst);
int tcp_get_psh(layer_t *l, u8 *psh);
int tcp_get_ack(layer_t *l, u8 *ack);
int tcp_get_urg(layer_t *l, u8 *urg);
int tcp_get_ece(layer_t *l, u8 *ece);
int tcp_get_cwr(layer_t *l, u8 *cwr);
int tcp_get_flags(layer_t *l, u8 *flags);
int tcp_get_window(layer_t *l, u16 *window);
int tcp_get_check(layer_t *l, u16 *check);
int tcp_get_urgPtr(layer_t *l, u16 *urg_ptr);

#define TCP_FLAGS_FIN(f) (f & 1)
#define TCP_FLAGS_SYN(f) ((f >> 1) & 1)
#define TCP_FLAGS_RST(f) ((f >> 2) & 1)
#define TCP_FLAGS_PSH(f) ((f >> 3) & 1)
#define TCP_FLAGS_ACK(f) ((f >> 4) & 1)
#define TCP_FLAGS_URG(f) ((f >> 5) & 1)
#define TCP_FLAGS_ECE(f) ((f >> 6) & 1)
#define TCP_FLAGS_CWR(f) ((f >> 7) & 1)

#endif
