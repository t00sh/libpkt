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


#include "dissector.h"
#include "packet.h"
#include "types.h"

#include <stdlib.h>


int ether_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);
int ipv4_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);
int tcp_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);
int udp_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);
int icmp_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);
int arp_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);
int dns_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);
int ipv6_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);
int raw_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);
int ipv6_parse_hbh_ext(packet_t *p, layer_t **layer, u8 *data, u32 size);
int ipv6_parse_frag_ext(packet_t *p, layer_t **layer, u8 *data, u32 size);
int ipv6_parse_route_ext(packet_t *p, layer_t **layer, u8 *data, u32 size);
int tls_parse(packet_t *p, layer_t **layer, u8 *data, u32 size);

int (*layer_parsers[])(packet_t *p, layer_t**, u8*, u32) = {
  ether_parse,           /* LAYER_ETHER           */
  ipv4_parse,            /* LAYER_IPV4            */
  tcp_parse,             /* LAYER_TCP             */
  udp_parse,             /* LAYER_UDP             */
  icmp_parse,            /* LAYER_ICMP            */
  arp_parse,             /* LAYER_ARP             */
  dns_parse,             /* LAYER_DNS             */
  ipv6_parse,            /* LAYER_IPV6            */
  raw_parse,             /* LAYER_RAW             */
  ipv6_parse_hbh_ext,    /* LAYER_IPV6_HBH_EXT    */
  ipv6_parse_frag_ext,   /* LAYER_IPV6_FRAG_EXT   */
  ipv6_parse_route_ext,  /* LAYER_IPV6_ROUTE_EXT  */
  tls_parse,             /* LAYER_TLS             */
  NULL                   /* LAYER_MAX             */
};


/********************************************/
/* ************ LAYER_ETHER *************** */
/********************************************/

int ether_is_ipv4(layer_t*);
int ether_is_ipv6(layer_t*);
int ether_is_arp(layer_t*);

dissector_t ether_dissectors[] = {
  { ether_is_ipv4, ipv4_parse },
  { ether_is_ipv6, ipv6_parse },
  { ether_is_arp, arp_parse },
  { NULL,          NULL       }
};


/*************************************/
/* ********** LAYER_IPV4 *********** */
/*************************************/

int ipv4_is_tcp(layer_t*);
int ipv4_is_udp(layer_t*);
int ipv4_is_icmp(layer_t*);

dissector_t ipv4_dissectors[] = {
  { ipv4_is_tcp, tcp_parse },
  { ipv4_is_udp, udp_parse },
  { ipv4_is_icmp, icmp_parse },
  { NULL, NULL }
};

/*************************************/
/* ********** LAYER_IPV6 *********** */
/*************************************/

int ipv6_is_tcp(layer_t*);
int ipv6_is_udp(layer_t*);
int ipv6_is_hbh_ext(layer_t*);
int ipv6_is_frag_ext(layer_t*);
int ipv6_is_route_ext(layer_t*);

dissector_t ipv6_dissectors[] = {
  { ipv6_is_tcp, tcp_parse },
  { ipv6_is_udp, udp_parse },
  { ipv6_is_hbh_ext, ipv6_parse_hbh_ext},
  { ipv6_is_frag_ext, ipv6_parse_frag_ext},
  { ipv6_is_route_ext, ipv6_parse_route_ext},
  { NULL, NULL }
};

/*************************************/
/* ********** LAYER_UDP  *********** */
/*************************************/

int udp_is_dns(layer_t*);

dissector_t udp_dissectors[] = {
  { udp_is_dns, dns_parse },
  { NULL, NULL }
};

/*************************************/
/* ********** LAYER_TCP  *********** */
/*************************************/

int tcp_is_tls(layer_t *l);

dissector_t tcp_dissectors[] = {
  { tcp_is_tls, tls_parse },
  { NULL, NULL }
};

/*************************************/
/* ********** LAYER_ICMP  *********** */
/*************************************/

dissector_t icmp_dissectors[] = {
  { NULL, NULL }
};

/*************************************/
/* ********** LAYER_TLS  *********** */
/*************************************/

int tls_is_tls(layer_t *l);

dissector_t tls_dissectors[] = {
  { tls_is_tls, tls_parse },
  { NULL, NULL }
};
