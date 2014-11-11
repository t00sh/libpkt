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
#include "tls.h"
#include "parsers.h"
#include "utils.h"

#include "ipv4.h"
#include "ipv6.h"
#include "tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TLS_MIN_HLEN 5UL
#define TLS_IS_VALID_LEN(len) (len >= TLS_MIN_HLEN)
#define TLS_LEN(h) (ntohs(h->length))

typedef struct tls_state {
  packet_t *packet;
  u32 len_left;
  struct tls_state *next;
}tls_state_t;

tls_state_t *tls_states = NULL;

int tls_is_tls(layer_t *l) {
  (void)l;
  return 1;
}

int tls_parse(packet_t *p, layer_t **layer, u8 *data, u32 size) {
  tls_hdr *tls;

  if(!TLS_IS_VALID_LEN(size))
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  tls = (tls_hdr*)data;

  if(TLS_LEN(tls) > size - TLS_MIN_HLEN)
    return 0;

  (*layer)->type = LAYER_TLS;
  (*layer)->object = tls;

  dissector_run(p,
		tls_dissectors,
		*layer,
		data + TLS_LEN(tls) + TLS_MIN_HLEN,
		size - TLS_LEN(tls) - TLS_MIN_HLEN);

  return 1;
}

int tls_get_ctype(layer_t *l, u8 *ctype) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;


  hdr = l->object;
  *ctype = hdr->content_type;

  return 1;
}

int tls_get_length(layer_t *l, u16 *length) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;

  hdr = l->object;
  *length = ntohs(hdr->content_type);

  return 1;
}

int tls_get_versionmaj(layer_t *l, u8 *ver) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;


  hdr = l->object;
  *ver = hdr->version.major;

  return 1;
}

int tls_get_versionmin(layer_t *l, u8 *ver) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;


  hdr = l->object;
  *ver = hdr->version.minor;

  return 1;
}

int tls_get_ctypeStr(layer_t *l, const char **ctype) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;

  hdr = l->object;

  switch(hdr->content_type) {

  case TLS_CTYPE_CHANGECIPHERSPECS:
    *ctype = "Change Cipher Specs";
    break;

  case TLS_CTYPE_ALERT:
    *ctype = "Alert";
    break;

  case TLS_CTYPE_HANDSHAKE:
    *ctype = "Handshake";
    break;

  case TLS_CTYPE_DATA:
    *ctype = "Application data";
    break;

  default:
    *ctype = "Unknown content type";
    break;
  }

  return 1;
}

/********************************/
/* TODO: TLS states */

#if 0
void tls_state_add(tls_state_t *s) {
  s->next = tls_states;
  tls_states = s;
}

tls_state_t* tls_state_new(void) {
  return calloc(1, sizeof(tls_state_t));
}

void tls_state_free(tls_state_t *state) {
  free(state);
}

void tls_state_remove(tls_state_t *state) {
  tls_state_t *s;

  assert(state != NULL);

  if(state == tls_states) {
    tls_states = state->next;
  } else {
    for(s = tls_states; s; s = s->next) {
      if(s->next == state) {
	s->next = state->next;
	break;
      }
    }
  }
  tls_state_free(state);
}

tls_state_t* tls_state_find(packet_t *p) {
  tls_state_t *s;
  layer_t *ipv4_in, *ipv4;
  layer_t *ipv6_in, *ipv6;
  layer_t *tcp_in, *tcp;
  ipv4addr_t saddr4_in, saddr4, daddr4_in, daddr4;
  ipv6addr_t saddr6_in, saddr6, daddr6_in, daddr6;
  u16 sport_in, sport, dport_in, dport;

  ipv4_in = packet_get_layer(p, LAYER_IPV4);
  if(!ipv4_in)
    ipv6_in = packet_get_layer(p, LAYER_IPV6);
  tcp_in = packet_get_layer(p, LAYER_TCP);

  for(s = tls_states; s; s = s->next) {
    tcp = packet_get_layer(p, LAYER_TCP);

    tcp_get_dport(tcp_in, &dport_in);
    tcp_get_dport(tcp, &dport);
    tcp_get_sport(tcp_in, &sport_in);
    tcp_get_sport(tcp, &sport);

    if((dport != dport_in || sport != sport_in) &&
       (dport != sport_in || sport != dport_in))
      return NULL;


    if(ipv4_in) {
      if((ipv4 = packet_get_layer(s->packet, LAYER_IPV4))) {
	ipv4_get_daddr(ipv4_in, &daddr4_in);
	ipv4_get_daddr(ipv4, &daddr4);
	ipv4_get_saddr(ipv4_in, &saddr4_in);
	ipv4_get_saddr(ipv4, &saddr4);

	if((!memcmp(&daddr4, &daddr4_in, sizeof(ipv4addr_t)) && !memcmp(&saddr4, &saddr4_in, sizeof(ipv4addr_t))) ||
	   (!memcmp(&daddr4, &saddr4_in, sizeof(ipv4addr_t)) && !memcmp(&saddr4, &daddr4_in, sizeof(ipv4addr_t)))) {
	  return s;
	}
      }
    } else if(ipv6_in) {
      if((ipv6 = packet_get_layer(s->packet, LAYER_IPV6))) {
	ipv6_get_daddr(ipv6_in, &daddr6_in);
	ipv6_get_daddr(ipv6, &daddr6);
	ipv6_get_saddr(ipv6_in, &saddr6_in);
	ipv6_get_saddr(ipv6, &saddr6);

	if((!memcmp(&daddr6, &daddr6_in, sizeof(ipv6addr_t)) && !memcmp(&saddr6, &saddr4_in, sizeof(ipv6addr_t))) ||
	   (!memcmp(&daddr6, &saddr6_in, sizeof(ipv6addr_t)) && !memcmp(&saddr6, &daddr4_in, sizeof(ipv6addr_t)))) {
	  return s;
	}
      }
    }
  }
  return NULL;
}

/* Return 1 if the state of the packet must be conserved, 0 overwhise*/
int tls_state_update(packet_t *p, u8 *data, u32 tls_length) {
  tls_state_t *state;

  if((state = tls_state_find(p)) != NULL) {
    if(state->len_left < tls_length) {
      tls_state_remove(state);
    } else {

    }
  }
  return 0;
}
#endif
