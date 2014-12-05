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


#ifdef ENABLE_TLS

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
#define TLS_MIN_HANDSHAKE_LEN (sizeof(tls_hdr) + sizeof(tls_handshake_hdr))
#define TLS_IS_VALID_LEN(len) (len >= TLS_MIN_HLEN)
#define TLS_LEN(h) (ntohs(h->length))

static void tls_state_add(packet_t *p, u32 len);
static int tls_state_update(packet_t *p, u32 *tls_length);

int tls_is_tls(layer_t *l) {
  (void)l;
  return 1;
}

static void tls_obj_free(void *obj) {
  tls_obj *tls = obj;

  if(tls) {
    free(tls->obj);
    free(tls);
  }
}

static tls_obj* tls_obj_new(void) {
  return calloc(1, sizeof(tls_obj));
}

static tls_continuous_data* tls_continuous_data_new(void) {
  return calloc(1, sizeof(tls_continuous_data));
}

static tls_handshake* tls_handshake_new(void) {
  return calloc(1, sizeof(tls_handshake));
}

static int tls_parse_handshake(tls_obj *tls, const u8 *data, u32 size) {
  tls_handshake *handshake;

  if(size < TLS_MIN_HANDSHAKE_LEN)
    return 0;

  if((handshake = tls_handshake_new()) == NULL)
    return 0;

  handshake->hdr = (tls_hdr*)data;
  handshake->handshake_hdr = (tls_handshake_hdr*)(data + sizeof(tls_hdr));

  tls->type = TLS_CTYPE_HANDSHAKE;
  tls->obj = handshake;

  return 1;
}

static int tls_parse_header(tls_obj *tls, const u8 *data, u32 size) {
  tls_hdr *hdr;

  if(size < TLS_MIN_HLEN)
    return 0;

  hdr = (tls_hdr*)data;

  if(hdr->content_type == TLS_CTYPE_HANDSHAKE) {
    return tls_parse_handshake(tls, data, size);
  }
  return 1;
}

static int tls_parse_continuous_data(tls_obj *tls, const u8 *data, u32 size) {
  tls_continuous_data *tls_data;

  if((tls_data = tls_continuous_data_new()) == NULL)
    return 0;

  tls->type = TLS_CTYPE_CONTINUOUS_DATA;
  tls_data->len = size;
  tls_data->bytes = data;
  tls->obj = tls_data;

  return 1;
}

int tls_parse(packet_t *p, layer_t **layer, const u8 *data, u32 size) {
  tls_obj *tls = NULL;
  tls_hdr *hdr = NULL;
  u32 tls_size;

  if((*layer = layer_new()) == NULL)
    goto err;

  if((tls = tls_obj_new()) == NULL)
    goto err;

  (*layer)->type = LAYER_TLS;
  (*layer)->object = tls;
  (*layer)->destructor = tls_obj_free;

  tls_size = size;

  if(tls_state_update(p, &tls_size)) {
    if(!tls_parse_continuous_data(tls, data, tls_size))
      goto err;
    data += tls_size;
    size -= tls_size;
  } else {

    if(!tls_parse_header(tls, data, size))
      goto err;

    if(!tls_get_hdr(*layer, &hdr))
      goto err;

    if(TLS_LEN(hdr) > size - TLS_MIN_HLEN) {
      tls_state_add(p, TLS_LEN(hdr) - (size - TLS_MIN_HLEN));
      size = 0;
    } else {
      data += TLS_LEN(hdr) + TLS_MIN_HLEN;
      size -= TLS_LEN(hdr) + TLS_MIN_HLEN;
    }
  }

  dissector_run(p,
		tls_dissectors,
		*layer,
		data,
		size);


  return 1;

 err:
  if(layer)
    layer_free(layer);
  if(tls)
    tls_obj_free(tls);

  return 0;
}

int tls_get_type(layer_t *l, int *type) {
  tls_obj *tls;

  if(l->type !=  LAYER_TLS)
    return 0;

  tls = l->object;

  *type = tls->type;

  return 1;
}

int tls_get_hdr(layer_t *l, tls_hdr **hdr) {
  tls_obj *tls;

  if(l->type != LAYER_TLS)
    return 0;

  tls = l->object;

  if(tls->type == TLS_CTYPE_HANDSHAKE)
    *hdr = ((tls_handshake*)(tls->obj))->hdr;
  else if(tls->type == TLS_CTYPE_DATA)
    *hdr = ((tls_data*)(tls->obj))->hdr;
  else
    return 0;

  return 1;
}

int tls_get_ctype(layer_t *l, u8 *ctype) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;

  if(!tls_get_hdr(l, &hdr))
    return 0;

  *ctype = hdr->content_type;

  return 1;
}

int tls_get_length(layer_t *l, u16 *length) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;

  if(!tls_get_hdr(l, &hdr))
    return 0;

  *length = ntohs(hdr->length);

  return 1;
}

int tls_get_versionmaj(layer_t *l, u8 *ver) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;

  if(!tls_get_hdr(l, &hdr))
    return 0;

  *ver = hdr->version.major;

  return 1;
}

int tls_get_versionmin(layer_t *l, u8 *ver) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;

  if(!tls_get_hdr(l, &hdr))
    return 0;

  *ver = hdr->version.minor;

  return 1;
}

int tls_get_ctypeStr(layer_t *l, const char **ctype) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;

  if(!tls_get_hdr(l, &hdr))
    return 0;

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
/* TLS states                   */
/********************************/

/* A TLS state is reprensented with a couple of address (ipv4 or ipv6) and with
   a couple of port.
   The len_left field specify how much data have to be received.

   TODO: check unreceived data, packet lost, retransmited packets...
*/
typedef struct tls_state {
  int layer_type;

  union {
    ipv6addr_t saddr6;
    ipv4addr_t saddr4;
  };

  union {
    ipv6addr_t daddr6;
    ipv4addr_t daddr4;
  };

  u16 sport;
  u16 dport;
  u32 len_left;

  struct tls_state *next;
}tls_state_t;

tls_state_t *tls_states = NULL;


static void tls_state_insert(tls_state_t *s) {
  s->next = tls_states;
  tls_states = s;
}

static tls_state_t* tls_state_new(void) {
  return calloc(1, sizeof(tls_state_t));
}

static void tls_state_free(tls_state_t *state) {
  free(state);
}

static void tls_state_remove(tls_state_t *state) {
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

/* Find a TLS state */
static tls_state_t* tls_state_find(packet_t *p) {
  tls_state_t *s;
  layer_t *ipv4;
  layer_t *ipv6;
  layer_t *tcp;
  ipv4addr_t saddr4, daddr4;
  ipv6addr_t saddr6, daddr6;
  u16 sport, dport;

  /* Get the IPv4/IPv6 address and TCP ports */
  ipv4 = packet_get_layer(p, LAYER_IPV4);
  ipv6 = packet_get_layer(p, LAYER_IPV6);
  tcp = packet_get_layer(p, LAYER_TCP);

  if((!ipv4 && !ipv6) || !tcp)
    return NULL;

  tcp_get_dport(tcp, &dport);
  tcp_get_sport(tcp, &sport);

  if(ipv4) {
    ipv4_get_saddr(ipv4, &saddr4);
    ipv4_get_daddr(ipv4, &daddr4);
  } else {
    ipv6_get_saddr(ipv6, &saddr6);
    ipv6_get_daddr(ipv6, &daddr6);
  }

  /* Foreach state, check if it match the current packet */
  for(s = tls_states; s; s = s->next) {

    if((s->dport == dport && s->sport == sport) ||
       (s->dport == sport && s->sport == dport)) {

      if(s->layer_type == LAYER_IPV4 && ipv4) {
	if((!memcmp(&s->daddr4, &daddr4, sizeof(ipv4addr_t)) && !memcmp(&s->saddr4, &saddr4, sizeof(ipv4addr_t))) ||
	   (!memcmp(&s->daddr4, &saddr4, sizeof(ipv4addr_t)) && !memcmp(&s->saddr4, &daddr4, sizeof(ipv4addr_t)))) {
	  return s;
	}

      }
      if(s->layer_type == LAYER_IPV6 && ipv6) {
	if((!memcmp(&s->daddr6, &daddr6, sizeof(ipv6addr_t)) && !memcmp(&s->saddr6, &saddr4, sizeof(ipv6addr_t))) ||
	   (!memcmp(&s->daddr6, &saddr6, sizeof(ipv6addr_t)) && !memcmp(&s->saddr6, &daddr4, sizeof(ipv6addr_t)))) {
	  return s;
	}
      }
    }
  }
  return NULL;
}

/*
   Return 1 if it's continuous data, 0 if it's a new TLS packet
   Update the state;
 */
static int tls_state_update(packet_t *p, u32 *tls_length) {
  tls_state_t *state;

  if((state = tls_state_find(p)) != NULL) {
    if(state->len_left <= *tls_length) {
      tls_state_remove(state);
      *tls_length = state->len_left;
    } else {
      state->len_left -= *tls_length;
    }
    return 1;
  }

  return 0;
}

/* Add a new state */
static void tls_state_add(packet_t *p, u32 len) {
  layer_t *ipv4;
  layer_t *ipv6;
  layer_t *tcp;
  tls_state_t *state;

  ipv4 = packet_get_layer(p, LAYER_IPV4);
  ipv6 = packet_get_layer(p, LAYER_IPV6);
  tcp = packet_get_layer(p, LAYER_TCP);

  if((!ipv4 && !ipv6) || !tcp)
    return;

  if((state = tls_state_new()) == NULL)
    return;

  tcp_get_dport(tcp, &state->dport);
  tcp_get_sport(tcp, &state->sport);

  if(ipv4) {
    ipv4_get_saddr(ipv4, &state->saddr4);
    ipv4_get_daddr(ipv4, &state->daddr4);
    state->layer_type = LAYER_IPV4;
  } else {
    ipv6_get_saddr(ipv6, &state->saddr6);
    ipv6_get_daddr(ipv6, &state->daddr6);
    state->layer_type = LAYER_IPV6;
  }

  state->len_left = len;
  tls_state_insert(state);
}

#endif /* ENABLE_TLS */
