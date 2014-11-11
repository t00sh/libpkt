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


#ifndef DEF_TLS_H
#define DEF_TLS_H


#include "types.h"

/*!
 * \file
 * \brief Implement LAYER_TLS
 */

/*! tls version
 * \private
 */
typedef struct tls_version {
  u8 major;
  u8 minor;
}__attribute__((__packed__)) tls_version;

/*! tls random
 * \private
 */
typedef struct tls_random {
  u32 gmt_unix_time;
  u8 rand_bytes[28];
}__attribute__((__packed__)) tls_random;

/*! SSL/TLS header
 * \private
 */
typedef struct tls_hdr {
  u8 content_type;
  tls_version version;
  u16 length;
}__attribute__((__packed__)) tls_hdr;


typedef enum tls_ctype {
  TLS_CTYPE_CHANGECIPHERSPECS=20,
  TLS_CTYPE_ALERT=21,
  TLS_CTYPE_HANDSHAKE=22,
  TLS_CTYPE_DATA=23
}tls_ctype;

/*! tls handshake header
 * \private
 */
typedef struct tls_handshake {
  u8 msg_type;
  u8 length[3];

  union {
    struct {
      tls_version cli_version;
      tls_random random;
      u8 session_id[32];

    }client_hello;
  };
}__attribute__((__packed__)) tls_handshake;

typedef enum tls_handshake_type {
  TLS_HANDSHAKE_HELLO_REQUEST=0,
  TLS_HANDSHAKE_CLIENT_HELLO=1,
  TLS_HANDSHAKE_SERVER_HELLO=2,
  TLS_HANDSHAKE_CERTIFICATE=11,
  TLS_HANDSHAKE_SERVER_KEY_EXCHANGE=12,
  TLS_HANDSHAKE_CERTIFICATE_REQUEST=13,
  TLS_HANDSHAKE_SERVER_HELLO_DONE=14,
  TLS_HANDSHAKE_CERTIFICATE_VERIFY=15,
  TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE=16,
  TLS_HANDSHAKE_FINISHED=20
}tls_handshake_type;

int tls_get_ctype(layer_t *l, u8 *ctype);
int tls_get_versionmaj(layer_t *l, u8 *ver);
int tls_get_versionmin(layer_t *l, u8 *ver);
int tls_get_ctypeStr(layer_t *l, const char **ctype);

#endif /* DEF_TLS_H */
