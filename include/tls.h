#ifndef DEF_TLS_H
#define DEF_TLS_H

#include "types.h"

typedef struct tls_hdr {
  u8 content_type;
  u8 version_maj;
  u8 version_min;
  u16 length;
}__attribute__((__packed__)) tls_hdr;

#define TLS_MIN_HLEN 5UL
#define TLS_IS_VALID_LEN(len) (len >= TLS_MIN_HLEN)
#define TLS_LEN(h) (ntohs(h->length))

#define TLS_CTYPE_CHANGECIPHERSPECS 20
#define TLS_CTYPE_ALERT 21
#define TLS_CTYPE_HANDSHAKE 22
#define TLS_CTYPE_DATA 23

typedef struct tls_handshake {

}__attribute__((__packed__)) tls_handshake;

#define TLS_HANDSHAKE_HELLO_REQUEST 0
#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2
#define TLS_HANDSHAKE_CERTIFICATE 11
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE 12
#define TLS_HANDSHAKE_CERTIFICATE_REQUEST 13
#define TLS_HANDSHAKE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY 15
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE 16
#define TLS_HANDSHAKE_FINISHED 20

int tls_get_ctype(layer_t *l, u16 *ctype);
int tls_get_versionmaj(layer_t *l, u8 *ver);
int tls_get_versionmin(layer_t *l, u8 *ver);
int tls_get_ctypeStr(layer_t *l, const char **ctype);

#endif /* DEF_TLS_H */
