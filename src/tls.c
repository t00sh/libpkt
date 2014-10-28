#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "tls.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int tls_is_tls(layer_t *l) {
  (void)l;
  return 1;
}

int tls_parse(layer_t **layer, u8 *data, u32 size) {
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

  dissector_run(tls_dissectors,
		*layer,
		data + TLS_LEN(tls) + TLS_MIN_HLEN,
		size - TLS_LEN(tls) - TLS_MIN_HLEN);

  return 1;
}

int tls_get_ctype(layer_t *l, u16 *ctype) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;


  hdr = l->object;
  *ctype = hdr->content_type;

  return 1;
}

int tls_get_versionmaj(layer_t *l, u8 *ver) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;


  hdr = l->object;
  *ver = hdr->version_maj;

  return 1;
}

int tls_get_versionmin(layer_t *l, u8 *ver) {
  tls_hdr *hdr;

  if(l->type !=  LAYER_TLS)
    return 0;


  hdr = l->object;
  *ver = hdr->version_min;

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
