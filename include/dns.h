#ifndef DEF_DNS_H
#define DEF_DNS_H

#include "types.h"

typedef struct dns_hdr {

  u16 id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  u16 rcode:4;
  u16 cd:1;
  u16 ad:1;
  u16 z:1;
  u16 ra:1;
  u16 rd:1;
  u16 tc:1;
  u16 aa:1;
  u16 opcode:4;
  u16 qr:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
  u16 qr:1;
  u16 opcode:4;
  u16 aa:1;
  u16 tc:1;
  u16 rd:1;
  u16 ra:1;
  u16 z:1;
  u16 ad:1;
  u16 cd:1;
  u16 rcode:4;
#else
# error	"Please fix <bits/endian.h>"
#endif

  u16 tot_query;
  u16 tot_answer;
  u16 tot_auth_rr;
  u16 tot_add_rr;

}__attribute__((__packed__)) dns_hdr;


#define DNS_MIN_HLEN 12UL
#define DNS_IS_VALID_LEN(len) (len >= DNS_MIN_HLEN)

int dns_get_id(layer_t *l, u16 *id);

#endif /* DEF_DNS_H */
