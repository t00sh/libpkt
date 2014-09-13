#ifndef DEF_IPV4_H
#define DEF_IPV4_H

#include "packet.h"
#include "types.h"

#include <sys/types.h>

#define IPV4_ALEN 4   /* IPv4 address len */
#define IPV4_ADDR_STR_LEN 16 /* IPv4 string len */

typedef struct ipv4addr {
  u8 bytes[IPV4_ALEN];
}__attribute__((__packed__)) ipv4addr_t;

typedef struct ipv4_hdr {

#if __BYTE_ORDER == __LITTLE_ENDIAN
  u8         ihl:4;
  u8         version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  u8         version:4;
  u8         ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
  u8	      tos;
  u16	      tot_len;
  u16	      id;
  u16	      frag_off;
  u8	      ttl;
  u8          protocol;
  u16         check;
  ipv4addr_t  saddr;
  ipv4addr_t  daddr;

  /* Options */
}__attribute__((__packed__)) ipv4_hdr;


#define IPV4_MIN_HLEN 20UL
#define IPV4_IS_VALID_LEN(len) (len >= IPV4_MIN_HLEN)
#define IPV4_HLEN(h) ((u16)(((ipv4_hdr*)(h))->ihl << 2))
#define IPV4_HAVE_OPTIONS(h) (IPV4_HLEN(h) > IPV4_MIN_HLEN)


#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

int ipv4_get_protocol(layer_t *l, u8 *proto);
int ipv4_get_saddrStr(layer_t *l, char str[IPV4_ADDR_STR_LEN]);
int ipv4_get_daddrStr(layer_t *l, char str[IPV4_ADDR_STR_LEN]);
int ipv4_get_ihl(layer_t *l, u8* ihl);
int ipv4_get_version(layer_t *l, u8* version);
int ipv4_get_tos(layer_t *l, u8* tos);
int ipv4_get_totLen(layer_t *l, u16* tot_len);
int ipv4_get_id(layer_t *l, u16* id);
int ipv4_get_fragOff(layer_t *l, u16* frag_off);
int ipv4_get_ttl(layer_t *l, u8* ttl);
int ipv4_get_check(layer_t *l, u16* check);
int ipv4_get_options(layer_t *l, u8** options, u32 *options_len);

#endif /* DEF_IPV4_H */
