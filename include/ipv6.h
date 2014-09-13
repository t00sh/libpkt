#ifndef DEF_IPV6_H
#define DEF_IPV6_H

#include "packet.h"
#include "types.h"
#include "ipv4.h"
#include <sys/types.h>

#define IPV6_ALEN 16   /* Ipv6 address len */
#define IPV6_ADDR_STR_LEN 48 /* Ipv6 string len */

typedef struct ipv6addr {
  u8 bytes[IPV6_ALEN];
}__attribute__((__packed__)) ipv6addr_t;

typedef struct ipv6_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u8			priority:4,
				version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u8			version:4,
				priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	u8			flow_lbl[3];

	u16			payload_len;
	u8			nexthdr;
	u8			hop_limit;

	ipv6addr_t      	saddr;
	ipv6addr_t      	daddr;

}__attribute__((__packed__))ipv6_hdr;


/* Extension headers */

/* Hop by hop and destination extension header */
typedef struct ipv6_hbh_hdr {
  u8 nexthdr;
  u8 hdr_len;
  u16 opts;
  u32 opts2;

  /* Optional options and padding */

}__attribute__((__packed__)) ipv6_hbh_hdr;

/* routing extension header */
typedef struct ipv6_route_hdr {

  u8 nexthdr;
  u8 hdr_len;
  u8 type;
  u8 segments;
  u16 opts;

  /* Optional options and padding */

}__attribute__((__packed__)) ipv6_route_hdr;

/* Fragment extension header */
typedef struct ipv6_frag_hdr {
  u8 nexthdr;
  u8 reserved;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  u16 m:1,
    res:2,
    frag:13;
#elif __BYTE_ORDER == __BIG_ENDIAN
  u16 frag:13,
    res:2,
    m:1;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
  u32 ident;
}__attribute__((__packed__)) ipv6_frag_hdr;


#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif
#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

#define IPV6_HBH_HLEN(h) (8UL + (h->hdr_len << 3))
#define IPV6_FRAG_HLEN 8UL
#define IPV6_ROUTE_HLEN(h) (8UL + (h->hdr_len << 3))

#define IPV6_MIN_HLEN 40UL
#define IPV6_IS_VALID_LEN(len) (len >= IPV6_MIN_HLEN)
#define IPV6_HLEN (IPV6_MIN_HLEN)

int ipv6_get_nexthdr(layer_t *l, u8 *nexthdr);
int ipv6_get_saddrStr(layer_t *l, char str[IPV6_ADDR_STR_LEN]);
int ipv6_get_daddrStr(layer_t *l, char str[IPV6_ADDR_STR_LEN]);

#endif /* DEF_IPV6_H */
