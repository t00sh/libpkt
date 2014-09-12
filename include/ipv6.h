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



#define IPV6_MIN_HLEN 38UL
#define IPV6_IS_VALID_LEN(len) (len >= IPV6_MIN_HLEN)
#define IPV6_HLEN (IPV6_MIN_HLEN)

int ipv6_get_nexthdr(layer_t *l, u8 *nexthdr);
int ipv6_get_saddrStr(layer_t *l, char str[IPV6_ADDR_STR_LEN]);
int ipv6_get_daddrStr(layer_t *l, char str[IPV6_ADDR_STR_LEN]);

#endif /* DEF_IPV6_H */
