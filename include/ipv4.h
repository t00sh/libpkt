#ifndef DEF_IPV4_H
#define DEF_IPV4_H

#include "packet.h"
#include "types.h"

#include <sys/types.h>
#include <arpa/inet.h>

typedef struct ipv4_hdr {

#if __BYTE_ORDER == __LITTLE_ENDIAN
       u8 ihl:4;
       u8 version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
       u8 version:4;
       u8 ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
	u8	tos;
	u16	tot_len;
	u16	id;
	u16	frag_off;
	u8	ttl;
	u8	protocol;
	u16	check;
	u32	saddr;
	u32	daddr;
        u8*     options;
}__attribute__((packed)) ipv4_hdr;

#define IPV4_MIN_HLEN 20UL
#define IPV4_IS_VALID_LEN(len) (len >= IPV4_MIN_HLEN)
#define IPV4_HLEN(hdr) ((u16)(((ipv4_hdr*)(hdr))->ihl << 2))


void ipv4_parse(packet_t **pkt, u8 *data, u32 size);

#endif /* DEF_IPV4_H */
