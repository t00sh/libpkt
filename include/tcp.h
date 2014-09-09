#ifndef DEF_TCP_H
#define DEF_TCP_H

#include "types.h"
#include <sys/types.h>

typedef struct tcp_hdr {
	u16	src;
	u16	dst;
	u32	seq;
	u32	ack_seq;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	u16	window;
	u16	check;
	u16	urg_ptr;
}__attribute__((__packed__)) tcp_hdr;


#define TCP_MIN_HLEN 20UL
#define TCP_IS_VALID_LEN(len) (len >= TCP_MIN_HLEN)
#define TCP_HLEN(h) ((u16)(((tcp_hdr*)(h))->doff << 2))


int tcp_get_dport(layer_t *l, u16 *port);
int tcp_get_sport(layer_t *l, u16 *port);

#endif
