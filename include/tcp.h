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
  u8	res1:4,
    doff:4;
  union {
    struct {
      u8 fin:1,
	syn:1,
	rst:1,
	psh:1,
	ack:1,
	urg:1,
	ece:1,
	cwr:1;
    };
    u8 flags;
  };
#elif __BYTE_ORDER == __BIG_ENDIAN
	u8	doff:4,
	  res1:4;
  union {
    struct {
    u8 cwr:1,
      ece:1,
      urg:1,
      ack:1,
      psh:1,
      rst:1,
      syn:1,
      fin:1;
    };
    u8 flags;
  }
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
int tcp_get_seq(layer_t *l, u32 *seq);
int tcp_get_ackSeq(layer_t *l, u32 *ack_seq);
int tcp_get_doff(layer_t *l, u8 *doff);
int tcp_get_fin(layer_t *l, u8 *fin);
int tcp_get_syn(layer_t *l, u8 *syn);
int tcp_get_rst(layer_t *l, u8 *rst);
int tcp_get_psh(layer_t *l, u8 *psh);
int tcp_get_ack(layer_t *l, u8 *ack);
int tcp_get_urg(layer_t *l, u8 *urg);
int tcp_get_ece(layer_t *l, u8 *ece);
int tcp_get_cwr(layer_t *l, u8 *cwr);
int tcp_get_flags(layer_t *l, u8 *flags);
int tcp_get_window(layer_t *l, u16 *window);
int tcp_get_check(layer_t *l, u16 *check);
int tcp_get_urgPtr(layer_t *l, u16 *urg_ptr);

#define TCP_FLAGS_FIN(f) (f & 1)
#define TCP_FLAGS_SYN(f) ((f >> 1) & 1)
#define TCP_FLAGS_RST(f) ((f >> 2) & 1)
#define TCP_FLAGS_PSH(f) ((f >> 3) & 1)
#define TCP_FLAGS_ACK(f) ((f >> 4) & 1)
#define TCP_FLAGS_URG(f) ((f >> 5) & 1)
#define TCP_FLAGS_ECE(f) ((f >> 6) & 1)
#define TCP_FLAGS_CWR(f) ((f >> 7) & 1)

#endif
