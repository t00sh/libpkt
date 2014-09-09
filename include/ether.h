#ifndef DEF_ETHER_H
#define DEF_ETHER_H

#define ETHER_ALEN	6		/* Octets in one ethernet addr	 */
#define ETHER_HLEN	14		/* Total octets in header.	 */

#define ETHER_ADDR_STR_LEN 18

#include "types.h"

typedef struct etheraddr {
  u8 bytes[ETHER_ALEN];
}__attribute__((__packed__)) etheraddr_t;

/* 10Mb/s ethernet header */
typedef struct ether_hdr {
  etheraddr_t  dst;	/* destination eth addr	*/
  etheraddr_t  src;	/* source ether addr	*/
  u16 type;	        /* packet type ID field	*/
} __attribute__ ((__packed__)) ether_hdr;


/* Ethernet protocol ID's */
#define	ETHERTYPE_PUP		0x0200          /* Xerox PUP */
#define ETHERTYPE_SPRITE	0x0500		/* Sprite */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
#define ETHERTYPE_AT		0x809B		/* AppleTalk protocol */
#define ETHERTYPE_AARP		0x80F3		/* AppleTalk ARP */
#define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX		0x8137		/* IPX */
#define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK	0x9000		/* used to test interfaces */


/* make sure ethenet length is valid */
#define	ETHER_IS_VALID_LEN(foo)	\
  ((foo) >= ETHER_HLEN)

int ether_get_type(layer_t *l, u16 *type);
int ether_get_srcStr(layer_t *l, char addr[ETHER_ADDR_STR_LEN]);
int ether_get_dstStr(layer_t *l, char addr[ETHER_ADDR_STR_LEN]);

#endif /* DEF_ETHER_H */
