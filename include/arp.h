#ifndef DEF_ARP_H
#define DEF_ARP_H

typedef struct arp_hdr {
	uint16_t	hrd;	/* format of hardware address */
	uint16_t	pro;	/* format of protocol address */
	uint8_t		hln;	/* length of hardware address (ETH_ADDR_LEN) */
	uint8_t		pln;	/* length of protocol address (IP_ADDR_LEN) */
	uint16_t	op;	/* operation */
}__attribute__((__packed__))arp_hdr;

/*
 * Hardware address format
 */
#define ARP_HRD_ETH 	0x0001	/* ethernet hardware */
#define ARP_HRD_IEEE802	0x0006	/* IEEE 802 hardware */

/*
 * Protocol address format
 */
#define ARP_PRO_IP	0x0800	/* IP protocol */

/*
 * ARP operation
 */
#define	ARP_OP_REQUEST		1	/* request to resolve ha given pa */
#define	ARP_OP_REPLY		2	/* response giving hardware address */
#define	ARP_OP_REVREQUEST	3	/* request to resolve pa given ha */
#define	ARP_OP_REVREPLY		4	/* response giving protocol address */

#define ARP_MIN_HLEN 8UL
#define ARP_HLEN(h) ((u32)(ARP_MIN_HLEN + 2*h->hln + 2*h->pln))
#define ARP_IS_VALID_LEN(len) (len >= ARP_MIN_HLEN)

int arp_get_op(layer_t *l, u16 *op);

#endif /* DEF_ARP_H */
