### libpkt
-------------------

A Network Packet Dissector Library

-------------------

packet_t* packet_parse(u8* data, u32 size, int layer_type);

## ETHERNET

int ether_get_type(layer_t *l, u16 *type);
int ether_get_srcStr(layer_t *l, char* addr[ETH_ADDR_STR_LEN]);
int ether_get_dstStr(layer_t *l, char* addr[ETH_ADDR_STR_LEN]);

## IPV4

int ipv4_get_srcStr(layer_t *l, char* addr[IPV4_ADDR_STR_LEN]);
int ipv4_get_dstStr(layer_t *l, char* addr[IPV4_ADDR_STR_LEN]);

## TCP

int tcp_get_src(layer_t *l, u16 *port);
int tcp_get_dst(layer_t *l, u16 *port);

## UDP

int udp_get_src(layer_t *l, u16 *port);
int udp_get_dst(layer_t *l, u16 *port);

# TODO

- ARP
- IPV6
- RARP
- ICMP
- ...