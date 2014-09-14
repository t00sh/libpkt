### libpkt
-------------------

A Network Packet Dissector Library

-------------------
[Parser](#parser-)

[Ethernet](#ethernet-)

[Ipv4](#ipv4-)

[Tcp](#tcp-)

[Udp](#udp-)


## Parser <a id="parser"></a> 
packet_t* packet_parse(u8* data, u32 size, int layer_type);

## Ethernet <a id="ethernet"></a>

int ether_get_type(layer_t *l, u16 *type);
int ether_get_srcStr(layer_t *l, char* addr[ETH_ADDR_STR_LEN]);
int ether_get_dstStr(layer_t *l, char* addr[ETH_ADDR_STR_LEN]);

## Ivp4 <a id="ipv4"></a>

int ipv4_get_srcStr(layer_t *l, char* addr[IPV4_ADDR_STR_LEN]);
int ipv4_get_dstStr(layer_t *l, char* addr[IPV4_ADDR_STR_LEN]);

## Tcp <a id="tcp"></a>

int tcp_get_src(layer_t *l, u16 *port);
int tcp_get_dst(layer_t *l, u16 *port);

## Udp <a id="udp"></a>

int udp_get_src(layer_t *l, u16 *port);
int udp_get_dst(layer_t *l, u16 *port);
