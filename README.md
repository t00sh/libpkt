### libpkt
-------------------

A Network Packet Dissector Library

-------------------
[Packet](#packet-)

[Ethernet](#ethernet-)

[Ipv4](#ipv4-)

[Tcp](#tcp-)

[Udp](#udp-)


## Packet <a id="packet"></a>
### Functions

_ Parse raw data (receved with pcap for example) and return the parsed
packet. (must be free by packet_free). _

- **data**       : bytes of the packet

- **size**       : size of the packet (in bytes)

- **layer_type** : the layer where the packet was captured (example: LAYER_ETHER)

- **@RETURN**    : the parsed packet (must be free with packet_free) or NULL
	       	 if an error occured

```c
packet_t* packet_parse(u8* data, u32 size, int layer_type);
```

_ Get the next layer of type layer _

- **p**       : The packet

- **layer**   : The layer type

- **@RETURN** : Return the first layer if type **layer** or NULL
	      if layer wasn't find

```c
layer_t* packet_get_layer(packet_t *p, int layer);
```

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
