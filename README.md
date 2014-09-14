### libpkt
-------------------

A Network Packet Dissector Library

-------------------
[Packet](#packet-)

[Ethernet](#ethernet-)

[Ipv4](#ipv4-)

[Tcp](#tcp-)

[Udp](#udp-)

[Examples](#examples-)


## Packet <a id="packet"></a>
#### Functions

------------------------------------

Parse raw data (receved with pcap for example) and return the parsed
packet. (must be free by packet_free).

- **data**       : bytes of the packet

- **size**       : size of the packet (in bytes)

- **layer_type** : the layer where the packet was captured (example: LAYER_ETHER)

- **@RETURN**    : the parsed packet (must be free with packet_free) or NULL
	       	 if an error occured

```c
packet_t* packet_parse(u8* data, u32 size, int layer_type);
```

----------------------------------

Get the next layer of type layer (constantes LAYER_*)

- **p**       : The packet

- **layer**   : The layer type

- **@RETURN** : Return the first layer of type **layer** or NULL
	      if layer wasn't find

```c
layer_t* packet_get_layer(packet_t *p, int layer);
```

----------------------------------

Execute a fonction on each layer of a given packet

- **p**          : The packet

- **callback**   : The function to call on each layer

- **user**       : A user defined variable (or NULL if no variable have to be passed)

```c
void packet_foreach_layer(packet_t *p, void (*callback)(layer_t*, void* user), void* user);
```

----------------------------------

#### Constantes

- **LAYER_ETHER**              Ethernet layer

- **LAYER_IPV4**               IPv4 layer

- **LAYER_TCP**                TCP layer

- **LAYER_UDP**                UDP layer

- **LAYER_ICMP**               ICMP layer

- **LAYER_ARP**                ARP layer

- **LAYER_DNS**                DNS layer

- **LAYER_IPV6**               IPV6 layer

- **LAYER_RAW**                RAW layer (data)

- **LAYER_IPV6_HBH_EXT**       IPv6 Hop by hop extension

- **LAYER_IPV6_FRAG_EXT**      IPv6 fragment extension

- **LAYER_IPV6_ROUTE_EXT**     IPv6 routing extension

----------------------------

## Ethernet <a id="ethernet"></a>

#### Functions

----------------------------------------

Get the ethertype of a LAYER_ETHER in the host byte order

- **l**  : the layer

- **type** : the variable where to store the value

- **@RETURN** : return 1 if layer is of type LAYER_ETHER or 0 if not (then the variable type is not set). 

```c
int ether_get_type(layer_t *l, u16 *type);
```

-----------------------------------------

Get the string representation of the source address of a LAYER_ETHER layer. 

- **l**  : the layer

- **addr** : the buffer where to store the string. (Must have a size of ETH_ADDR_STR_LEN) 

- **@RETURN** : return 1 if layer is of type LAYER_ETHER or 0 if not (then the variable addr is not set). 

```c
int ether_get_srcStr(layer_t *l, char* addr[ETH_ADDR_STR_LEN]);
```

-----------------------------------------

Get the string representation of the destination address of a LAYER_ETHER layer. 

- **l**  : the layer

- **addr** : the buffer where to store the string. (Must have a size of ETH_ADDR_STR_LEN) 

- **@RETURN** : return 1 if layer is of type LAYER_ETHER or 0 if not (then the variable addr is not set). 

```c
int ether_get_dstStr(layer_t *l, char* addr[ETH_ADDR_STR_LEN]);
```

-----------------------------------------

## Ivp4 <a id="ipv4"></a>

#### Functions

--------------------------------------

Get the string representation of the source address of a LAYER_IPV4 layer. 

- **l**  : the layer

- **addr** : the buffer where to store the string. (Must have a size of IPV4_ADDR_STR_LEN) 

- **@RETURN** : return 1 if layer is of type LAYER_IPV4 or 0 if not (then the variable addr is not set). 

```c
int ipv4_get_srcStr(layer_t *l, char* addr[IPV4_ADDR_STR_LEN]);
```

---------------------------------------

Get the string representation of the destination address of a LAYER_IPV4 layer. 

- **l**  : the layer

- **addr** : the buffer where to store the string. (Must have a size of IPV4_ADDR_STR_LEN) 

- **@RETURN** : return 1 if layer is of type LAYER_IPV4 or 0 if not (then the variable addr is not set). 

```c
int ipv4_get_dstStr(layer_t *l, char* addr[IPV4_ADDR_STR_LEN]);
```

-------------------------------------

## Tcp <a id="tcp"></a>

#### Functions

---------------------------------------

Get the source port of a LAYER_TCP layer in host byte order. 

- **l**  : the layer

- **port** : the variable where to store the value.

- **@RETURN** : return 1 if layer is of type LAYER_TCP or 0 if not (then the variable port is not set). 

```c
int tcp_get_src(layer_t *l, u16 *port);
```

-----------------------------------------

Get the destination port of a LAYER_TCP layer in host byte order. 

- **l**  : the layer

- **port** : the variable where to store the value.

- **@RETURN** : return 1 if layer is of type LAYER_TCP or 0 if not (then the variable port is not set). 

```c
int tcp_get_dst(layer_t *l, u16 *port);
```

------------------------------------------

## Udp <a id="udp"></a>

Get the source port of a LAYER_UDP layer in host byte order. 

- **l**  : the layer

- **port** : the variable where to store the value.

- **@RETURN** : return 1 if layer is of type LAYER_UDP or 0 if not (then the variable port is not set). 

```c
int udp_get_src(layer_t *l, u16 *port);
```

----------------------------------------

Get the destination port of a LAYER_UDP layer in host byte order. 

- **l**  : the layer

- **port** : the variable where to store the value.

- **@RETURN** : return 1 if layer is of type LAYER_UDP or 0 if not (then the variable port is not set). 

```c
int udp_get_dst(layer_t *l, u16 *port);
```

## Examples <a id="examples"></a>

[Example 1](https://github.com/t00sh/libpkt/blob/master/test/main.c)