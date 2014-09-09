#include "dissector.h"
#include "packet.h"
#include "types.h"

int ether_parse(layer_t **layer, u8 *data, u32 size);
int ipv4_parse(layer_t **layer, u8 *data, u32 size);
int tcp_parse(layer_t **layer, u8 *data, u32 size);
int udp_parse(layer_t **layer, u8 *data, u32 size);

int (*layer_parsers[])(layer_t**, u8*, u32) = {
  ether_parse,    /* LAYER_ETHER  */
  ipv4_parse,     /* LAYER_IPV4   */
  tcp_parse,      /* LAYER_TCP    */
  udp_parse,      /* LAYER_UDP    */
  NULL            /* LAYER_MAX    */
};



/********************************************/
/* ************ LAYER_ETHER *************** */
/********************************************/

int ether_is_ipv4(layer_t*);
int ether_is_ipv6(layer_t*);

dissector_t ether_dissectors[] = {
  { ether_is_ipv4, ipv4_parse },
  { NULL,          NULL       }
};


/*************************************/
/* ********** LAYER_IPV4 *********** */
/*************************************/

int ipv4_is_tcp(layer_t*);
int ipv4_is_udp(layer_t*);

dissector_t ipv4_dissectors[] = {
  { ipv4_is_tcp, tcp_parse },
  { ipv4_is_udp, udp_parse },
  { NULL, NULL }
};
