#ifndef DEF_PARSERS_H
#define DEF_PARSERS_H

#include "dissector.h"

enum {
  LAYER_ETHER=0,
  LAYER_IPV4,
  LAYER_TCP,
  LAYER_UDP,
  LAYER_ICMP,
  LAYER_ARP,
  LAYER_DNS,
  LAYER_IPV6,
  LAYER_RAW,
  LAYER_IPV6_HBH_EXT,
  LAYER_IPV6_FRAG_EXT,
  LAYER_IPV6_ROUTE_EXT,
  LAYER_TLS,
  LAYER_MAX
};

extern int (*layer_parsers[])(layer_t**, u8*, u32);
extern dissector_t ether_dissectors[];
extern dissector_t ipv4_dissectors[];
extern dissector_t udp_dissectors[];
extern dissector_t ipv6_dissectors[];
extern dissector_t tcp_dissectors[];
extern dissector_t icmp_dissectors[];
extern dissector_t tls_dissectors[];

#endif /* DEF_PARSERS_H */
