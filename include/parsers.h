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
  LAYER_MAX
};

extern int (*layer_parsers[])(layer_t**, u8*, u32);
extern dissector_t ether_dissectors[];
extern dissector_t ipv4_dissectors[];
extern dissector_t udp_dissectors[];

#endif /* DEF_PARSERS_H */
