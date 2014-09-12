#include "libpkt.h"
#include <stdio.h>
#include <string.h>
#include <pcap.h>

void do_ether(layer_t *l) {
  char src[ETHER_ADDR_STR_LEN];
  char dst[ETHER_ADDR_STR_LEN];
  u16 type;

  ether_get_srcStr(l, src);
  ether_get_dstStr(l, dst);
  ether_get_type(l, &type);

  printf("ETHER - TYPE:%04hx SRC:%s DST:%s\n",
	 type, src, dst);
}

void do_ipv4(layer_t *l) {
  char src[IPV4_ADDR_STR_LEN];
  char dst[IPV4_ADDR_STR_LEN];
  u8 proto;

  ipv4_get_saddrStr(l, src);
  ipv4_get_daddrStr(l, dst);
  ipv4_get_protocol(l, &proto);

  printf("IPV4 - PROTO:%hhu SRC:%s DST:%s\n",
	 proto, src, dst);
}

void do_ipv6(layer_t *l) {
  char src[IPV6_ADDR_STR_LEN];
  char dst[IPV6_ADDR_STR_LEN];
  u8 nexthdr;

  ipv6_get_saddrStr(l, src);
  ipv6_get_daddrStr(l, dst);
  ipv6_get_nexthdr(l, &nexthdr);

  printf("IPV6 - PROTO:%hhu SRC:%s DST:%s\n",
	 nexthdr, src, dst);
}

void do_tcp(layer_t *l) {
  u16 src;
  u16 dst;

  tcp_get_sport(l, &src);
  tcp_get_dport(l, &dst);

  printf("TCP - SRC:%hu DST:%hu\n",
	 src, dst);
}

void do_udp(layer_t *l) {
  u16 src;
  u16 dst;

  udp_get_sport(l, &src);
  udp_get_dport(l, &dst);

  printf("UDP - SRC:%hu DST:%hu\n",
	 src, dst);
}

void do_icmp(layer_t *l) {
  u8 code;
  u8 type;

  icmp_get_code(l, &code);
  icmp_get_type(l, &type);

  printf("ICMP - CODE:%hhu TYPE:%hu\n",
	 code, type);
}

void do_arp(layer_t *l) {
  u16 op;

  arp_get_op(l, &op);

  printf("ARP - OP:%hhu\n",
	 op);
}

void do_dns(layer_t *l) {
  u16 id;

  dns_get_id(l, &id);

  printf("DNS - ID:%hu\n",
	 id);
}

void print_layer(layer_t *l, void* user) {
  (void)user;

  if(l->type == LAYER_ETHER)
    do_ether(l);
  else if(l->type == LAYER_IPV4)
    do_ipv4(l);
  else if(l->type == LAYER_TCP)
    do_tcp(l);
  else if(l->type == LAYER_UDP)
    do_udp(l);
  else if(l->type == LAYER_ICMP)
    do_icmp(l);
  else if(l->type == LAYER_ARP)
    do_arp(l);
  else if(l->type == LAYER_DNS)
    do_dns(l);
  else if(l->type == LAYER_IPV6)
    do_ipv6(l);
}

void handle_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *raw) {
  packet_t *pkt;
  int *layer = (int*)args;

  pkt = packet_parse((u8*)raw, (u32)header->caplen, *layer);

  printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++\n");
  packet_foreach_layer(pkt, print_layer, NULL);
  printf("+++++++++++++++++++++++++++++++++++++++++++++++++++\n");

  packet_free(&pkt);
}

int main(int argc, char** argv) {
  pcap_t *pcap = NULL;
  const char *dev = NULL, *file = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  int layer;

  if(argc != 3) {
    printf("Usage %s dev  <device>\n", argv[0]);
    printf("Usage %s pcap <pcap>\n", argv[0]);
    return 1;
  }

  if(!strcmp(argv[1], "dev"))
    dev = argv[2];
  else if(!strcmp(argv[1], "pcap"))
    file = argv[2];
  else
    return 1;

  if(dev) {
    if((pcap = pcap_open_live(dev, 1500, 1, 1000, errbuf)) == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
      return 1;
    }
  }

  if(file) {
    if((pcap = pcap_open_offline(file, errbuf)) == NULL) {
      fprintf(stderr, "Couldn't open pcap %s: %s\n", file, errbuf);
      return 1;
    }
  }

  if (pcap_datalink(pcap) == DLT_EN10MB) {
    layer = LAYER_ETHER;
  } else if(pcap_datalink(pcap) == DLT_RAW) {
    layer = LAYER_IPV4;
  } else {
    fprintf(stderr, "Headers not supported\n");
    return 1;
  }

  pcap_loop(pcap, -1, handle_pkt, (u_char*)&layer);

  return 0;
}
