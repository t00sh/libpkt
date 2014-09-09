#include "libpkt.h"
#include <stdio.h>
#include "test.h"

#define RUN_TEST(n) pkt((u8*)pkt##n, sizeof(pkt##n))

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
}

void pkt(u8 *raw, u32 len) {
  packet_t *pkt;

  pkt = packet_parse(raw, len, LAYER_ETHER);

  printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++\n");
  packet_foreach_layer(pkt, print_layer, NULL);
  printf("+++++++++++++++++++++++++++++++++++++++++++++++++++\n");

  packet_free(&pkt);
}

int main(void) {
  RUN_TEST(1);
  RUN_TEST(2);
  RUN_TEST(3);
  RUN_TEST(4);
  RUN_TEST(5);
  RUN_TEST(6);
  RUN_TEST(7);
  RUN_TEST(8);
  RUN_TEST(9);
  RUN_TEST(10);
  RUN_TEST(11);
  RUN_TEST(12);
  RUN_TEST(13);
  RUN_TEST(14);
  RUN_TEST(15);
  RUN_TEST(16);
  RUN_TEST(17);
  RUN_TEST(18);
  RUN_TEST(19);
  RUN_TEST(20);
  RUN_TEST(21);
  RUN_TEST(22);
  RUN_TEST(23);
  RUN_TEST(24);
  RUN_TEST(25);
  RUN_TEST(26);
  RUN_TEST(27);
  RUN_TEST(28);
  RUN_TEST(29);
  RUN_TEST(30);
  RUN_TEST(31);
  RUN_TEST(32);
  RUN_TEST(33);
  RUN_TEST(34);
  RUN_TEST(35);
  RUN_TEST(36);
  RUN_TEST(37);
  RUN_TEST(38);
  RUN_TEST(39);
  RUN_TEST(40);
  RUN_TEST(41);
  RUN_TEST(42);
  RUN_TEST(43);
  RUN_TEST(44);
  RUN_TEST(45);
  RUN_TEST(46);
  RUN_TEST(47);
  RUN_TEST(48);
  RUN_TEST(49);
  RUN_TEST(50);
  RUN_TEST(51);
  RUN_TEST(52);
  RUN_TEST(53);
  RUN_TEST(54);
  RUN_TEST(55);
  RUN_TEST(56);
  RUN_TEST(57);
  RUN_TEST(58);
  RUN_TEST(59);
  RUN_TEST(60);
  RUN_TEST(61);
  RUN_TEST(62);
  RUN_TEST(63);
  RUN_TEST(64);
  RUN_TEST(65);
  RUN_TEST(66);
  RUN_TEST(67);
  RUN_TEST(68);
  RUN_TEST(69);
  RUN_TEST(70);
  RUN_TEST(71);
  RUN_TEST(72);
  RUN_TEST(73);
  RUN_TEST(74);
  RUN_TEST(75);
  RUN_TEST(76);
  RUN_TEST(77);
  RUN_TEST(78);
  RUN_TEST(79);
  RUN_TEST(80);
  RUN_TEST(81);
  RUN_TEST(82);
  RUN_TEST(83);
  RUN_TEST(84);
  RUN_TEST(85);
  RUN_TEST(86);
  RUN_TEST(87);
  RUN_TEST(88);
  RUN_TEST(89);
  RUN_TEST(90);
  RUN_TEST(91);
  RUN_TEST(92);
  RUN_TEST(93);
  RUN_TEST(94);
  RUN_TEST(95);
  RUN_TEST(96);
  RUN_TEST(97);
  RUN_TEST(98);
  RUN_TEST(99);
  RUN_TEST(100);
  return 0;
}
