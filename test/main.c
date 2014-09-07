#include "libpkt.h"
#include <stdio.h>

void pkt1(void) {
  u8 raw[] = "abcd";
  packet_t *pkt = NULL;

  ether_parse(&pkt, raw, sizeof(raw)); 
}

int main(void) {
  
  return 0;
}
