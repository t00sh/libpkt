#include "types.h"
#include "packet.h"
#include "dissector.h"
#include <stdlib.h>


void dissector_run(dissector_t *dis, packet_t *cur_layer, u8* data, u32 size) {
  int i;

  for(i = 0; dis[i].is_proto; i++) {
    if(dis[i].is_proto(cur_layer)) {
      /* TODO: check errors ? */
      dis[i].parser(&cur_layer->next, data, size);
      return;
    }
  }

  /* TODO: parse raw data */
}
