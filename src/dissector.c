#include "types.h"
#include "packet.h"
#include "dissector.h"
#include <stdlib.h>

int raw_parse(layer_t **layer, u8 *data, u32 size);

void dissector_run(dissector_t *dis, layer_t *cur_layer, u8* data, u32 size) {
  int i;

  for(i = 0; dis[i].is_proto; i++) {
    if(dis[i].is_proto(cur_layer)) {
      /* TODO: check errors ? */
      if(dis[i].parser(&cur_layer->next, data, size) == 0)
	break;
      return;
    }
  }
  raw_parse(&cur_layer->next, data, size);
}
