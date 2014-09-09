#ifndef DEF_DISSECTOR_H
#define DEF_DISSECTOR_H

#include "packet.h"

typedef struct dissector {
  int (*is_proto)(layer_t*);
  int (*parser)(layer_t**, u8*, u32);
}dissector_t;

void dissector_run(dissector_t *dis, layer_t *cur_layer, u8* data, u32 size);

#endif /* DEF_DISSECTOR_H */
