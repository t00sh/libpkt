#ifndef DEF_RAW_H
#define DEF_RAW_H

#include "types.h"

typedef struct raw_hdr {
  u8 *data;
  u32 size;
} raw_hdr;


int raw_get_data(layer_t *l, u8 **data);
int raw_get_size(layer_t *l, u32 *size);

#endif /* DEF_RAW_H */
