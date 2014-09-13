#include "packet.h"
#include "types.h"
#include "dissector.h"
#include "raw.h"
#include "parsers.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static raw_hdr* raw_new(void) {
  raw_hdr *new;

  if((new = malloc(sizeof(raw_hdr))) == NULL)
    return NULL;

  memset(new, 0, sizeof(raw_hdr));
  return new;
}

int raw_parse(layer_t **layer, u8 *data, u32 size) {
  raw_hdr *raw;

  if(size == 0)
    return 0;

  if((*layer = layer_new()) == NULL)
    return 0;

  (*layer)->destructor = free;

  if((raw = raw_new()) == NULL) {
    layer_free(layer);
    return 0;
  }

  raw->data = data;
  raw->size = size;

  (*layer)->type = LAYER_RAW;
  (*layer)->object = raw;

  return 1;
}

int raw_get_size(layer_t *l, u32 *size) {
  raw_hdr *hdr;

  if(l->type !=  LAYER_RAW)
    return 0;


  hdr = l->object;
  *size = hdr->size;

  return 1;
}

int raw_get_data(layer_t *l, u8 **data) {
  raw_hdr *hdr;

  if(l->type !=  LAYER_RAW)
    return 0;


  hdr = l->object;
  *data = hdr->data;

  return 1;
}
