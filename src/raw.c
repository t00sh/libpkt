/************************************************************************/
/* libpkt - A packet dissector library  			        */
/* 								        */
/* Copyright 2014, -TOSH-					        */
/* File coded by -TOSH-	(tosh <at> t0x0sh <dot> org		        */
/* 								        */
/* This file is part of libpkt.					        */
/* 								        */
/* libpkt is free software: you can redistribute it and/or modify       */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* libpkt is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with libpkt.  If not, see <http://www.gnu.org/licenses/>       */
/************************************************************************/


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
