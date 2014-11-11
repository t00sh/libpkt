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


#include "types.h"
#include "packet.h"
#include "dissector.h"
#include <stdlib.h>

int raw_parse(layer_t **layer, u8 *data, u32 size);

void dissector_run(packet_t *p, dissector_t *dis, layer_t *cur_layer, u8* data, u32 size) {
  int i;

  for(i = 0; dis[i].is_proto; i++) {
    if(dis[i].is_proto(cur_layer)) {
      /* TODO: check errors ? */
      if(dis[i].parser(p, &cur_layer->next, data, size) == 0)
	break;
      return;
    }
  }
  raw_parse(&cur_layer->next, data, size);
}
