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


#ifndef DEF_DISSECTOR_H
#define DEF_DISSECTOR_H

#include "packet.h"

/*!
 * \file
 * \brief Dissectors definitions
 */

/*! Dissector
 */
typedef struct dissector {
  int (*is_proto)(layer_t*);                      /**< Check protocol */
  int (*parser)(packet_t*, layer_t**, const u8*, u32);  /**< Parser to run if protocol match */
}dissector_t;

void dissector_run(packet_t *p, dissector_t *dis, layer_t *cur_layer, const u8* data, u32 size);

#endif /* DEF_DISSECTOR_H */
