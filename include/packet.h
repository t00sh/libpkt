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


#ifndef DEF_PACKET_H
#define DEF_PACKET_H


#include "types.h"

/*!
 * \file
 * \brief Generic packet and layers manipulation
 */

/*!
 * A Layer structure
 */
typedef struct layer {
  int type;                   /**< Layer type (LAYER_*) */
  void *object;               /**< Structure which describe the layer */
  void (*destructor)(void*);  /**< A destructor for the layer */
  struct layer *next;         /**< The next layer */

}layer_t;

/*!
 * A Packet structure
 */
typedef struct packet {
  u8* raw;              /**< Raw packet */
  u32 size;             /**< Raw packet size */
  layer_t *layers;      /**< List of layers */
}packet_t;

/*! Allocate a new packet */
packet_t* packet_new(void);

/*! Free a packet */
void packet_free(packet_t **packet);

/*! Allocate a new layer */
layer_t* layer_new(void);

/*! Free a layer */
void layer_free(layer_t **layer);

/*! Get a given layer of a packet.
 * \return NULL if the layer isn't found
 */
layer_t* packet_get_layer(packet_t *p, int layer);

/*! Check if a packet have a specified layer type */
int packet_has_layer(packet_t *p, int layer);

/*! Call a callback for each layer of a packet */
void packet_foreach_layer(packet_t *p, void (*callback)(layer_t*, void* user), void* user);

/*! Parse raw data and return the given packet.
 * \param data The data captured on the wire
 * \param len The len of the data
 * \param layer_type The first layer
 * \return the packet or NULL if an error occured
 */
packet_t* packet_parse(u8* data, u32 size, int layer_type);

#endif /* DEF_PACKET_H */
