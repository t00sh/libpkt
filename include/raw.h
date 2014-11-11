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


#ifndef DEF_RAW_H
#define DEF_RAW_H


#include "types.h"

/*!
 * \file
 * \brief Implement LAYER_RAW
 */

/*! RAW header */
typedef struct raw_hdr {
  u8 *data;   /**< Pointer to the data */
  u32 size;   /**< Size of the data */
} raw_hdr;


/*! Get the data field. */
int raw_get_data(layer_t *l, u8 **data);

/*! Get the size field. */
int raw_get_size(layer_t *l, u32 *size);

#endif /* DEF_RAW_H */
