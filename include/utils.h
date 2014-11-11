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



#ifndef DEF_UTILS_H
#define DEF_UTILS_H

#include "types.h"

/*!
 * \file
 * \brief Implement some usefull functions
 */

/*! Take a 16 bits integer in network order and return the integer in host order */
u16 ntohs(u16 n);

/*! Take a 32 bits integer in network order and return the integer in host order */
u32 ntohl(u32 n);

#endif
