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

inline u16 ntohs(u16 n) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return ((((u16)(n) & 0xFF)) << 8) | (((u16)(n) & 0xFF00) >> 8);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return n;
#else
# error	"Please fix endianness"
#endif
}


inline u32 ntohl(u32 n) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return (((((u32)(n) & 0xFF)) << 24) | \
	  ((((u32)(n) & 0xFF00)) << 8) | \
	  ((((u32)(n) & 0xFF0000)) >> 8) | \
	  ((((u32)(n) & 0xFF000000)) >> 24));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return n;
#else
#error	"Please fix endianness"
#endif
}

inline u32 ntoh24(u8 n[3]) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return					\
    (((u32)(n[0])) |				\
     ((u32)(n[1]) << 8) |			\
     ((u32)(n[2]) << 16));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return					\
    (((u32)(n[2])) |				\
     ((u32)(n[1]) << 8) |			\
     ((u32)(n[0]) << 16));;
#else
#error	"Please fix endianness"
#endif
}
