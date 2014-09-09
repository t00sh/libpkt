#include "types.h"

inline u16 ntohs(u16 n) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return ((((u16)(n) & 0xFF)) << 8) | (((u16)(n) & 0xFF00) >> 8);
#elif __BYTE_ORDER == __BIG_ENDIAN
  return n;
#else
# error	"Please fix <bits/endian.h>"
#endif
}


inline u32 ntohl(u32 n) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return (((((u32)(n) & 0xFF)) << 24) | \
	  ((((u32)(n) & 0xFF00)) << 8) | \
	  ((((u32)(n) & 0xFF0000)) >> 8) | \
	  ((((u32)(n) & 0xFF000000)) >> 24));
#elif __BYTE_ORDER == __BIG_ENDIAN
  return n;
#else
# error	"Please fix <bits/endian.h>"
#endif
}
