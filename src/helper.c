#include "1A/helper.h"

/* bin转换为hex */
int bin2hex(unsigned char *dst, int *pd, unsigned char *src, int s) {
  *pd = s * 2;
  for (int i = 0; i < s; i++)
    sprintf((char *)dst + i * 2, "%02X", src[i]);
  return 0;
}

/* hex转换为bin */
int hex2bin(unsigned char *dst, int *pd, unsigned char *src, int s) {
  /* 16进制转换为二进制 */
  int u = 0;
  *pd = s / 2;
  for (int i = 0; i < s; i += 2) {
    sscanf((char *)src + i, "%02X", &u);
    dst[i / 2] = u;
  }
  return 0;
}
